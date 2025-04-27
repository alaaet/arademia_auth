import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import logger from '../config/middlewares/logger';
import oidcProvider from '../config/oidcProvider';
import crypto from 'crypto';
import axios from 'axios';
import User from '../models/User';
import { isValidObjectId } from 'mongoose';

// Extend Express Session type
declare module 'express-session' {
    interface Session {
        interactionUrl?: string;
        originalAuthParams?: {
            client_id?: string;
            response_type?: string;
            scope?: string;
            redirect_uri?: string;
            state?: string;
            nonce?: string;
            [key: string]: any;
        };
    }
    interface SessionData {
        pendingInteractionUid?: string;
        originalAuthParams?: Record<string, unknown>;
        // interactionDetails?: any; // Avoid storing the whole object if possible
    }
}

dotenv.config();
const router = express.Router();

// Google authentication initiation route
router.get('/google', async (req: Request, res: Response, next: NextFunction) => {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    logger.info(`[Google Auth Start] Request received (${requestId})`, {
        sessionId: req.sessionID,
        hasSession: !!req.session,
        timestamp: new Date().toISOString()
    });

    try {
        // 1. Get interaction details from oidc-provider
        // This establishes the interaction context within the current request/session
        logger.info(`[Google Auth Start] Cookies received: ${JSON.stringify(req.cookies, null, 2)}`);
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        const { uid, prompt, params, session: oidcSessionInfo, exp } = interactionDetails;

        const now = Math.floor(Date.now() / 1000);
        const timeRemaining = exp ? exp - now : 'unknown';

        logger.info(`[Google Auth Start] Interaction details obtained (${requestId})`, {
            uid,
            prompt: prompt?.name,
            params,
            expiresAt: exp,
            currentTime: now,
            timeRemaining,
            oidcSessionUid: oidcSessionInfo?.uid,
            currentSessionId: req.sessionID,
            timestamp: new Date().toISOString()
        });

        // 2. Check if interaction is expired *before* redirecting
        if (exp && exp < now) {
            logger.warn(`[Google Auth Start] Interaction already expired (${requestId})`, {
                uid,
                expiresAt: exp,
                currentTime: now,
                timeSinceExpiry: now - exp,
                timestamp: new Date().toISOString()
            });
            // Don't throw, let the interactionFinished/Result handle expiration later
            // Or redirect to an error page or restart flow immediately
            throw new Error('Authorization request has expired before redirect');
        }

        // 3. Store the interaction UID securely in the user's session
        // This is crucial for retrieving it in the callback
        req.session.pendingInteractionUid = uid;
        // Store original params for potential retries on error/expiry
        req.session.originalAuthParams = params;

        // Save the session explicitly before redirecting if using certain session stores
        await new Promise<void>((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    logger.error(`[Google Auth Start] Failed to save session before redirect (${requestId})`, { error: err });
                    reject(new Error('Failed to save session'));
                } else {
                    logger.info(`[Google Auth Start] Session saved,interaction UID ${uid} stored (${requestId})`, {
                        sessionId: req.sessionID,
                        sessionExpiresAt: req.session.cookie?.expires?.toISOString(),
                    });
                    resolve();
                }
            });
        });


        // 4. Construct the Google OAuth URL, using the interaction UID as 'state'
        const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({
            client_id: process.env.GOOGLE_CLIENT_ID!,
            redirect_uri: `${process.env.ISSUER_URL}/auth/google/callback`, // Ensure ISSUER_URL is correct base
            response_type: 'code',
            scope: 'openid email profile',
            state: uid, // Use the interaction UID as state for CSRF protection and linking
            access_type: 'offline', // Optional: if you need refresh tokens
            prompt: 'consent' // Optional: forces consent screen
        }).toString()}`;

        logger.info(`[Google Auth Start] Redirecting to Google (${requestId})`, {
            authUrl: googleAuthUrl,
            interactionUid: uid,
            stateParam: uid,
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime
        });

        // 5. Redirect the user
        res.redirect(googleAuthUrl);

    } catch (err) {
        const durationMs = Date.now() - startTime;
        logger.error(`[Google Auth Start] Error in Google auth initiation (${requestId})`, {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined,
            sessionId: req.sessionID,
            hasSession: !!req.session,
            timestamp: new Date().toISOString(),
            durationMs
        });

        // Attempt to gracefully handle expired interaction before redirect
        if (err instanceof Error && err.message.includes('expired')) {
            logger.warn(`[Google Auth Start] Handling expired interaction error (${requestId})`);
            // Optionally try to restart the original OIDC flow
            if (req.session?.originalAuthParams) {
                const authUrl = new URL('/auth', process.env.ISSUER_URL || 'http://localhost:5001');
                Object.entries(req.session.originalAuthParams).forEach(([key, value]) => {
                    if (value !== undefined && value !== null) {
                        authUrl.searchParams.append(key, String(value));
                    }
                });
                logger.info(`[Google Auth Start] Redirecting to restart original OIDC auth flow (${requestId})`, {
                    authUrl: authUrl.toString(),
                    timestamp: new Date().toISOString()
                });
                // Clear potentially stale session data before redirecting
                delete req.session.pendingInteractionUid;
                delete req.session.originalAuthParams;
                // Consider saving session again here if needed
                return res.redirect(authUrl.toString());
            }
        }
        // Fallback error handling
        next(err);
    }
});

// Google callback route
router.get('/google/callback', async (req: Request, res: Response, next: NextFunction) => {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    logger.info(`[Google Callback] Request received (${requestId})`, {
        query: req.query,
        sessionId: req.sessionID,
        hasSession: !!req.session,
        pendingUidInSession: req.session?.pendingInteractionUid,
        timestamp: new Date().toISOString()
    });

    const { code, state, error: googleError, error_description } = req.query;

    // Retrieve the interaction UID we stored in the session before redirecting
    const expectedUid = req.session?.pendingInteractionUid;

    try {
        // --- Pre-computation Checks ---
        if (!req.session) {
            throw new Error('Session not found during callback. Ensure session middleware is configured correctly and cookies are sent.');
        }
        if (googleError) {
            throw new Error(`Google OAuth error: ${error_description || googleError}`);
        }
        if (!code || typeof code !== 'string') {
            throw new Error('No authorization code received from Google');
        }
        if (!state || typeof state !== 'string') {
            throw new Error('No state parameter received from Google');
        }
        if (!expectedUid) {
            throw new Error('No pending interaction UID found in session. Flow may have timed out or session was lost.');
        }

        // 1. **CRITICAL:** Verify the 'state' parameter to prevent CSRF
        if (state !== expectedUid) {
            logger.error(`[Google Callback] State mismatch (${requestId})`, {
                receivedState: state,
                expectedUidFromSession: expectedUid,
                sessionId: req.sessionID,
            });
            throw new Error('Invalid state parameter. Possible CSRF attack or corrupted session.');
        }

        logger.info(`[Google Callback] State verified successfully (${requestId})`, { interactionUid: expectedUid });

        // Clean up the UID from the session now that we've used it
        delete req.session.pendingInteractionUid;
        // Consider saving session immediately if your store requires it
        // await new Promise<void>((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

        // 2. Exchange the authorization code for tokens
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
            code: code,
            client_id: process.env.GOOGLE_CLIENT_ID!,
            client_secret: process.env.GOOGLE_CLIENT_SECRET!,
            redirect_uri: `${process.env.ISSUER_URL}/auth/google/callback`, // Must match exactly what was sent in the auth request
            grant_type: 'authorization_code'
        }).toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const { access_token, id_token } = tokenResponse.data;
        if (!access_token) {
            throw new Error('Failed to obtain access token from Google');
        }

        logger.info(`[Google Callback] Received tokens from Google (${requestId})`, {
            interactionUid: expectedUid,
            hasAccessToken: !!access_token,
            hasIdToken: !!id_token,
            expiresIn: tokenResponse.data.expires_in,
            timestamp: new Date().toISOString()
        });

        // 3. Get user info from Google
        const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const googleUserInfo = userInfoResponse.data;
        logger.info(`[Google Callback] Retrieved user info from Google (${requestId})`, {
            interactionUid: expectedUid,
            googleUserId: googleUserInfo.id,
            email: googleUserInfo.email,
            timestamp: new Date().toISOString()
        });

        // 4. Find or provision the user in your local database
        // Adapt this logic based on your User schema and provisioning strategy
        const providerIdPath = 'externalAuth.google.id'; // Example path in your User schema
        let user = await User.findOne({ [providerIdPath]: googleUserInfo.id });

        if (!user) {
            user = new User({
                email: googleUserInfo.email || '',
                username: googleUserInfo.email || googleUserInfo.id,
                firstName: googleUserInfo.given_name || '',
                lastName: googleUserInfo.family_name || '',
                role: 'student', // Default role for external sign-in
                isValidated: true, // External-verified emails are considered validated
                isProfileComplete: false,
                externalAuth: {
                    ['google']: {
                        id: googleUserInfo.id,
                        accessToken: access_token
                    }
                }
            });
            await user.save();
        }

        if (!user || !user._id || !isValidObjectId(user._id)) {
            throw new Error('Invalid user object or missing _id');
        }
        const accountId = user._id.toString();
        logger.info(`[Google Callback] Found local user mapping (${requestId})`, {
            interactionUid: expectedUid,
            accountId: accountId,
            googleUserId: googleUserInfo.id
        });


        // 5. Prepare the result for oidc-provider
        // This tells oidc-provider that the login step of the interaction is complete
        const result = {
            login: {
                accountId: accountId,
                // acr: 'urn:google:sso', // Optional: Authentication Context Class Reference
                amr: ['google'], // Optional: Authentication Methods References
                remember: true, // Or based on user choice if you have a "remember me" checkbox
                ts: Math.floor(Date.now() / 1000), // Login timestamp
            },
            // consent: {}, // Add consent if needed/prompted for scopes
        };

        logger.info(`[Google Callback] Prepared result for oidc-provider (${requestId})`, {
            interactionUid: expectedUid,
            result: JSON.stringify(result), // Log result carefully, may contain sensitive info indirectly
            timestamp: new Date().toISOString()
        });

        const interaction = await oidcProvider.Interaction.find(expectedUid);
        logger.info(`[Google Callback] Interaction details JUST BEFORE interactionFinished:${JSON.stringify(interaction)}`);

        await oidcProvider.interactionFinished(req, res, result);

        logger.info(`[Google Callback] OIDC interactionFinished successfully called (${requestId})`, {
            interactionUid: expectedUid,
            accountId: accountId,
            durationMs: Date.now() - startTime,
            timestamp: new Date().toISOString()
        });

        // interactionFinished handles the redirect back to the client application,
        // so no further response should be sent here unless interactionFinished throws.

    } catch (err) {
        const durationMs = Date.now() - startTime;
        logger.error(`[Google Callback] Error processing Google callback (${requestId})`, {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined,
            interactionUid: expectedUid || 'unknown (session missing?)',
            sessionId: req.sessionID,
            hasSession: !!req.session,
            timestamp: new Date().toISOString(),
            durationMs
        });

        // Attempt to restart the original OIDC flow if interaction expired or certain errors occurred
        const shouldRestartFlow = err instanceof Error && (
            err.message.includes('interaction session not found') ||
            err.message.includes('interaction expired') ||
            err.message.includes('Invalid state parameter') // Maybe restart on CSRF fail? Or show error page.
            // Add other specific oidc-provider errors if needed
        );

        if (shouldRestartFlow && req.session?.originalAuthParams) {
            logger.warn(`[Google Callback] Attempting to restart original OIDC flow due to error (${requestId})`, { originalParams: req.session.originalAuthParams });
            const authUrl = new URL('/auth', process.env.ISSUER_URL || 'http://localhost:5001');
            Object.entries(req.session.originalAuthParams).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    authUrl.searchParams.append(key, String(value));
                }
            });
            // Clean up potentially stale session data
            delete req.session.pendingInteractionUid;
            delete req.session.originalAuthParams;
            // Consider saving session again here if needed
            return res.redirect(authUrl.toString());
        }

        // Fallback to general error handler
        next(err);
    }
});

export default router;
