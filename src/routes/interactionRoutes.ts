import { Router, Request, Response, NextFunction } from 'express';
import { Session } from 'express-session';
import { Interaction } from 'oidc-provider';
// Import Provider type if needed for type hints, though often inferred
// import Provider, { InteractionResults, PromptDetail } from 'oidc-provider';
import Account from '../config/account'; // Import your Account class
import oidcProvider from '../config/oidcProvider'; // Import the provider instance
import { ObjectId } from 'mongoose';
import logger from '../config/middlewares/logger';

const router = Router();

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
        interactionDetails?: Interaction;
    }
}

// Helper to set secure headers for interaction views
const setNoCache = (req: Request, res: Response, next: NextFunction) => {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
};

// Main interaction route (handles GET requests)
router.get('/:uid', setNoCache, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        logger.debug('[Interaction] Starting interaction flow:', {
            uid: req.params.uid,
            sessionId: req.sessionID,
            hasSession: !!req.session
        });

        // Get interaction details
        const details = await oidcProvider.interactionDetails(req, res);
        logger.debug('[Interaction] Got interaction details:', {
            uid: details.uid,
            prompt: details.prompt?.name,
            params: details.params,
            session: details.session
        });

        // Store interaction details in session
        req.session.interactionDetails = details;
        logger.debug('[Interaction] Stored interaction details in session');

        // Check if the interaction exists and is valid
        const interaction = await oidcProvider.Interaction.find(details.uid);
        if (!interaction) {
            logger.error('[Interaction] Interaction not found:', details.uid);
            res.status(404).json({
                error: 'not_found',
                error_description: 'The interaction session was not found',
                details: { uid: details.uid }
            });
            return;
        }

        // Check if the interaction has expired
        const now = Math.floor(Date.now() / 1000);
        if (interaction.exp && interaction.exp < now) {
            logger.warn('[Interaction] Interaction expired:', {
                uid: details.uid,
                expiredAt: interaction.exp,
                currentTime: now
            });

            // If we have original auth params, restart the flow
            if (req.session.originalAuthParams) {
                logger.debug('[Interaction] Restarting auth flow with original parameters');
                const authUrl = new URL('/auth', process.env.ISSUER_URL || 'http://localhost:5001');
                Object.entries(req.session.originalAuthParams).forEach(([key, value]) => {
                    authUrl.searchParams.append(key, value as string);
                });
                res.redirect(authUrl.toString());
                return;
            }

            res.status(400).json({
                error: 'invalid_request',
                error_description: 'The interaction session has expired',
                details: { 
                    uid: details.uid,
                    expiredAt: interaction.exp,
                    currentTime: now
                }
            });
            return;
        }

        // Load client information
        const client = await oidcProvider.Client.find(details.params.client_id as string);
        if (!client) {
            logger.error('[Interaction] Client not found:', details.params.client_id);
            res.status(400).json({
                error: 'invalid_request',
                error_description: 'Client not found',
                details: { client_id: details.params.client_id }
            });
            return;
        }
        logger.debug(`[Interaction] Loaded interaction information, the current prompt is: ${JSON.stringify(details.prompt) || details.prompt}`);
        // Handle different interaction prompts
        switch (details.prompt?.name) {
            case 'login':
                logger.debug('[Interaction] Rendering login view');
                res.render('login', {
                    uid: details.uid,
                    details: details.prompt.details,
                    params: details.params,
                    client,
                    title: 'Sign-in',
                    flash: undefined,
                });
                return;

            case 'consent':
                logger.debug('[Interaction] Rendering consent view');
                // Extract scopes from the interaction details
                const scopeParam = details.params.scope as string | undefined;
                const scopes = scopeParam ? scopeParam.split(' ') : [];
                res.render('consent', {
                    uid: details.uid,
                    details: details.prompt.details,
                    params: details.params,
                    client,
                    title: 'Authorize',
                    flash: undefined,
                    scopes: scopes // Add scopes to the template data
                });
                return;

            default:
                logger.error('[Interaction] Unknown prompt type:', details.prompt?.name);
                res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Unknown interaction type',
                    details: { prompt: details.prompt }
                });
                return;
        }
    } catch (err) {
        logger.error('[Interaction] Error in interaction route:', err);
        next(err);
    }
});

// Handle Login Form Submission (POST)
router.post('/:uid/login', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        logger.debug('[Login] Starting login process:', {
            uid: req.params.uid,
            sessionId: req.sessionID,
            hasSession: !!req.session
        });

        // Get interaction details from session or provider
        let interactionDetails;
        if (req.session.interactionDetails) {
            interactionDetails = req.session.interactionDetails;
            logger.debug('[Login] Using interaction details from session');
        } else {
            interactionDetails = await oidcProvider.interactionDetails(req, res);
            logger.debug('[Login] Got fresh interaction details from provider');
        }

        const { uid, prompt, params, session } = interactionDetails;

        logger.debug('[Login] Interaction details:', {
            uid,
            prompt: prompt.name,
            params,
            sessionId: session?.uid,
            hasSession: !!session,
            hasAccountId: !!session?.accountId
        });

        // Ensure this interaction is indeed waiting for login
        if (prompt.name !== 'login') {
            logger.error('[Login] Wrong prompt type:', prompt.name);
            return next(new Error('Interaction prompt is not login'));
        }

        // Get username/password submitted by the user
        const { username, password } = req.body;

        // Authenticate the user using your Account logic
        const account = await Account.authenticate(username, password);

        // If authentication fails
        if (!account) {
            logger.warn('[Login] Authentication failed for user:', username);
            return res.render('login', {
                uid,
                client: await oidcProvider.Client.find(params.client_id as string),
                params,
                title: 'Sign-in',
                flash: 'Invalid username or password',
            });
        }

        // If authentication succeeds, prepare the result for interactionFinished
        const accountIdString = (account._id as ObjectId).toString();
        logger.debug('[Login] Authentication successful:', {
            username,
            accountId: accountIdString,
            interactionId: uid
        });

        // const allCookies = req.cookies;
        // logger.debug('All Cookies:', allCookies);

        const result = {
            login: {
                accountId: accountIdString,
                remember: true,
                ts: Math.floor(Date.now() / 1000)
            },
        };

        logger.debug('[Login] Completing interaction with result:', result);

        // Complete the interaction
        await oidcProvider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });

        logger.debug('[Login] Interaction completed successfully');

    } catch (err) {
        logger.error('[Login] Error during login:', {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined
        });
        next(err);
    }
});

// Handle Consent Form Submission (POST)
router.post('/:uid/confirm', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    logger.debug(`[Interaction /confirm POST] Received consent confirmation for UID: ${req.params.uid}`);
    try {
        // Get interaction details
        logger.debug('[Interaction /confirm POST] Getting interaction details...');
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        const { prompt: { name, details }, params, session, grantId: existingGrantId } = interactionDetails;
        logger.debug(`[Interaction /confirm POST] Details retrieved. Prompt: ${name}, Has Session: ${!!session}, Has GrantId: ${!!existingGrantId}`);

        // Ensure this interaction is waiting for consent
        if (name !== 'consent') {
            logger.error('[Interaction /confirm POST] Error: Interaction prompt is not consent.');
            return next(new Error('Interaction prompt is not consent'));
        }

        // Ensure accountId is present (should be after login)
        const accountId = session?.accountId || details.accountId as string;
        logger.debug(`[Interaction /confirm POST] Account ID: ${accountId}`);
        if (!accountId) {
            logger.error('[Interaction /confirm POST] Error: Account ID missing when trying to confirm consent.');
            return next(new Error('Cannot confirm consent without a logged-in user session.'));
        }
        logger.debug(`[Interaction /confirm POST] Account ID found: ${accountId}`);

        let grant;

        // Find or create the grant object associated with this interaction
        logger.debug(`[Interaction /confirm POST] Looking for existing grant with ID: ${existingGrantId}`);
        if (existingGrantId) {
            grant = await oidcProvider.Grant.find(existingGrantId);
            logger.debug(`[Interaction /confirm POST] Existing grant ${existingGrantId ? 'found' : 'not found'}.`);
        }

        if (!grant) {
            logger.debug(`[Interaction /confirm POST] Creating new grant for account ${accountId} and client ${params.client_id}`);
            grant = new oidcProvider.Grant({
                accountId: accountId,
                clientId: params.client_id as string,
            });

            // Initialize the grant with required properties
            if (details.missingOIDCScope) {
                const scopesToAdd = (details.missingOIDCScope as string[]).join(' ');
                logger.debug(`[Interaction /confirm POST] Adding OIDC Scopes: ${scopesToAdd}`);
                grant.addOIDCScope(scopesToAdd);
            }
        }

        // Save the grant to the adapter
        logger.debug('[Interaction /confirm POST] Saving grant...');
        const savedGrantId = await grant.save();
        if (!savedGrantId) {
            throw new Error('Failed to save grant');
        }
        logger.debug(`[Interaction /confirm POST] Grant saved successfully. Grant ID: ${savedGrantId}`);

        // Prepare the result for interactionFinished
        const consentResult = { consent: { grantId: savedGrantId } };
        logger.debug('[Interaction /confirm POST] Calling interactionFinished...');

        // Complete the interaction
        await oidcProvider.interactionFinished(req, res, consentResult, { mergeWithLastSubmission: true });
        logger.debug('[Interaction /confirm POST] Interaction completed successfully');

    } catch (err) {
        logger.error('[Interaction /confirm POST] Error caught:', {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined
        });
        next(err);
    }
});

// Handle Abort Interaction (POST)
router.post('/:uid/abort', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        const result = {
            error: 'access_denied',
            error_description: 'End-User aborted interaction',
        };
        await oidcProvider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});


export default router;
