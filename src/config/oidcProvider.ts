import Provider, { Configuration, ClientMetadata, KoaContextWithOIDC, interactionPolicy, Interaction, InteractionResults, ErrorOut, KoaContextWithOIDC as DefaultContext, PromptDetail } from 'oidc-provider';
import { IncomingMessage } from 'http';
import dotenv from 'dotenv';
import path from 'path';
import Account from './account'; // Import the Account class
import adapterFactory from './mongodb.adapter'; // Import the MongoDB adapter factory
import logger from './middlewares/logger';
const { Prompt } = interactionPolicy;

dotenv.config(); // Load environment variables

const ISSUER_URL = process.env.ISSUER_URL;
const MONGODB_URI = process.env.MONGODB_URI; // Get MongoDB URI for adapter
// Client 1: arademia_front_client
// const FRONTEND_URL = process.env.FRONTEND_URL;
// const FRONTEND_CALLBACK_URL = FRONTEND_URL ? `${FRONTEND_URL}/auth/callback` : '';
// const FRONTEND_LOGOUT_CALLBACK_URL = FRONTEND_URL ? `${FRONTEND_URL}/auth/logout` : '';
// Client 2: arademia_intranet_client
const INTRANET_URL = process.env.INTRANET_URL;
const INTRANET_CALLBACK_URL = INTRANET_URL ? `${INTRANET_URL}/auth/callback` : '';
logger.info(`INTRANET_CALLBACK_URL: ${INTRANET_CALLBACK_URL}`);
const INTRANET_CLIENT_ID = process.env.INTRANET_CLIENT_ID;
logger.info(`INTRANET_CLIENT_ID: ${INTRANET_CLIENT_ID}`);
const INTRANET_CLIENT_SECRET = process.env.INTRANET_CLIENT_SECRET;
logger.info(`INTRANET_CLIENT_SECRET: ${INTRANET_CLIENT_SECRET}`);
const INTRANET_LOGOUT_CALLBACK_URL = process.env.INTRANET_LOGOUT_CALLBACK_URL || `${INTRANET_URL}/auth/logout`;
logger.info(`INTRANET_LOGOUT_CALLBACK_URL: ${INTRANET_LOGOUT_CALLBACK_URL}`);
// Client 3: moodle_oidc_client
const MOODLE_CALLBACK_URL = process.env.MOODLE_CALLBACK_URL;
const MOODLE_CLIENT_ID = process.env.MOODLE_CLIENT_ID;
const MOODLE_CLIENT_SECRET = process.env.MOODLE_CLIENT_SECRET;
const MOODLE_LOGOUT_CALLBACK_URL = process.env.MOODLE_LOGOUT_CALLBACK_URL;
// --- Environment Variable Validation ---
if (!ISSUER_URL || !MONGODB_URI || !process.env.SESSION_SECRET) {
    logger.error('FATAL ERROR: ISSUER_URL, MONGODB_URI, or SESSION_SECRET environment variable is not set.');
    process.exit(1);
}
// if (!FRONTEND_CALLBACK_URL) {
//     logger.warn('WARN: FRONTEND_URL environment variable is not set. Redirect URI for arademia_front_client will be empty.');
// }
// --- End Validation ---

// Define OIDC clients
const clients: ClientMetadata[] = [
    {
        client_name: 'Arademia Intranet',
        client_id: INTRANET_CLIENT_ID || '',
        client_secret: INTRANET_CLIENT_SECRET || '',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [INTRANET_CALLBACK_URL],
        post_logout_redirect_uris: [INTRANET_LOGOUT_CALLBACK_URL || ''],
        token_endpoint_auth_method: 'client_secret_post',
        application_type: 'web',
        scope: 'openid profile email offline_access',
    },
    {
        client_name: 'Arademia LMS',
        client_id: MOODLE_CLIENT_ID || '',
        client_secret: MOODLE_CLIENT_SECRET || '',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        redirect_uris: [MOODLE_CALLBACK_URL || ''],
        post_logout_redirect_uris: [MOODLE_LOGOUT_CALLBACK_URL || ''],
        token_endpoint_auth_method: 'client_secret_post',
        application_type: 'web',
        scope: 'openid profile email offline_access',
    },
];

const renderError = async (ctx: KoaContextWithOIDC, out: ErrorOut, error: Error) => {
    const oidcError = error as Error & { error?: string; error_description?: string };

    logger.error('[OIDC] Rendering error:', {
        error: oidcError.error,
        description: oidcError.error_description,
        timestamp: new Date().toISOString()
    });

    if (oidcError.error === 'invalid_request') {
        const req = ctx.req as IncomingMessage & { session?: { originalAuthParams?: Record<string, any> } };
        if (req.session?.originalAuthParams) {
            const authUrl = new URL('/auth', process.env.ISSUER_URL || 'http://localhost:5001');
            Object.entries(req.session.originalAuthParams).forEach(([key, value]) => {
                authUrl.searchParams.append(key, value as string);
            });
            logger.info('[OIDC] Redirecting to restart auth flow:', {
                url: authUrl.toString(),
                timestamp: new Date().toISOString()
            });
            return ctx.redirect(authUrl.toString());
        }
    }

    ctx.type = 'html';
    ctx.body = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Error</title>
        </head>
        <body>
          <h1>Error</h1>
          <p>${oidcError.error || 'server_error'}</p>
          <p>${oidcError.error_description || 'An unexpected error occurred'}</p>
        </body>
      </html>
    `;
}

// --- Configure MongoDB Adapter ---
// The adapter needs to be initialized before the provider configuration
// It expects the MONGODB_URI to be passed or available via process.env
// MongoAdapter.connect(MONGODB_URI); // Connect the adapter to MongoDB
// --- End Adapter Config ---

// Extend the CookiesSetOptions interface to include maxAge
declare module 'cookies' {
    interface CookiesSetOptions {
        maxAge?: number;
    }
}

const configuration: Configuration = {
    // --- Add the adapter configuration ---
    adapter: adapterFactory, // Use the MongoDB adapter factory
    // --- End Adapter Config ---

    clients: clients,
    findAccount: Account.findAccount,
    pkce: {
        methods: ['S256'],
        required: () => true,
    },
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    claims: {
        openid: ['sub'],
        profile: ['given_name', 'family_name', 'preferred_username'], // Removed 'name'
        email: ['email', 'email_verified'],
    },
    features: {
        devInteractions: { enabled: false },
        introspection: { enabled: true },
        revocation: { enabled: true },
        userinfo: { enabled: true },
        rpInitiatedLogout: { enabled: true },
        backchannelLogout: { enabled: true },
        resourceIndicators: { enabled: false },
        claimsParameter: { enabled: true },
        clientCredentials: { enabled: true },
    },
    // --- JWKS Configuration ---
    // REMOVED the jwks property entirely for development.
    // oidc-provider will generate ephemeral keys in memory on startup.
    //
    // IMPORTANT FOR PRODUCTION:
    // You MUST generate stable signing keys (e.g., RSA or EC) and configure them here.
    // Load keys securely (e.g., from environment variables or a key vault).
    // Example structure (DO NOT use these placeholders):
    // jwks: {
    //   keys: [
    //     { /* Your actual private key in JWK format */ }
    //   ],
    // },
    // --- End JWKS Configuration ---

    cookies: {
        keys: [process.env.SESSION_SECRET || 'default-secret-key'],
        long: {
            secure: process.env.NODE_ENV === 'production',
            signed: true,
            httpOnly: true,
            // @ts-ignore - maxAge is supported by the underlying cookie implementation
            maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days in milliseconds
            path: '/',
        },
        short: {
            path: '/',
            secure: process.env.NODE_ENV === 'production',
            signed: true,
            httpOnly: true,
            // @ts-ignore - maxAge is supported by the underlying cookie implementation
            maxAge: 10 * 60 * 1000, // 10 minutes in milliseconds
        },
    },
    interactions: {
        url(ctx: KoaContextWithOIDC, interaction: Interaction) {
            logger.info('[OIDC] Generating interaction URL:', {
                uid: interaction.uid,
                prompt: interaction.prompt,
                params: interaction.params,
                timestamp: new Date().toISOString()
            });
            return `/interaction/${interaction.uid}`;
        },
        // policy: [
        //     new Prompt({
        //         name: 'login',
        //         requestable: true // Allow clients to request 'login' prompt explicitly if needed
        //     }),
        //     new Prompt({
        //         name: 'consent',
        //         requestable: true // Allow clients to request 'consent' prompt explicitly if needed
        //     })
        // ]
    },
    renderError,
    // Add TTL configuration for various artifacts (optional but recommended)
    ttl: {
        AccessToken: 60 * 60, // 1 hour
        AuthorizationCode: 2 * 60 * 60, // 2 hours
        Grant: 14 * 24 * 60 * 60, // 14 days
        IdToken: 60 * 60, // 1 hour
        RefreshToken: 14 * 24 * 60 * 60, // 14 days
        Session: 14 * 24 * 60 * 60, // 14 days
        Interaction: 4 * 60 * 60, // 2 hours
    },
    logger: console
};



const oidc = new Provider(ISSUER_URL,configuration);

// Add request logging middleware
oidc.use(async (ctx: any, next: () => Promise<void>) => {
    const start = Date.now();
    logger.info(`[OIDC] Incoming ${ctx.request.method} request to ${ctx.request.url}`);
    logger.info(`[OIDC] Headers: ${JSON.stringify(ctx.request.headers)}`);

    try {
        await next();
        const duration = Date.now() - start;
        logger.info(`[OIDC] Request completed in ${duration}ms with status ${ctx.status}`);
    } catch (err: any) {
        logger.error(`[OIDC] Error processing request: ${err.message}`);
        logger.error(err.stack);
        throw err;
    }
});

// Add error handling middleware
oidc.on('error', (err: Error, ctx: any) => {
    logger.error(`[OIDC] Error occurred: ${JSON.stringify(err)}`);
    const session = ctx.session; // assume this is the session document from the database
    const expiresAt = new Date(session.expiresAt);
    const currentTime = new Date();

    if (currentTime > expiresAt) {
        logger.error('[OIDC] Session has expired');
    } else {
        logger.error('[OIDC] Session is still valid');
    }
    const errorType = err.name || 'UnknownError';
    const errorMessage = err.message;
    const requestUrl = ctx?.request?.url;
    const clientId = ctx?.oidc?.params?.client_id;
    const sessionId = ctx?.oidc?.session?.uid;

    logger.error(`[OIDC] Provider error: ${errorType} - ${errorMessage}`);
    logger.error(`[OIDC] Error context: URL=${requestUrl}, Client=${clientId}, SessionID=${sessionId}`);
    logger.error(`[OIDC] Stack trace: ${err.stack}`);

    // Handle specific OIDC errors
    switch (errorType) {
        case 'InvalidRequest':
            logger.warn('[OIDC] Invalid request - checking parameters');
            if (ctx?.oidc?.params) {
                logger.info(`[OIDC] Request parameters: ${JSON.stringify(ctx.oidc.params)}`);
            }
            break;

        case 'AccessDenied':
            logger.warn('[OIDC] Access denied - checking session state');
            if (ctx?.oidc?.session) {
                logger.info(`[OIDC] Session state: ${JSON.stringify({
                    uid: ctx.oidc.session.uid,
                    accountId: ctx.oidc.session.accountId,
                    exp: ctx.oidc.session.exp,
                })}`);
            }
            break;

        case 'SessionNotFound':
            logger.warn('[OIDC] Session not found - checking cookies and headers');
            logger.info(`[OIDC] Request cookies: ${JSON.stringify(ctx.request.cookies)}`);
            logger.info(`[OIDC] Request headers: ${JSON.stringify(ctx.request.headers)}`);
            break;

        case 'ExpiredToken':
            logger.warn('[OIDC] Token expired - checking expiration details');
            if (ctx?.oidc?.entities?.AccessToken || ctx?.oidc?.entities?.AuthorizationCode) {
                const token = ctx.oidc.entities.AccessToken || ctx.oidc.entities.AuthorizationCode;
                logger.info(`[OIDC] Token details: ${JSON.stringify({
                    exp: token.exp,
                    iat: token.iat,
                    kind: token.kind,
                })}`);
            }
            break;

        default:
            logger.error(`[OIDC] Unhandled error type: ${errorType}`);
            if (ctx?.oidc?.session) {
                logger.info(`[OIDC] Current session state: ${JSON.stringify({
                    uid: ctx.oidc.session.uid,
                    accountId: ctx.oidc.session.accountId,
                    exp: ctx.oidc.session.exp,
                })}`);
            }
    }

    // Handle authorization expiration
    if (errorMessage.includes('authorization request has expired')) {
        logger.warn('[OIDC] Authorization request expired, redirecting to restart flow');
        // Store the original request parameters in session
        if (ctx?.req?.session && ctx?.oidc?.params) {
            ctx.req.session.originalAuthParams = ctx.oidc.params;
            logger.info('[OIDC] Stored original auth parameters in session');
            // Redirect to restart the auth flow
            const authUrl = new URL('/auth', process.env.ISSUER_URL || 'http://localhost:5001');
            Object.entries(ctx.oidc.params).forEach(([key, value]) => {
                authUrl.searchParams.append(key, value as string);
            });
            logger.info(`[OIDC] Redirecting to: ${authUrl.toString()}`);
            ctx.res.redirect(authUrl.toString());
            return;
        }
    }

    // Log additional context for debugging
    if (ctx?.oidc?.session) {
        logger.info(`[OIDC] Session state: ${JSON.stringify(ctx.oidc.session)}`);
    }
    if (ctx?.oidc?.client) {
        logger.info(`[OIDC] Client details: ${JSON.stringify(ctx.oidc.client)}`);
    }
});

// Add token issuance logging via event listener
oidc.on('grant.success', (ctx: KoaContextWithOIDC, token: any) => {
    try {
        if (!token) {
            logger.error('[OIDC] Token issuance failed: token is undefined', {
                clientId: ctx.oidc.client?.clientId,
                grantId: ctx.oidc.grant?.grantId,
                timestamp: new Date().toISOString()
            });
            return;
        }

        // Log grant details
        if (ctx.oidc.grant) {
            logger.info('[OIDC] Grant details:', {
                grantId: ctx.oidc.grant.grantId,
                accountId: ctx.oidc.grant.accountId,
                clientId: ctx.oidc.grant.clientId,
                scope: ctx.oidc.grant.scope,
                timestamp: new Date().toISOString()
            });
        }

        // Log token details
        logger.info('[OIDC] Token issued:', {
            type: token.kind || 'unknown',
            clientId: ctx.oidc.client?.clientId,
            accountId: ctx.oidc.session?.accountId,
            scope: token.scope,
            expiresIn: token.expiresIn,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        logger.error('[OIDC] Error in grant.success handler:', {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined,
            clientId: ctx.oidc.client?.clientId,
            timestamp: new Date().toISOString()
        });
    }
});

// Add error handling for token issuance
oidc.on('grant.error', (ctx: KoaContextWithOIDC, error: Error) => {
    logger.error('[OIDC] Token issuance error:', {
        error: error.message,
        stack: error.stack,
        clientId: ctx.oidc.client?.clientId,
        grantId: ctx.oidc.grant?.grantId,
        accountId: ctx.oidc.session?.accountId,
        timestamp: new Date().toISOString()
    });
});

// Add grant creation logging
oidc.on('grant.created', (ctx: KoaContextWithOIDC, grant: any) => {
    try {
        if (!grant) {
            logger.error('[OIDC] Grant creation failed: grant is undefined');
            return;
        }
        logger.info('[OIDC] Grant created:', {
            grantId: grant.grantId,
            clientId: grant.clientId,
            accountId: grant.accountId,
            scope: grant.scope,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        logger.error('[OIDC] Error in grant.created handler:', {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined,
            timestamp: new Date().toISOString()
        });
    }
});

// Add grant saved logging
oidc.on('grant.saved', (ctx: KoaContextWithOIDC, grant: any) => {
    try {
        if (!grant) {
            logger.error('[OIDC] Grant save failed: grant is undefined');
            return;
        }
        logger.info('[OIDC] Grant saved:', {
            grantId: grant.grantId,
            clientId: grant.clientId,
            accountId: grant.accountId,
            scope: grant.scope,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        logger.error('[OIDC] Error in grant.saved handler:', {
            error: err instanceof Error ? err.message : 'Unknown error',
            stack: err instanceof Error ? err.stack : undefined,
            timestamp: new Date().toISOString()
        });
    }
});

// Production readiness (proxy handling)
if (process.env.NODE_ENV === 'production') {
    oidc.proxy = true;
}

// Add interaction creation logging
oidc.on('interaction.created', (ctx: KoaContextWithOIDC, interaction: any) => {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = interaction.exp;
    const timeRemaining = expiresAt ? expiresAt - now : 'unknown';
    const req = ctx.req as any; // Type assertion for session properties

    logger.info('[OIDC] Interaction created:', {
        uid: interaction.uid,
        prompt: interaction.prompt?.name,
        params: interaction.params,
        expiresAt,
        currentTime: now,
        timeRemaining,
        timestamp: new Date().toISOString(),
        sessionId: req?.sessionID,
        hasSession: !!req?.session,
        cookieExpires: req?.session?.cookie?.expires,
        maxAge: req?.session?.cookie?.maxAge,
        interactionDetails: {
            kind: interaction.kind,
            exp: interaction.exp,
            iat: interaction.iat,
            jti: interaction.jti,
            clientId: interaction.clientId,
            accountId: interaction.accountId,
            grantId: interaction.grantId,
            params: interaction.params,
            session: interaction.session
        }
    });
});

// Add interaction lookup logging
oidc.on('interaction.details', (ctx: KoaContextWithOIDC, interaction: any) => {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = interaction.exp;
    const timeRemaining = expiresAt ? expiresAt - now : 'unknown';
    const req = ctx.req as any; // Type assertion for session properties

    logger.info('[OIDC] Interaction details retrieved:', {
        uid: interaction.uid,
        prompt: interaction.prompt?.name,
        params: interaction.params,
        expiresAt,
        currentTime: now,
        timeRemaining,
        timestamp: new Date().toISOString(),
        sessionId: req?.sessionID,
        hasSession: !!req?.session,
        cookieExpires: req?.session?.cookie?.expires,
        maxAge: req?.session?.cookie?.maxAge,
        interactionDetails: {
            kind: interaction.kind,
            exp: interaction.exp,
            iat: interaction.iat,
            jti: interaction.jti,
            clientId: interaction.clientId,
            accountId: interaction.accountId,
            grantId: interaction.grantId,
            params: interaction.params,
            session: interaction.session
        }
    });
});

// Add interaction expiration logging
oidc.on('interaction.expired', (ctx: KoaContextWithOIDC, interaction: any) => {
    const now = Math.floor(Date.now() / 1000);
    const expiredAt = interaction.exp;
    const timeSinceExpiry = expiredAt ? now - expiredAt : 'unknown';
    const req = ctx.req as any; // Type assertion for session properties

    logger.warn('[OIDC] Interaction expired:', {
        uid: interaction.uid,
        prompt: interaction.prompt?.name,
        expiredAt,
        currentTime: now,
        timeSinceExpiry,
        timestamp: new Date().toISOString(),
        sessionId: req?.sessionID,
        hasSession: !!req?.session,
        cookieExpires: req?.session?.cookie?.expires,
        maxAge: req?.session?.cookie?.maxAge,
        interactionDetails: {
            kind: interaction.kind,
            exp: interaction.exp,
            iat: interaction.iat,
            jti: interaction.jti,
            clientId: interaction.clientId,
            accountId: interaction.accountId,
            grantId: interaction.grantId,
            params: interaction.params,
            session: interaction.session
        }
    });
});

export default oidc;