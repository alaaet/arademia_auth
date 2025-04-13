// Import ErrorRequestHandler for explicit typing
import express, { Express, Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet'; // Security headers
import cluster from 'cluster';
import os from 'os';
import process from 'process';
import path from 'path';
import cors from 'cors'; // Import cors
import session from 'express-session'; // Import session
import MongoStore from 'connect-mongo'; // Import MongoStore
// Passport import might not be needed if not using local strategies alongside OIDC
// import passport from 'passport';

// --- Configuration ---
dotenv.config(); // Load .env variables first
import connectDB from './config/database'; // Import DB connection function
import oidcProvider from './config/oidcProvider'; // Import the configured provider
//import './config/passportSetup'; // Import Passport configuration (runs the setup) - Remove if not using passport explicitly
// Import routes
// Remove courseRoutes and postRoutes as they belong in arademia_api
// import courseRoutes from './routes/courseRoutes';
// import postRoutes from './routes/postRoutes';
import authRoutes from './routes/authRoutes'; // Standard auth routes (status, logout)
import interactionRoutes from './routes/interactionRoutes'; // OIDC Interaction routes
import mongoose from 'mongoose';

const PORT = process.env.PORT || 5001; // Use port 5001 for auth service
const ISSUER_URL = process.env.ISSUER_URL || `http://localhost:${PORT}`; // Get issuer URL for CSP
const numCPUs = process.env.WORKERS ? parseInt(process.env.WORKERS, 10) : os.cpus().length;

// --- Cluster Setup ---
if (cluster.isPrimary) {
    console.log(`[Auth Server]: Primary process ${process.pid} is running`);
    const workersToFork = Math.min(numCPUs, os.cpus().length);
    console.log(`[Auth Server]: Forking ${workersToFork} workers...`);
    for (let i = 0; i < workersToFork; i++) cluster.fork();
    cluster.on('online', (worker) => console.log(`[Auth Server]: Worker ${worker.process.pid} is online`));
    cluster.on('exit', (worker, code, signal) => {
        console.error(`[Auth Server]: Worker ${worker.process.pid} died.`);
        if (code !== 0 && !worker.exitedAfterDisconnect) {
            console.log('[Auth Server]: Forking new worker...');
            cluster.fork();
        }
    });
} else {
    // --- Worker Process ---
    const app: Express = express();
    connectDB(); // Connect DB

    // --- View Engine Setup ---
    app.set('views', path.join(__dirname, './views')); // Set views directory relative to src
    app.set('view engine', 'ejs'); // Set EJS as the view engine

    // --- Security Middleware ---
    // Explicitly configure Helmet's Content Security Policy
    // app.use(
    //     helmet({
    //         contentSecurityPolicy: {
    //             directives: {
    //                 ...helmet.contentSecurityPolicy.getDefaultDirectives(), // Start with Helmet's recommended defaults
    //                 "form-action": ["'self'",ISSUER_URL], // Explicitly allow forms to POST to the same origin
    //                 // Add other directives here if needed later, e.g., for scripts, styles, images
    //                 // "script-src": ["'self'", "trusted-cdn.com"],
    //                 // "style-src": ["'self'", "'unsafe-inline'"], // Example, be careful with unsafe-inline
    //             },
    //         },
    //         // Optional: Adjust other helmet features if needed
    //         // crossOriginEmbedderPolicy: false, // Example if causing issues
    //     })
    // );
    // Temporarily disable CSP for debugging
    
    app.use(helmet({ contentSecurityPolicy: false }));

    // Uncomment this if you want to use CSP with Helmet
    // app.use(
    //     helmet({
    //       contentSecurityPolicy: {
    //         useDefaults: true,
    //         directives: {
    //           "script-src": ["'self'", ISSUER_URL],
    //           "frame-src": ["'self'", ISSUER_URL], // For iframes, if used
    //           "connect-src": ["'self'", ISSUER_URL], // For XHR/WebSocket
    //         },
    //       },
    //       frameguard: {
    //         action: "sameorigin", // or 'allow-from' with a URL if needed
    //       },
    //       referrerPolicy: {
    //         policy: "no-referrer-when-downgrade",
    //       },
    //     })
    //   );

    // --- CORS Middleware ---
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    console.log(`[Worker ${process.pid}]: Allowing CORS for origin: ${frontendUrl}`);
    app.use(cors({ origin: frontendUrl, credentials: true }));

    // --- Body Parsers ---
    app.use(express.json());
    app.use(express.urlencoded({ extended: true })); // Needed for form submissions (login, consent)

    // --- Session Middleware (Required for oidc-provider interactions/sessions) ---
    if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
        console.error(`[Worker ${process.pid}]: FATAL ERROR: SESSION_SECRET or MONGODB_URI is not defined.`);
        process.exit(1);
    }
    app.use(session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            maxAge: process.env.SESSION_MAX_AGE_MS ? parseInt(process.env.SESSION_MAX_AGE_MS) : 86400000,
            sameSite: process.env.NODE_ENV === 'production' ? 'lax' : undefined
        },
        name: process.env.SESSION_NAME || 'connect.sid'
    }));

    // --- Routes ---
    // Simple health check / worker check route
    app.get('/', (req: Request, res: Response) => {
        res.status(200).json({ message: `Auth Server Worker ${process.pid} responding!` });
    });

    // Mount interaction routes separately to handle login/consent UI
    app.use('/interaction', interactionRoutes);

    // Mount standard auth routes (like status, logout)
    app.use('/auth', authRoutes); // Mounted at /auth path

    // Mount the oidc-provider middleware.
    // It handles OIDC discovery, jwks, authorization, token endpoints etc.
    // Mounting it at the root '/' is common practice for OIDC providers.
    app.use(oidcProvider.callback());

    // --- Error Handling ---
    // Basic Not Found Handler (Place after all other routes)
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (!res.headersSent) {
            res.status(404).json({ message: 'Resource not found on Auth Server' });
        } else {
            next();
        }
    });

    // Define the Central Error Handling Middleware with explicit type
    const centralErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
        console.error(`[Auth Worker ${process.pid}] Error: ${err.message}`);
        console.error(err.stack); // Log stack trace for debugging

        // Handle specific oidc-provider errors if needed
        if ((err as any).name === 'InteractionNeeded') {
            // Send response but DO NOT return it from the function
            res.status(500).json({ error: 'interaction_required', message: 'User interaction needed but interaction route failed.' });
            return; // End execution for this specific case after sending response
        }
        // Add more specific OIDC error handling if desired (e.g., err.statusCode)

        const statusCode = (err as any).statusCode || 500;
        // Avoid sending stack trace in production
        // Send response - no return needed here as it's the end of the function
        res.status(statusCode).json({
            error: (err as any).error || err.name || 'InternalServerError',
            error_description: err.message || 'Internal Server Error',
            ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {})
        });
        // Note: If there was code after this res.status().json(), you would add 'return;'
    };

    // Use the explicitly typed error handler (Place last)
    app.use(centralErrorHandler);


    // In src/server.ts (Worker process section)

    oidcProvider.on('server_error', (ctx, error) => {
        // ctx is the Koa context oidc-provider uses internally
        console.error('OIDC Provider Server Error Event:', error, 'Context:', ctx?.request?.url);
    });

    oidcProvider.on('grant.error', (ctx, error) => {
        console.error('OIDC Provider Grant Error Event:', error, 'Context:', ctx?.request?.url);
    });

    oidcProvider.on('authorization_code.saved', (code) => {
        console.log('OIDC Provider Event: Authorization Code Saved - JTI:', code.jti, 'GrantID:', code.grantId);
    });

    oidcProvider.on('grant.saved', (grant) => {
        console.log('OIDC Provider Event: Grant Saved - ID:', grant.jti, 'AccountID:', grant.accountId);
    });

    oidcProvider.on('interaction.finished', async (ctx) => {
        console.log('OIDC Provider Event: Interaction Finished - ID:', ctx.interactionId);
        const interaction = await oidcProvider.Interaction.find(ctx.interactionId);
        if (interaction) {
            console.log('OIDC Provider Event: Interaction Found - ID:', ctx.interactionId);
        } else {
            console.log('OIDC Provider Event: Interaction Not Found - ID:', ctx.interactionId);
        }
    });

    oidcProvider.on('server_error', (ctx, error) => { console.error('OIDC Provider Server Error Event:', error); });
    oidcProvider.on('grant.error', (ctx, error) => { console.error('OIDC Provider Grant Error Event:', error); });

    // oidc redirect event
    oidcProvider.on('redirect_uri.success', (ctx) => {
        console.log('OIDC Provider Event: Redirect URI Success - Context:', ctx.request.url);
    });
    oidcProvider.on('redirect_uri.error', (ctx, error) => {
        console.error('OIDC Provider Event: Redirect URI Error - Context:', ctx.request.url, 'Error:', error);
    });


    // --- Start Server ---
    const server = app.listen(PORT, () => {
        console.log(`[Auth Server]: Worker ${process.pid} started on port ${PORT}`);
    });

    // Graceful shutdown
    const shutdown = (signal: string) => {
        console.log(`[Auth Worker ${process.pid}]: ${signal} signal received: closing HTTP server`);
        server.close(() => {
            console.log(`[Auth Worker ${process.pid}]: HTTP server closed`);
            mongoose.connection.close(false).then(() => {
                console.log(`[Auth Worker ${process.pid}]: MongoDB connection closed`);
                process.exit(0);
            }).catch(err => {
                console.error(`[Auth Worker ${process.pid}]: Error closing MongoDB connection:`, err);
                process.exit(1);
            });
        });
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}
