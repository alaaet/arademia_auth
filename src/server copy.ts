// Import ErrorRequestHandler for explicit typing
import express, { Express, Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet'; // Security headers
import cluster from 'cluster';
import os from 'os';
import process from 'process';
import path from 'path';
import cors from 'cors'; // Import cors
// const bodyParser = require('body-parser'); // Needed for parsing JSON payloads
import session from 'express-session'; // Import session
import MongoStore from 'connect-mongo'; // Import MongoStore
import responseTime from 'response-time'; // Import response-time for logging request duration
// Passport import might not be needed if not using local strategies alongside OIDC
// import passport from 'passport';

// --- Configuration ---
dotenv.config(); // Load .env variables first
import connectDB from './config/database'; // Import DB connection function
import oidcProvider from './config/oidcProvider'; // Import the configured provider
import authRoutes from './routes/authRoutes'; // Standard auth routes (status, logout)
import interactionRoutes from './routes/interactionRoutes'; // OIDC Interaction routes
import mongoose from 'mongoose';
import { requestLogger } from './config/middlewares/requestLogger';
import logger from './config/middlewares/logger';

const PORT = process.env.PORT || 5001; // Use port 5001 for auth service
const ISSUER_URL = process.env.ISSUER_URL || `http://localhost:${PORT}`; // Get issuer URL for CSP
const numCPUs = process.env.WORKERS ? parseInt(process.env.WORKERS, 10) : os.cpus().length;

// --- Cluster Setup ---
if (cluster.isPrimary) {
    logger.info(`[Auth Server]: Primary process ${process.pid} is running`);
    const workersToFork = Math.min(numCPUs, os.cpus().length);
    logger.info(`[Auth Server]: Forking ${workersToFork} workers...`);
    for (let i = 0; i < workersToFork; i++) cluster.fork();
    cluster.on('online', (worker) => logger.info(`[Auth Server]: Worker ${worker.process.pid} is online`));
    cluster.on('exit', (worker, code, signal) => {
        logger.error(`[Auth Server]: Worker ${worker.process.pid} died.`);
        if (code !== 0 && !worker.exitedAfterDisconnect) {
            logger.info('[Auth Server]: Forking new worker...');
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

    // Request logger middleware for logging requests
    app.use(responseTime(requestLogger))
    

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
    logger.info(`[Worker ${process.pid}]: Allowing CORS for origin: ${frontendUrl}`);
    app.use(cors({ origin: frontendUrl, credentials: true }));

    // --- Body Parsers ---
    app.use(express.json());
    // app.use(bodyParser.json()); // Parses JSON payloads
    app.use(express.urlencoded({ extended: true })); // Needed for form submissions (login, consent)

    // --- Session Middleware (Required for oidc-provider interactions/sessions) ---
    if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
        logger.error(`[Worker ${process.pid}]: FATAL ERROR: SESSION_SECRET or MONGODB_URI is not defined.`);
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
        logger.info( `Auth Server Worker ${process.pid} responding!`);
        res.status(200).json({ message: `Auth Server Worker ${process.pid} responding!` });
    });

    // Mount interaction routes separately to handle login/consent UI
    app.use('/interaction', interactionRoutes);

    // Mount standard auth routes (like status, logout)
    app.use('/auth', authRoutes); // Mounted at /auth path

    // --- OIDC Provider Middleware ---
    // Mount the oidc-provider middleware HERE, before other app-specific routes
    // that might potentially conflict or need OIDC context established first.
    // It handles standard OIDC endpoints like /auth, /token, /jwks, /userinfo etc.
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
        logger.error(`[Auth Worker ${process.pid}] Error: ${err.message}`);
        logger.error(err.stack); // Log stack trace for debugging

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


    // --- Start Server ---
    const server = app.listen(PORT, () => {
        logger.info(`[Auth Server]: Worker ${process.pid} started on port ${PORT}`);
    });

    // Graceful shutdown
    const shutdown = (signal: string) => {
        logger.info(`[Auth Worker ${process.pid}]: ${signal} signal received: closing HTTP server`);
        server.close(() => {
            logger.info(`[Auth Worker ${process.pid}]: HTTP server closed`);
            mongoose.connection.close(false).then(() => {
                logger.info(`[Auth Worker ${process.pid}]: MongoDB connection closed`);
                process.exit(0);
            }).catch(err => {
                logger.error(`[Auth Worker ${process.pid}]: Error closing MongoDB connection:`, err);
                process.exit(1);
            });
        });
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}
