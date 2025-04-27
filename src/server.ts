// Import ErrorRequestHandler for explicit typing
import express, { Express, Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet';
import cluster from 'cluster';
import os from 'os';
import process from 'process';
import path from 'path';
import cors from 'cors';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import responseTime from 'response-time';
import cookieParser from 'cookie-parser'; // Corrected import style
import mongoose from 'mongoose';
import expressLayouts from 'express-ejs-layouts';
import { requestLogger } from './config/middlewares/requestLogger';
import logger from './config/middlewares/logger';
import favicon from 'serve-favicon';

dotenv.config(); // Load .env variables first
import connectDB from './config/database';
import oidcProvider from './config/oidcProvider'; // Ensure this initializes the provider instance
import authRoutes from './routes/authRoutes';
import interactionRoutes from './routes/interactionRoutes';

const PORT = process.env.PORT || 5001;
// Removed ISSUER_URL definition here as it's usually configured within oidcProvider setup
const numCPUs = process.env.WORKERS ? parseInt(process.env.WORKERS, 10) : os.cpus().length;

const activeWorkers = new Set<number>(); // Track active workers

if (cluster.isPrimary) {
    logger.debug(`[Auth Server]: Primary process ${process.pid} is running`);
    const workersToFork = Math.min(numCPUs, os.cpus().length);
    logger.debug(`[Auth Server]: Forking ${workersToFork} workers...`);
    for (let i = 0; i < workersToFork; i++) cluster.fork();

    cluster.on('online', (worker) => {
        if (worker?.process?.pid) activeWorkers.add(worker.process.pid);
        logger.debug(`[Auth Server]: Worker ${worker.process.pid} is online`);
    });

    cluster.on('exit', (worker, code, signal) => {
        if (worker?.process?.pid) activeWorkers.delete(worker.process.pid);
        logger.error(`[Auth Server]: Worker ${worker.process.pid} exited with code ${code} and signal ${signal}`);
        if (code !== 0 && !worker.exitedAfterDisconnect) {
            logger.debug('[Auth Server]: Forking new worker...');
            cluster.fork();
        }
    });

    const primaryShutdown = (signal: string) => {
        logger.debug(`[Primary]: ${signal} received. Shutting down workers.`);
        for (const id in cluster.workers) {
            cluster.workers[id]?.kill();
        }
        logger.debug(`Active workers on exit: ${[...activeWorkers]}`);
        process.exit(0);
    };

    process.on('SIGTERM', () => primaryShutdown('SIGTERM'));
    process.on('SIGINT', () => primaryShutdown('SIGINT'));
} else {
    const app: Express = express();
    connectDB();

    // Trust proxy is important if behind a load balancer or reverse proxy (e.g., Heroku, Nginx)
    // for secure cookies and correct IP addresses. Adjust '1' if you have more proxy layers.
    app.set('trust proxy', 1);

    app.set('views', path.join(__dirname, './views'));
    app.set('view engine', 'ejs');
    app.set('layout', 'layout'); // Default layout file name
    app.use(expressLayouts);

    // Serve favicon
    app.use(favicon(path.join(__dirname, './assets/favicon.ico')));

    // Serve static files from the assets directory
    app.use('/assets', express.static(path.join(__dirname, './assets'), {
        maxAge: '1y', // Example cache control
        // Example: Add specific content types for fonts if needed
        setHeaders: (res, filePath) => {
            if (filePath.endsWith('.woff2')) {
                res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
                res.setHeader('Content-Type', 'font/woff2');
            } else if (filePath.endsWith('.woff')) {
                 res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
                 res.setHeader('Content-Type', 'font/woff');
            }
        }
    }));

    // Response time logging first
    app.use(responseTime(requestLogger));

    // Security headers (adjust ContentSecurityPolicy as needed)
    // Consider using a stricter CSP in production
    app.use(helmet({
        contentSecurityPolicy: false, // Temporarily disabled, configure properly for production!
        // Example stricter setup (needs customization):
        // contentSecurityPolicy: {
        //     directives: {
        //         defaultSrc: ["'self'"],
        //         scriptSrc: ["'self'", "'unsafe-inline'"], // Adjust based on your scripts
        //         styleSrc: ["'self'", "'unsafe-inline'"], // Adjust based on your styles
        //         imgSrc: ["'self'", "data:"],
        //         fontSrc: ["'self'"],
        //         connectSrc: ["'self'"], // Add domains for API calls if needed
        //         formAction: ["'self'"],
        //         frameAncestors: ["'none'"], // Prevent clickjacking
        //     },
        // },
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // Enforce HTTPS
        referrerPolicy: { policy: 'strict-origin-when-cross-origin'}, // Control referrer header
    }));

    // CORS configuration
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173'; // Default for development
    app.use(cors({
        origin: frontendUrl, // Allow only your frontend domain
        credentials: true, // Allow cookies to be sent
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allowed methods
        allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
    }));

    // Parsers for request bodies
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Cookie parser (place before session)
    app.use(cookieParser());

    // Check for essential environment variables
    if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
        logger.error(`[Worker ${process.pid}]: FATAL ERROR: SESSION_SECRET or MONGODB_URI is not defined.`);
        process.exit(1); // Exit if essential config is missing
    }

    // Session middleware (requires cookieParser)
    // Needs to come before oidcProvider and any routes using req.session
    app.use(
        session({
            secret: process.env.SESSION_SECRET,
            resave: false, // Don't save session if unmodified
            saveUninitialized: false, // Don't create session until something stored
            store: MongoStore.create({
                 mongoUrl: process.env.MONGODB_URI,
                 // Recommended options for MongoStore
                 ttl: process.env.SESSION_MAX_AGE_MS ? parseInt(process.env.SESSION_MAX_AGE_MS) / 1000 : 14 * 24 * 60 * 60, // TTL in seconds (default: 14 days)
                 autoRemove: 'native', // Recommended
            }),
            cookie: {
                secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
                httpOnly: true, // Prevent client-side JS access
                maxAge: process.env.SESSION_MAX_AGE_MS ? parseInt(process.env.SESSION_MAX_AGE_MS) : 24 * 60 * 60 * 1000, // e.g., 1 day
                // sameSite: 'Lax' is a good default. Use 'None' only if necessary for cross-site scenarios AND secure=true
                sameSite: process.env.NODE_ENV === 'production' ? 'lax' : (process.env.NODE_ENV === 'development' ? 'lax' : undefined), // Explicitly Lax in dev too?
            },
            name: process.env.SESSION_NAME || 'arademia.auth.sid', // Use a specific session cookie name
        })
    );

    // ** IMPORTANT: Middleware Order Adjustment **

    // Mount interaction routes first - they define the UI for interaction prompts
    // These routes rely on the interaction context set up *by* the provider *before* redirecting here.
    app.use('/interaction', interactionRoutes);

    // Mount custom authentication strategy routes (like Google login)
    // These are *part of* an interaction flow initiated earlier.
    app.use('/auth', authRoutes); // This contains '/auth/google' etc.

    // Mount OIDC provider middleware LAST without a path prefix.
    // This lets it handle all standard OIDC endpoints (`/auth`, `/token`, `/jwks`, etc.)
    // It needs session middleware configured before it.
    // Requests to `/interaction/*` and `/auth/*` will be caught by the routers above first.
    // Requests for standard OIDC endpoints will fall through to this handler.
    app.use(oidcProvider.callback());


    // --- Root route and Error Handling ---

    app.get('/', (req: Request, res: Response) => {
        // Avoid logging sensitive session info here if possible
        logger.debug(`[Auth Worker ${process.pid}] GET / request received`);
        res.status(200).json({ message: `Arademia Auth Server Worker ${process.pid} is running.` });
    });


    // Catch 404s that fall through previous routes/middleware
    app.use((req: Request, res: Response, next: NextFunction) => {
        // Check if response has already been sent by OIDC provider or other middleware
        if (!res.headersSent) {
             logger.warn(`[Auth Worker ${process.pid}] 404 Not Found: ${req.method} ${req.originalUrl}`);
             res.status(404).json({
                 error: 'NotFound',
                 error_description: `Resource not found on Auth Server at ${req.originalUrl}`,
             });
        } else {
             next(); // Ensure next() is called if headers were sent but middleware didn't end response
        }
    });


    // Centralized Error Handler - Must be the LAST `app.use`
    const centralErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
        // If headers already sent, delegate to the default Express error handler
        if (res.headersSent) {
            return next(err);
        }

        logger.error(`[Auth Worker ${process.pid}] Error during request ${req.method} ${req.originalUrl}: ${err.message}`);
        logger.error(err.stack); // Log stack trace for debugging

        const statusCode = err.statusCode || err.status || 500; // Standardize status code access
        const errorResponse = {
            error: err.error || err.name || 'InternalServerError',
            error_description: err.error_description || err.message || 'An internal server error occurred',
            // Optionally include stack trace in development
            ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),
            // Include OIDC state if available in the error object
            ...(err.state ? { state: err.state } : {}),
        };

        res.status(statusCode).json(errorResponse);
    };

    app.use(centralErrorHandler);


    // --- Server Start and Graceful Shutdown ---
    const server = app.listen(PORT, () => {
        logger.debug(`[Auth Server]: Worker ${process.pid} started. Listening on port ${PORT}. Frontend URL: ${frontendUrl}`);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
        logger.error(`[Auth Worker ${process.pid}] Unhandled Rejection at:`, promise, 'reason:', reason);
        // Consider crashing the process for unhandled rejections, depending on your strategy
        // shutdown('UnhandledRejection'); // Optionally trigger shutdown
    });

    // Handle uncaught exceptions
     process.on('uncaughtException', (error) => {
        logger.error(`[Auth Worker ${process.pid}] Uncaught Exception:`, error);
        // Crashing is generally recommended for uncaught exceptions
        process.exit(1); // Exit immediately
        // shutdown('UncaughtException'); // Or attempt graceful shutdown if possible
     });


    const shutdown = (signal: string) => {
        logger.debug(`[Auth Worker ${process.pid}]: ${signal} signal received. Starting graceful shutdown.`);
        const shutdownTimer = setTimeout(() => {
            logger.warn(`[Auth Worker ${process.pid}]: Forced shutdown after timeout.`);
            process.exit(1);
        }, 15000); // Increased timeout slightly

        server.close((err) => {
            if (err) {
                logger.error(`[Auth Worker ${process.pid}]: Error closing HTTP server:`, err);
                clearTimeout(shutdownTimer);
                process.exit(1);
                return;
            }
            logger.debug(`[Auth Worker ${process.pid}]: HTTP server closed.`);
            mongoose.connection
                .close(false) // Pass false to allow existing operations to finish if possible
                .then(() => {
                    logger.debug(`[Auth Worker ${process.pid}]: MongoDB connection closed.`);
                    clearTimeout(shutdownTimer);
                    logger.debug(`[Auth Worker ${process.pid}]: Exiting gracefully.`);
                    process.exit(0);
                })
                .catch((mongoErr) => {
                    logger.error(`[Auth Worker ${process.pid}]: Error closing MongoDB connection:`, mongoErr);
                    clearTimeout(shutdownTimer);
                    process.exit(1);
                });
        });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM')); // Standard signal for termination
    process.on('SIGINT', () => shutdown('SIGINT'));  // Ctrl+C
}