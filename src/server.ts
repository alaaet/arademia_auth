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
import mongoose from 'mongoose';
import { requestLogger } from './config/middlewares/requestLogger';
import logger from './config/middlewares/logger';

dotenv.config(); // Load .env variables first
import connectDB from './config/database';
import oidcProvider from './config/oidcProvider';
import authRoutes from './routes/authRoutes';
import interactionRoutes from './routes/interactionRoutes';

const PORT = process.env.PORT || 5001;
const ISSUER_URL = process.env.ISSUER_URL || `http://localhost:${PORT}`;
const numCPUs = process.env.WORKERS ? parseInt(process.env.WORKERS, 10) : os.cpus().length;

const activeWorkers = new Set<number>(); // Track active workers

if (cluster.isPrimary) {
    logger.info(`[Auth Server]: Primary process ${process.pid} is running`);
    const workersToFork = Math.min(numCPUs, os.cpus().length);
    logger.info(`[Auth Server]: Forking ${workersToFork} workers...`);
    for (let i = 0; i < workersToFork; i++) cluster.fork();

    cluster.on('online', (worker) => {
        if (worker?.process?.pid)activeWorkers.add(worker.process.pid);
        logger.info(`[Auth Server]: Worker ${worker.process.pid} is online`);
    });

    cluster.on('exit', (worker, code, signal) => {
        if (worker?.process?.pid)activeWorkers.delete(worker.process.pid);
        logger.error(`[Auth Server]: Worker ${worker.process.pid} exited with code ${code} and signal ${signal}`);
        if (code !== 0 && !worker.exitedAfterDisconnect) {
            logger.info('[Auth Server]: Forking new worker...');
            cluster.fork();
        }
    });

    const primaryShutdown = (signal: string) => {
        logger.info(`[Primary]: ${signal} received. Shutting down workers.`);
        for (const id in cluster.workers) {
            cluster.workers[id]?.kill();
        }
        logger.info(`Active workers on exit: ${[...activeWorkers]}`);
        process.exit(0);
    };

    process.on('SIGTERM', () => primaryShutdown('SIGTERM'));
    process.on('SIGINT', () => primaryShutdown('SIGINT'));
} else {
    const app: Express = express();
    connectDB();

    app.set('views', path.join(__dirname, './views'));
    app.set('view engine', 'ejs');

    app.use(responseTime(requestLogger));
    app.use(helmet({ contentSecurityPolicy: false }));

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    app.use(cors({ origin: frontendUrl, credentials: true }));

    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
        logger.error(`[Worker ${process.pid}]: FATAL ERROR: SESSION_SECRET or MONGODB_URI is not defined.`);
        process.exit(1);
    }

    app.use(
        session({
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
            cookie: {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                maxAge: process.env.SESSION_MAX_AGE_MS ? parseInt(process.env.SESSION_MAX_AGE_MS) : 86400000,
                sameSite: process.env.NODE_ENV === 'production' ? 'lax' : undefined,
            },
            name: process.env.SESSION_NAME || 'connect.sid',
        })
    );

    app.get('/', (req: Request, res: Response) => {
        logger.info(`Auth Server Worker ${process.pid} responding!`);
        res.status(200).json({ message: `Auth Server Worker ${process.pid} responding!` });
    });

    app.use('/interaction', interactionRoutes);
    app.use('/auth', authRoutes);
    app.use(oidcProvider.callback());

    app.use((req: Request, res: Response, next: NextFunction) => {
        if (!res.headersSent) {
            res.status(404).json({ message: 'Resource not found on Auth Server' });
        } else {
            next();
        }
    });

    const centralErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
        logger.error(`[Auth Worker ${process.pid}] Error: ${err.message}`);
        logger.error(err.stack);
        const statusCode = (err as any).statusCode || 500;
        res.status(statusCode).json({
            error: (err as any).error || err.name || 'InternalServerError',
            error_description: err.message || 'Internal Server Error',
            ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),
        });
    };

    app.use(centralErrorHandler);

    const server = app.listen(PORT, () => {
        logger.info(`[Auth Server]: Worker ${process.pid} started on port ${PORT}`);
    });

    const shutdown = (signal: string) => {
        logger.info(`[Auth Worker ${process.pid}]: ${signal} signal received: closing HTTP server`);
        const shutdownTimer = setTimeout(() => {
            logger.warn(`[Auth Worker ${process.pid}]: Forced shutdown after timeout`);
            process.exit(1);
        }, 10000);

        server.close(() => {
            clearTimeout(shutdownTimer);
            logger.info(`[Auth Worker ${process.pid}]: HTTP server closed`);
            mongoose.connection
                .close(false)
                .then(() => {
                    logger.info(`[Auth Worker ${process.pid}]: MongoDB connection closed`);
                    process.exit(0);
                })
                .catch((err) => {
                    logger.error(`[Auth Worker ${process.pid}]: Error closing MongoDB connection:`, err);
                    process.exit(1);
                });
        });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}
