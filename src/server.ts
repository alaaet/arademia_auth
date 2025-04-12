import express, { Express, Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet'; // Security headers
import cluster from 'cluster';
import os from 'os';
import process from 'process';
import path from 'path';
import interactionRoutes from './routes/interactionRoutes'; // Import interaction routes

// --- Configuration ---
dotenv.config();
import connectDB from './config/database';
import oidcProvider from './config/oidcProvider'; // Import the configured provider
// Import interaction routes later
// import interactionRoutes from './routes/interactionRoutes';

const PORT = process.env.PORT || 5001; // Use port 5001 for auth service
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
    app.set('views', path.join(__dirname, '../views')); // Set views directory relative to src
    app.set('view engine', 'ejs'); // Set EJS as the view engine
    
    // --- Security Middleware ---
    app.use(helmet()); // Apply basic security headers

    // --- OIDC Provider Middleware ---
    // Mount the oidc-provider instance. It handles all OIDC routes.
    app.use(oidcProvider.callback());

    // --- Optional: Interaction Routes (Login, Consent Pages) ---
    // These routes render HTML forms for user interaction (login, consent)
    // You'll need a view engine (like EJS, Pug) and route handlers
    // app.set('view engine', 'ejs');
    // app.set('views', path.join(__dirname, 'views'));
    // app.use('/interaction', interactionRoutes); // Mount interaction routes

    // --- Basic Routes ---
    app.get('/', (req: Request, res: Response) => {
        res.status(200).json({ message: `Worker ${process.pid} responding!` });
    });

    // Mount interaction routes separately to handle login/consent UI
    app.use('/interaction', interactionRoutes);

    // --- Error Handling ---
    app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
         console.error(`[Auth Worker ${process.pid}] Error: ${err.message}`);
         console.error(err.stack);
         res.status(500).json({ error: 'Internal Server Error', message: err.message });
    });


    // --- Start Server ---
    const server = app.listen(PORT, () => {
        console.log(`[Auth Server]: Worker ${process.pid} started on port ${PORT}`);
    });

    // Graceful shutdown
    const shutdown = (signal: string) => { /* ... implement graceful shutdown ... */ };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}