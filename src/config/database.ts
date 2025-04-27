import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { Db as MongoDb } from 'mongodb'; // Import Db type for clarity
import logger from './middlewares/logger';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI?.trim();;

if (!MONGODB_URI) {
    logger.error('FATAL ERROR: MONGODB_URI environment variable is not set.');
    process.exit(1);
}

// Store the connection instance
let dbInstance: mongoose.Connection | null = null;

const connectDB = async (): Promise<void> => {
    // Prevent multiple connection attempts in the same process
    if (dbInstance && dbInstance.readyState === 1) {
         logger.debug(`[database][Worker ${process.pid}]: MongoDB already connected.`);
         return;
    }
    try {
        mongoose.set('strictQuery', false);
        await mongoose.connect(MONGODB_URI);
        dbInstance = mongoose.connection; // Store the connection instance
        logger.debug(`[database]: MongoDB connected successfully on worker ${process.pid}.`);

        // Event listeners for connection health
        dbInstance.on('error', (err) => {
            logger.error(`[database][Worker ${process.pid}]: MongoDB connection error:`, err);
        });
        dbInstance.on('disconnected', () => {
            logger.debug(`[database][Worker ${process.pid}]: MongoDB disconnected.`);
            dbInstance = null; // Reset instance on disconnect
        });
        // Optional: Listener for reconnected event
        dbInstance.on('reconnected', () => {
             logger.debug(`[database][Worker ${process.pid}]: MongoDB reconnected.`);
        });


    } catch (error) {
        logger.error(`[database][Worker ${process.pid}]: MongoDB connection failed during initial connect:`, error);
        process.exit(1); // Exit if initial connection fails
    }
};

// Function to get the underlying native driver's Db instance from Mongoose connection
// Ensure this function is EXPORTED
export const getDb = (): MongoDb | null => {
    // Access the native MongoDB driver's client instance via Mongoose connection
    // The 'client' property holds the MongoClient instance
    // The 'db()' method on MongoClient returns the Db instance
    return dbInstance?.getClient().db() ?? null; // Use getClient() to access the native MongoDB client
}

export default connectDB;
