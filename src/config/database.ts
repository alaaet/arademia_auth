import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI?.trim();;

if (!MONGODB_URI) {
    console.error('FATAL ERROR: MONGODB_URI environment variable is not set.');
    process.exit(1);
}else{
    console.info(`[database]: MONGODB_URI: ${MONGODB_URI}`);
}

const connectDB = async (): Promise<void> => {
    try {
        // Set strictQuery to false to prepare for Mongoose 7 default, or true/false based on preference
        mongoose.set('strictQuery', false); // Or true, depending on your needs
        await mongoose.connect(MONGODB_URI);
        console.log(`[database]: MongoDB connected successfully on worker ${process.pid}.`); // Log worker PID

        // Optional: Listen for connection events
        mongoose.connection.on('error', (err) => {
            console.error(`[database][Worker ${process.pid}]: MongoDB connection error:`, err);
        });

        mongoose.connection.on('disconnected', () => {
            console.log(`[database][Worker ${process.pid}]: MongoDB disconnected.`);
        });

    } catch (error) {
        console.error(`[database][Worker ${process.pid}]: MongoDB connection failed:`, error);
        // Exit process with failure - important for cluster workers
        process.exit(1);
    }
};

export default connectDB;
