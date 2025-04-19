// // src/config/logger.ts
import winston from 'winston';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config(); // Load .env to potentially configure log level

// const logDir = 'logs'; // Directory to store log files
// const logLevel = process.env.LOG_LEVEL || 'info'; // Get level from env or default to info

// // Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }), // Log stack traces
    winston.format.splat(),
    winston.format.printf(({ timestamp, level, message, stack }) => {
        return `${timestamp} [${level}]: ${stack ? `${stack}\n` : message}`;
    })
);
// const logFormat = winston.format.combine(
//     winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
//     winston.format.errors({ stack: true }), // Log stack traces
//     winston.format.splat(),
//     winston.format.printf(({ timestamp, level, message, stack }) => {
//         return `<span class="math-inline">\{timestamp\} \[</span>{level.toUpperCase()}]: ${stack || message}`;
//     })
// );

// // Define transports (where logs should go)
// const transports = [
//     // Console transport (logs to terminal)
//     new winston.transports.Console({
//         level: logLevel, // Use level from env/default
//         format: winston.format.combine(
//             winston.format.colorize(), // Add colors to console output
//             logFormat
//         ),
//     }),
//     // File transport for errors
//     new winston.transports.File({
//         filename: path.join(logDir, 'error.log'),
//         level: 'error', // Only log errors to this file
//         format: logFormat,
//         maxsize: 5242880, // 5MB
//         maxFiles: 5,
//     }),
//     // File transport for all logs
//     new winston.transports.File({
//         filename: path.join(logDir, 'combined.log'),
//         level: logLevel, // Use level from env/default
//         format: logFormat,
//         maxsize: 5242880, // 5MB
//         maxFiles: 5,
//     }),
// ];

// // Create the logger instance
// const logger = winston.createLogger({
//     level: logLevel, // Set the minimum level to log
//     format: logFormat, // Apply the base format
//     transports: transports,
//     exitOnError: false, // Do not exit on handled exceptions
// });

// // Add a simple stream object for potential use with middleware like morgan
// // logger.stream = {
// //     write: (message: string): void => {
// //         logger.info(message.trim());
// //     },
// // };

// logger.info(`Logger initialized with level: ${logLevel}`);

// export default logger;

const centralizedLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        // winston.format.timestamp(),
        // winston.format.json()
        winston.format.colorize(), // Add colors to console output
        logFormat
    ),
    transports: [new winston.transports.Console()],
});

// if (cluster.isPrimary) {
//     centralizedLogger.add(new winston.transports.File({ filename: 'combined.log' }));
// }

const logger = centralizedLogger; // Assign to your existing logger variable

export default logger;