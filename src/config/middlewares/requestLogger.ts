import { Request, Response, NextFunction } from 'express';
import logger from './logger';

export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    const start = process.hrtime();
    const { method, originalUrl, headers, body } = req;
    const { statusCode } = res;

    res.on('finish', () => {
        const [seconds, nanoseconds] = process.hrtime(start);
        const duration = (seconds * 1000) + (nanoseconds / 1000000);

        logger.info(`Request: ${method} ${originalUrl}`, {
            headers,
            body,
            statusCode,
            duration,
        });
    });

    next();
};
