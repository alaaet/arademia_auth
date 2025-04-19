import { Request, Response, NextFunction } from 'express';
import logger from './logger';

// export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
//     const start = process.hrtime();
//     const { method, originalUrl, headers, body } = req;

//     logger.info(`Request: ${method} ${originalUrl}`, {
//         headers,
//         body,
//     });

//     res.on('finish', () => {
//         const [seconds, nanoseconds] = process.hrtime(start);
//         const duration = (seconds * 1000) + (nanoseconds / 1000000);

//         logger.info(`Request finished: ${method} ${originalUrl}`, {
//             statusCode: res.statusCode,
//             duration,
//         });
//     });

//     next();
// };

export const requestLogger = (req: Request, res: Response, time: number) => {
    const { method, url, ip, body } = req;
    const status = res.statusCode;
    if (status > 499) {
      logger.error({
        message: `method=${method} url=${url} status=${status} duration=${time}ms`,
        labels: { origin: "ARADEMIA_AUTH", url: url },
        request: { ip, body },
      });
    } else if (status > 399) {
      logger.warn({
        message: `method=${method} url=${url} status=${status} duration=${time}ms`,
        labels: { origin: "ARADEMIA_AUTH", url: url },
        request: { ip, body },
      });
    } else {
      logger.info({
        message: `method=${method} url=${url} status=${status} duration=${time}ms`,
        labels: { origin: "ARADEMIA_AUTH", url: url },
        request: { ip, body },
      });
    }
  };

  