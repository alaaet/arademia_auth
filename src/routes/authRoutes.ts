import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { registerUser /*, other controllers */ } from '../controllers/authController'; // Import registerUser
import logger from '../config/middlewares/logger';
// Optional: Import middleware if needed (e.g., ensureAuthenticated for some routes)
// import { ensureAuthenticated } from '../middleware/authMiddleware'; // Create this later if needed

dotenv.config();
const router = express.Router();

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// POST /auth/register
const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) =>
    (req: Request, res: Response, next: NextFunction) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
// Wrap the async registerUser controller with asyncHandler
router.post('/register', asyncHandler(registerUser));

/**
 * GET /auth/status
 * Checks if the user has an active session with this auth server.
 * Returns authentication status and basic user info if logged in.
 * Useful for frontend apps to determine login state on load.
 */
router.get('/status', (req: Request, res: Response) => {
    // req.isAuthenticated() should now be recognized due to type augmentation
    // Use a check to ensure the method exists before calling
    if (req.isAuthenticated && req.isAuthenticated()) {
        // req.user should also be recognized
        logger.info(`[Auth Status]: User is authenticated. User ID: ${req.user?.id}`); // Use optional chaining on user
        res.status(200).json({
            isAuthenticated: true,
            user: req.user // Send back the user info from req.user
        });
    } else {
        logger.info('[Auth Status]: User is not authenticated.');
        res.status(200).json({ isAuthenticated: false, user: null });
    }
});

/**
 * POST /auth/logout
 * Logs the user out by destroying the session and clearing the cookie.
 */
router.post('/logout', (req: Request, res: Response, next: NextFunction) => {
    // req.logout should now be recognized
    if (req.logout) {
         // Explicitly type the 'err' parameter in the callback
         req.logout((err?: Error) => {
             if (err) {
                 logger.error("[Logout Error - req.logout]: ", err);
                 // Pass error to central handler, but still try to destroy session/cookie
                 // return next(err); // Or handle more gracefully
             }
             // Destroy the session regardless of req.logout error (if any)
             req.session.destroy((destroyErr) => {
                 if (destroyErr) {
                     logger.error("[Session Destroy Error]: ", destroyErr);
                     // Potentially send an error response, but clearing cookie is often enough
                     // return next(destroyErr);
                 }
                 // Clear the session cookie on the client side
                 const sessionCookieName = process.env.SESSION_NAME || 'connect.sid';
                 logger.info(`[Logout]: Clearing cookie: ${sessionCookieName}`);
                 res.clearCookie(sessionCookieName);
                 // Send success even if session destroy had minor issues, as logout likely worked
                 res.status(200).json({ message: 'Logout successful' });
             });
         });
    } else {
         // Fallback if req.logout is somehow not available
         logger.warn("[Logout]: req.logout function not found, attempting session destroy only.");
         req.session.destroy((destroyErr) => {
             if (destroyErr) {
                 logger.error("[Session Destroy Error - Fallback]: ", destroyErr);
                 return next(destroyErr);
             }
             const sessionCookieName = process.env.SESSION_NAME || 'connect.sid';
             logger.info(`[Logout]: Clearing cookie (fallback): ${sessionCookieName}`);
             res.clearCookie(sessionCookieName);
             res.status(200).json({ message: 'Logout successful (session destroyed)' });
         });
    }
});

// Optional: Add RP-Initiated Logout endpoint if configured in oidc-provider
// router.get('/logout/callback', (req, res) => { ... handle post-logout redirect ... });


export default router;
