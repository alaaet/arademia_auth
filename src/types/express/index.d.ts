// Import session types if you need to augment req.session as well
// import 'express-session';

// Define the structure of the user object attached to req.user
// Adjust this based on what your deserializeUser function actually attaches.
// For now, we assume it might just attach the ID based on the example.
interface AppUser {
    id: number | string; // Or the specific type of your user ID
    // Add any other properties consistently attached to req.user
    // moodleToken?: string; // Example if storing token here (less common)
  }
  
  // Use declaration merging to add properties to existing Express interfaces
  declare global {
    namespace Express {
      // Augment the Request interface
      export interface Request {
        // Method added by express-session/passport/oidc-provider session handling
        isAuthenticated?(): boolean;
  
        // Method added by express-session/passport/oidc-provider session handling
        logout?(callback: (err?: Error) => void): void;
  
        // Property added by express-session/passport/oidc-provider after login
        user?: AppUser;
  
        // You can also augment req.session here if needed, e.g.:
        // session: Session & Partial<SessionData> & {
        //   passport?: { user?: any }; // Example if using passport directly
        // };
      }
  
      // Optional: If you want Express.User to match your AppUser type
      // export interface User extends AppUser {}
    }
  }
  
  // Adding this empty export makes the file a module.
  // This is often required for global augmentations to be recognized correctly by TypeScript.
  export {};