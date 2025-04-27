import 'express-session';
import { IUser } from '../models/User';
import { Document } from 'mongoose';

declare module 'express-session' {
  interface SessionData {
    interactionUrl?: string;
  }
}

// Define the structure of the user object attached to req.user
// Adjust this based on what your deserializeUser function actually attaches.
// For now, we assume it might just attach the ID based on the example.
interface AppUser {
    id: string;
    // Add any other properties consistently attached to req.user
    // moodleToken?: string; // Example if storing token here (less common)
  }
  
  // Use declaration merging to add properties to existing Express interfaces
  declare global {
    namespace Express {
      // Augment the Request interface
      // export interface Request {
      //   // Method added by express-session/passport/oidc-provider session handling
      //   isAuthenticated?(): boolean;
  
      //   // Method added by express-session/passport/oidc-provider session handling
      //   logout?(callback: (err?: Error) => void): void;
  
      //   // Property added by express-session/passport/oidc-provider after login
      //   user?: User;
  
      //   // You can also augment req.session here if needed, e.g.:
      //   session: Session & Partial<SessionData> & {
      //     passport?: { user?: any }; // Example if using passport directly
      //     interactionUrl?: string;
      //     originalAuthParams?: {
      //       client_id?: string;
      //       response_type?: string;
      //       scope?: string;
      //       redirect_uri?: string;
      //       state?: string;
      //       nonce?: string;
      //       [key: string]: any;
      //     };
      //   };
      // }
  
      // Optional: If you want Express.User to match your AppUser type
      // export interface User extends AppUser {}

      // export interface Session {
      //   interactionUrl?: string;
      // }

      export interface Session {
        interactionUrl?: string;
        originalAuthParams?: {
          client_id?: string;
          response_type?: string;
          scope?: string;
          redirect_uri?: string;
          state?: string;
          nonce?: string;
          [key: string]: any;
        };
      }

      export interface User extends IUser, Document {}
    }
  }
  
  // Adding this empty export makes the file a module.
  // This is often required for global augmentations to be recognized correctly by TypeScript.
  export {};

// Extend OIDCContext type
declare module 'oidc-provider' {
    interface OIDCContext {
        grant?: {
            grantId: string;
            accountId: string;
            clientId: string;
            scope: string;
        };
    }
}