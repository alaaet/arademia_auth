import User, { IUser } from '../models/User'; // Import your User model
import bcrypt from 'bcrypt';
import mongoose from 'mongoose'; // Import mongoose if needed for ObjectId validation
import { AccountClaims } from 'oidc-provider'; // Import AccountClaims type from oidc-provider
import logger from './middlewares/logger';

// Define structure for the user object used by oidc-provider's findAccount
// Add index signature to match the expected Account type from oidc-provider
interface OIDCAccount {
    accountId: string; // Typically the user's _id from MongoDB
    // The claims method needs to return a promise resolving to AccountClaims
    claims: (use: string, scope: string) => Promise<AccountClaims>;
    // Add index signature to allow additional properties expected by oidc-provider's Account type
    [key: string]: any;
}

class Account {
    /**
     * Finds a user account based on the ID (subject claim).
     * Required by oidc-provider.
     * @param ctx - Koa context (or generic context from oidc-provider)
     * @param id - The account identifier (usually MongoDB _id as string)
     */
    static async findAccount(ctx: any, id: string): Promise<OIDCAccount | undefined> {
        try {
            // Validate if the id is a valid MongoDB ObjectId if that's what you use
            if (!mongoose.Types.ObjectId.isValid(id)) {
                 logger.debug(`findAccount: Invalid ID format: ${id}`);
                 return undefined;
            }

            const user:IUser | null = await User.findById(id).lean(); // Use lean() for plain JS object
            if (!user) {
                logger.debug(`findAccount: User not found for id: ${id}`);
                return undefined;
            }
            logger.debug(`findAccount: Found user for id: ${id}`);

            // Return the account object in the format oidc-provider expects
            // This object implicitly matches OIDCAccount interface due to the implementation
            return {
                accountId: id,
                // Ensure the claims method returns a Promise<AccountClaims>
                async claims(use: string, scope: string): Promise<AccountClaims> {
                    // 'use' can be 'id_token' or 'userinfo'
                    // 'scope' is a space-separated string of requested scopes
                    logger.debug(`Claims requested - use: ${use}, scope: ${scope}, accountId: ${id}`);
                    const scopes = scope ? scope.split(' ') : [];

                    // Base claims (always include sub) - initialize with the required type
                    const claims: AccountClaims = { sub: id };

                    // Add claims based on requested scopes
                    // Note: Only add claims that are part of the AccountClaims type definition
                    // or extend the type if necessary for custom claims.
                    if (scopes.includes('profile')) {
                        if (user.firstName) claims.given_name = user.firstName; // Map firstName
                        if (user.lastName) claims.family_name = user.lastName; // Map lastName
                        if (user.username) claims.preferred_username = user.username;
                        
                        // Add other standard profile claims if available in your IUser model
                        // claims.given_name = user.firstName;
                        // claims.family_name = user.lastName;
                        // claims.picture = user.profilePictureUrl;
                    }
                    if (scopes.includes('email')) {
                        if (user.email) claims.email = user.email;
                        // Set email_verified based on your application's logic
                        claims.email_verified = false; // Example: default to false
                    }
                    // Add custom claims here if needed, ensuring they don't conflict
                    // with standard claims expected by AccountClaims type if it's strict.
                    const claimsStr = JSON.stringify(claims, null, 2); // Pretty print for logging  
                    logger.debug(`Returning claims: ${claimsStr}`); // Log the claims);
                    return claims; // Return the object typed as AccountClaims
                },
            };
        } catch (error) {
            logger.error(`Error in findAccount for id ${id}:`, error);
            return undefined;
        }
    }

    /**
     * Authenticates a user based on username and password.
     * Used by your custom login interaction logic.
     * @param username
     * @param password
     * @returns The user object (IUser) if authentication succeeds, null otherwise.
     */
    static async authenticate(username: string, password: string): Promise<IUser | null> {
        try {
            logger.debug(`Attempting authentication for username: ${username}`);
            const user = await User.findOne({ username: username.toLowerCase() });

            if (!user) {
                logger.debug(`Authentication failed: User not found - ${username}`);
                return null; // User not found
            }

            if (!user.password) {
                 logger.debug(`Authentication failed: User has no password set - ${username}`);
                 return null; // User exists but has no password (e.g., created via SSO link?)
            }

            // Compare submitted password with hashed password in DB
            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                logger.debug(`Authentication successful for user: ${username}`);
                return user; // Passwords match
            } else {
                logger.debug(`Authentication failed: Invalid password for user: ${username}`);
                return null; // Passwords don't match
            }
        } catch (error) {
            logger.error(`Error during authentication for ${username}:`, error);
            return null;
        }
    }
}

export default Account;
