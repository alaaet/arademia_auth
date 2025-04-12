import { Router, Request, Response, NextFunction } from 'express';
// Import Provider type if needed for type hints, though often inferred
// import Provider, { InteractionResults, PromptDetail } from 'oidc-provider';
import Account from '../config/account'; // Import your Account class
import oidcProvider from '../config/oidcProvider'; // Import the provider instance

const router = Router();

// Helper to set secure headers for interaction views
const setNoCache = (req: Request, res: Response, next: NextFunction) => {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
};

// Main interaction route (handles GET requests)
router.get('/:uid', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Get interaction details from the provider
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        // Destructure known properties
        const { uid, prompt, params, session } = interactionDetails;
        console.log(`Interaction check for UID: ${uid}, Prompt: ${prompt.name}`);

        // Load client metadata using the client_id from params
        const client = await oidcProvider.Client.find(params.client_id as string);

        // Validate client
        if (!client) {
            console.error(`Interaction client not found for client_id: ${params.client_id} (UID: ${uid})`);
            return next(new Error(`Client not found for client_id: ${params.client_id}`));
        }

        // Handle different interaction prompts (login, consent)
        switch (prompt.name) {
            case 'login': {
                // Render the login form view
                return res.render('login', {
                    uid,
                    client, // Pass the loaded client metadata
                    params,
                    title: 'Sign-in',
                    flash: undefined, // Placeholder for error messages
                });
            }
            case 'consent': {
                // Find account details associated with this interaction
                const accountId = prompt.details.accountId as string; // Get accountId from prompt details
                if (!accountId) {
                   return next(new Error('Account ID missing for consent prompt'));
                }
                const account = await Account.findAccount(undefined, accountId); // Find account details
                if (!account) {
                   return next(new Error(`Account not found for consent: ${accountId}`));
                }

                // Get the scopes that require user consent
                // Use missingOIDCScope and potentially missingResourceScopes
                const missingOidcScopes = prompt.details.missingOIDCScope || [];
                // Combine with resource scopes if needed, for simplicity just use OIDC scopes here
                const scopesToDisplay = Array.isArray(missingOidcScopes) ? [...missingOidcScopes] : []; // Ensure it's an array or default to empty

                // Render the consent form view
                return res.render('consent', {
                    uid,
                    client, // Pass loaded client metadata
                    params,
                    title: 'Authorize',
                    accountId: accountId,
                    account: account, // Pass account details if needed for display
                    scopes: scopesToDisplay, // Pass the array of scopes needing consent
                });
            }
            default:
                // Handle unknown prompt types
                return next(new Error(`Unknown prompt type: ${prompt.name}`));
        }
    } catch (err) {
        // Pass any errors to the central error handler
        return next(err);
    }
});

// Handle Login Form Submission (POST)
router.post('/:uid/login', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Get interaction details again
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        const { uid, prompt, params } = interactionDetails;

        // Ensure this interaction is indeed waiting for login
        if (prompt.name !== 'login') {
           return next(new Error('Interaction prompt is not login'));
        }

        // Reload client for safety/context if needed, or trust details from GET
        const client = await oidcProvider.Client.find(params.client_id as string);
         if (!client) {
           return next(new Error(`Client not found for client_id: ${params.client_id}`));
         }

        // Get username/password submitted by the user
        const { username, password } = req.body;

        // Authenticate the user using your Account logic
        const account = await Account.authenticate(username, password);

        // If authentication fails
        if (!account) {
            // Re-render the login form with an error message
            return res.render('login', {
                uid,
                client,
                params,
                title: 'Sign-in',
                flash: 'Invalid username or password', // Error message
            });
        }

        // If authentication succeeds, prepare the result for interactionFinished
        const result = {
            login: {
                accountId: (account as { _id: { toString: () => string } })._id.toString(), // Use the MongoDB document ID as accountId
                // acr: 'urn:mace:incommon:iap:silver', // Optional: Authentication Context Class Reference
                // amr: ['pwd'], // Optional: Authentication Methods References
                // remember: !!req.body.remember, // Optional: Implement "remember me" logic
                // ts: Math.floor(Date.now() / 1000), // Optional: Timestamp of login
            },
        };

        // Complete the interaction, logging the user in within the OIDC provider session
        await oidcProvider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });

    } catch (err) {
        next(err); // Pass errors to central handler
    }
});

// Handle Consent Form Submission (POST)
router.post('/:uid/confirm', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Get interaction details
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        // Destructure details needed
        const { prompt: { name, details }, params, session } = interactionDetails;

        // Ensure this interaction is waiting for consent
        if (name !== 'consent') {
           return next(new Error('Interaction prompt is not consent'));
        }

        let { grantId } = interactionDetails;
        let grant;

        // Find or create the grant object associated with this interaction
        if (grantId) {
            // Load existing grant (if resuming interaction)
            grant = await oidcProvider.Grant.find(grantId);
        } else {
            // Create new grant if first time consenting
            grant = new oidcProvider.Grant({
                accountId: details.accountId as string, // Use the accountId from the interaction details
                clientId: params.client_id as string,
            });
        }

        if (!grant) {
            return next(new Error('Grant could not be found or created.'));
        }

        // Update the grant with the scopes/claims the user consented to
        // In this basic example, we assume user consents to all requested scopes/claims
        if (details.missingOIDCScope) {
             // Grant expects space-separated string of scopes
             grant.addOIDCScope((details.missingOIDCScope as string[]).join(' '));
        }
        if (details.missingOIDCClaims) {
             grant.addOIDCClaims(details.missingOIDCClaims as string[]);
        }
        if (details.missingResourceScopes) {
             // Grant expects space-separated string of scopes per resource indicator
             for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
                 grant.addResourceScope(indicator, (scopes as string[]).join(' '));
             }
        }

        // Save the grant to the adapter (e.g., MongoDB)
        grantId = await grant.save();

        // Prepare the result for interactionFinished
        const consentResult = {
             consent: {
                 grantId: grantId, // Pass the grant ID
                 // rejectedScopes: [], // If implementing selective consent, list rejected scopes here
                 // rejectedClaims: [], // If implementing selective consent, list rejected claims here
             }
         };
        // Complete the interaction, associating the grant with the session
        await oidcProvider.interactionFinished(req, res, consentResult, { mergeWithLastSubmission: true });

    } catch (err) {
        next(err);
    }
});

// Handle Abort Interaction (POST)
router.post('/:uid/abort', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Prepare the result indicating user aborted
        const result = {
            error: 'access_denied',
            error_description: 'End-User aborted interaction',
        };
        // Complete the interaction with the error result
        await oidcProvider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});


export default router;