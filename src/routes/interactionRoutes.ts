import { Router, Request, Response, NextFunction } from 'express';
// Import Provider type if needed for type hints, though often inferred
// import Provider, { InteractionResults, PromptDetail } from 'oidc-provider';
import Account from '../config/account'; // Import your Account class
import oidcProvider from '../config/oidcProvider'; // Import the provider instance
import { ObjectId } from 'mongoose';

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
        const { uid, prompt, params, session, exp } = interactionDetails; // session might contain accountId if logged in
        console.log(`Interaction check for UID: ${uid}, Prompt: ${prompt.name}`);
        // Log session details (if available) to see if user is already logged in at this stage
        if(session) {
            console.log(`Session details: accountId=${session.accountId}, uid=${session.uid}, exp=${exp}`);
        } else {
             console.log('No active session found for this interaction.');
        }


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
                // --- DEBUGGING: Log the details object when consent is prompted ---
                console.log(`Consent prompt details for UID ${uid}:`, JSON.stringify(prompt.details, null, 2));
                // --- End Debugging ---

                // Find account details associated with this interaction
                // Check session first, then prompt details as fallback (though it should be in details)
                const accountId = session?.accountId || prompt.details.accountId;
                if (!accountId) {
                   // If accountId is missing here, the login step likely didn't correctly establish the session/link
                   console.error(`Account ID missing for consent prompt. Session: ${JSON.stringify(session)}, Prompt Details: ${JSON.stringify(prompt.details)}`);
                   return next(new Error('Account ID missing for consent prompt')); // Error reported by user
                }
                console.log(`Account ID found for consent: ${accountId}`);

                const account = await Account.findAccount(undefined, accountId as string); // Find account details
                if (!account) {
                   console.error(`Account object not found for accountId: ${accountId}`);
                   return next(new Error(`Account not found for consent: ${accountId}`));
                }

                // Get the scopes that require user consent
                const missingOidcScopes = prompt.details.missingOIDCScope || ([] as string[]);
                const scopesToDisplay = Array.isArray(missingOidcScopes) ? [...missingOidcScopes] : [];

                console.log(`Scopes requiring consent: ${scopesToDisplay.join(', ')}`);

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
        // Use the MongoDB document ID as accountId
        const accountIdString = (account._id as ObjectId).toString(); // Convert ObjectId to string
        console.log(`Login successful for accountId: ${accountIdString}`);
        const result = {
            login: {
                accountId: accountIdString, // Use the MongoDB document ID as accountId
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
    console.log(`[Interaction /confirm POST] Received consent confirmation for UID: ${req.params.uid}`); // Log entry
    try {
        // Get interaction details
        console.log('[Interaction /confirm POST] Getting interaction details...');
        const interactionDetails = await oidcProvider.interactionDetails(req, res);
        const { prompt: { name, details }, params, session, grantId: existingGrantId } = interactionDetails; // Use existingGrantId alias
        console.log(`[Interaction /confirm POST] Details retrieved. Prompt: ${name}, Has Session: ${!!session}, Has GrantId: ${!!existingGrantId}`);


        // Ensure this interaction is waiting for consent
        if (name !== 'consent') {
           console.error('[Interaction /confirm POST] Error: Interaction prompt is not consent.');
           return next(new Error('Interaction prompt is not consent'));
        }

        // Ensure accountId is present (should be after login)
        const accountId = session?.accountId || details.accountId as string;
        console.log(`[Interaction /confirm POST] Account ID: ${accountId}`);
         if (!accountId) {
             console.error('[Interaction /confirm POST] Error: Account ID missing when trying to confirm consent.');
             return next(new Error('Cannot confirm consent without a logged-in user session.'));
         }
         console.log(`[Interaction /confirm POST] Account ID found: ${accountId}`);


        let grant;

        // Find or create the grant object associated with this interaction
         console.log(`[Interaction /confirm POST] Looking for existing grant with ID: ${existingGrantId}`);
        if (existingGrantId) {
            grant = await oidcProvider.Grant.find(existingGrantId);
             console.log(`[Interaction /confirm POST] Existing grant ${existingGrantId ? 'found' : 'not found'}.`);
        }

        if (!grant) {
             console.log(`[Interaction /confirm POST] Creating new grant for account ${accountId} and client ${params.client_id}`);
            grant = new oidcProvider.Grant({
                accountId: accountId, // Use the confirmed accountId
                clientId: params.client_id as string,
            });
        }

        // Update the grant with the scopes/claims the user consented to
        console.log('[Interaction /confirm POST] Updating grant scopes/claims...');
        if (details.missingOIDCScope) {
             const scopesToAdd = (details.missingOIDCScope as string[]).join(' ');
             console.log(`[Interaction /confirm POST] Adding OIDC Scopes: ${scopesToAdd}`);
             grant.addOIDCScope(scopesToAdd);
        } else {
             console.log('[Interaction /confirm POST] No missing OIDC scopes.');
        }
        // Add similar checks and logging for missingOIDCClaims and missingResourceScopes if used

        // Save the grant to the adapter (e.g., MongoDB)
        console.log('[Interaction /confirm POST] Saving grant...');
        console.log('Grant object before save:', JSON.stringify(grant, null, 2));
        const savedGrantId = await grant.save();
        console.log(`[Interaction /confirm POST] Grant saved successfully. Grant ID: ${savedGrantId}`);


        // Prepare the result for interactionFinished
        const consentResult = { consent: { grantId: savedGrantId } };
        console.log('[Interaction /confirm POST] Calling interactionFinished...');

        // Complete the interaction, associating the grant with the session
        try {
            // ... existing code up to preparing consentResult ...
            console.log('[Interaction /confirm POST] Calling interactionFinished...');
            const finishResult = await oidcProvider.interactionFinished(req, res, consentResult, { mergeWithLastSubmission: false });
            // ADD THIS LOG:
            console.log('[Interaction /confirm POST] interactionFinished resolved with:', finishResult);
            console.log('[Interaction /confirm POST] Provider should now redirect.');
        } catch (err) {
            console.error('[Interaction /confirm POST] Error during or after interactionFinished:', err);
            next(err);
        }
        // await oidcProvider.interactionFinished(req, res, consentResult, { mergeWithLastSubmission: false });
        // console.log('[Interaction /confirm POST] interactionFinished completed. Provider should now redirect.');
        // NOTE: If execution reaches here, the provider *should* handle the redirect.
        // If the browser hangs, check the Network Tab for the response to this POST.

    } catch (err) {
         console.error('[Interaction /confirm POST] Error caught:', err);
        next(err);
    }
});

// Handle Abort Interaction (POST)
router.post('/:uid/abort', setNoCache, async (req: Request, res: Response, next: NextFunction) => {
    try {
        const result = {
            error: 'access_denied',
            error_description: 'End-User aborted interaction',
        };
        await oidcProvider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});


export default router;
