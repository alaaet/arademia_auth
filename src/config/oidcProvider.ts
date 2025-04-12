import Provider, { Configuration, ClientMetadata } from 'oidc-provider'; // Import ClientMetadata type
import dotenv from 'dotenv';
import path from 'path';
import Account from './account'; // Import the Account class

dotenv.config();

const ISSUER_URL = process.env.ISSUER_URL;
// Check if ISSUER_URL is set, exit if not
console.info(`[oidcProvider]: ISSUER_URL: ${ISSUER_URL}`);
const FRONTEND_CALLBACK_URL = process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/auth/callback` : undefined;
console.info(`Frontend callback URL: ${FRONTEND_CALLBACK_URL}`); // Log the frontend callback URL
// Moodle callback URL (if applicable)
const MOODLE_CALLBACK_URL = process.env.MOODLE_CALLBACK_URL || ''; // Replace with actual Moodle callback
console.info(`Moodle callback URL: ${MOODLE_CALLBACK_URL}`); // Log the Moodle callback URL

if (!ISSUER_URL) {
  console.error('FATAL ERROR: ISSUER_URL environment variable is not set.');
  process.exit(1);
}
// Warning if frontend URL isn't set, as client config needs it
if (!FRONTEND_CALLBACK_URL) {
    console.warn('WARN: FRONTEND_URL environment variable is not set, frontend client redirect URI may be incorrect.');
}

// Define OIDC clients (React app, Moodle, Backoffice)
const clients: ClientMetadata[] = [
  {
    client_id: 'arademia_front_client',
    client_secret: 'arademia_front_secret_change_this',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: FRONTEND_CALLBACK_URL ? [FRONTEND_CALLBACK_URL] : [], // Use variable
    token_endpoint_auth_method: 'client_secret_post', // Example
  },
  {
    client_id: 'moodle_oidc_client',
    client_secret: 'moodle_oidc_secret_change_this',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: [MOODLE_CALLBACK_URL],
    token_endpoint_auth_method: 'client_secret_post', // Moodle often uses POST
  },
];

const configuration: Configuration = {
  clients: clients,
  findAccount: Account.findAccount, // Use the imported class method
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  claims: {
      openid: ['sub'],
      profile: ['name', 'family_name', 'given_name', 'preferred_username'],
      email: ['email', 'email_verified'],
   },
  features: {
    devInteractions: { enabled: false }, // <-- Disable dev interactions
    introspection: { enabled: true },
    revocation: { enabled: true },
    userinfo: { enabled: true },
    rpInitiatedLogout: { enabled: true },
  },
  // JWKS configuration (MUST replace with your own keys for production)
  jwks: {
    keys: [
        // Replace with your actual generated keys (RSA or EC)
        // Example structure - DO NOT USE THIS IN PRODUCTION
         {
             "p": "...", "kty": "RSA", "q": "...", "d": "...", "e": "AQAB",
             "use": "sig", "kid": "dev-key-1", "qi": "...", "dp": "...", "dq": "...", "n": "..."
         }
         // You MUST generate your own keys for production
    ],
  },
  cookies: {
    keys: process.env.SESSION_SECRET?.split(','), // Use the session secret (or generate separate keys)
  },
  // interactions URL tells provider where to redirect user for login/consent
  interactions: {
    url(ctx, interaction) {
      // The base URL for interaction views, provider appends /:uid
      return `/interaction/${interaction.uid}`;
    },
  },
  // Function to decide if refresh token should be issued
  issueRefreshToken: async (ctx, client, code) => {
     return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
  },
   // PKCE config
   pkce: {
     required: () => false, // Consider making required for public clients
   },
};

const oidc = new Provider(ISSUER_URL, configuration);

// Production readiness (proxy handling)
if (process.env.NODE_ENV === 'production') {
    oidc.proxy = true;
}

export default oidc;