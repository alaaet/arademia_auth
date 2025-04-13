import Provider, { Configuration, ClientMetadata } from 'oidc-provider';
import dotenv from 'dotenv';
import path from 'path';
import Account from './account'; // Import the Account class
import adapterFactory from './mongodb.adapter'; // Import the MongoDB adapter factory

dotenv.config(); // Load environment variables

const ISSUER_URL = process.env.ISSUER_URL;
const MONGODB_URI = process.env.MONGODB_URI; // Get MongoDB URI for adapter
const FRONTEND_URL = process.env.FRONTEND_URL;
const FRONTEND_CALLBACK_URL = FRONTEND_URL ? `${FRONTEND_URL}/auth/callback` : undefined;
const MOODLE_CALLBACK_URL = process.env.MOODLE_CALLBACK_URL+'';

// --- Environment Variable Validation ---
if (!ISSUER_URL || !MONGODB_URI || !process.env.SESSION_SECRET) {
  console.error('FATAL ERROR: ISSUER_URL, MONGODB_URI, or SESSION_SECRET environment variable is not set.');
  process.exit(1);
}
if (!FRONTEND_CALLBACK_URL) {
    console.warn('WARN: FRONTEND_URL environment variable is not set. Redirect URI for arademia_front_client will be empty.');
}
// --- End Validation ---

// Define OIDC clients
const clients: ClientMetadata[] = [
  {
    client_id: 'arademia_front_client',
    client_secret: 'arademia_front_secret_change_this',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: FRONTEND_CALLBACK_URL ? [FRONTEND_CALLBACK_URL] : [],
    token_endpoint_auth_method: 'client_secret_post',
  },
  {
    client_id: 'moodle_oidc_client',
    client_secret: 'moodle_oidc_secret_change_this',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: [MOODLE_CALLBACK_URL],
    token_endpoint_auth_method: 'client_secret_post',
  },
];

// --- Configure MongoDB Adapter ---
// The adapter needs to be initialized before the provider configuration
// It expects the MONGODB_URI to be passed or available via process.env
// MongoAdapter.connect(MONGODB_URI); // Connect the adapter to MongoDB
// --- End Adapter Config ---

const configuration: Configuration = {
  // --- Add the adapter configuration ---
  adapter: adapterFactory, // Use the MongoDB adapter factory
  // --- End Adapter Config ---

  clients: clients,
  findAccount: Account.findAccount,
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  claims: {
      openid: ['sub'],
      profile: ['name', 'family_name', 'given_name', 'preferred_username'],
      email: ['email', 'email_verified'],
   },
  features: {
    devInteractions: { enabled: false }, // Keep disabled
    introspection: { enabled: true },
    revocation: { enabled: true },
    userinfo: { enabled: true },
    rpInitiatedLogout: { enabled: true },
    // Enable session management feature for logout etc.
    backchannelLogout: { enabled: true },
  },
  // JWKS configuration (MUST replace with your own keys for production)
  jwks: {
    keys: [
         { "p": "...", "kty": "RSA", "q": "...", "d": "...", "e": "AQAB", "use": "sig", "kid": "dev-key-1", "qi": "...", "dp": "...", "dq": "...", "n": "..." }
    ],
  },
  cookies: {
    keys: process.env.SESSION_SECRET?.split(','),
  },
  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
  issueRefreshToken: async (ctx, client, code) => {
     return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
  },
   pkce: {
     required: () => false,
   },
   // Add TTL configuration for various artifacts (optional but recommended)
   ttl: {
     AccessToken: 60 * 60, // 1 hour
     AuthorizationCode: 10 * 60, // 10 minutes
     Grant: 14 * 24 * 60 * 60, // 14 days
     IdToken: 60 * 60, // 1 hour
     RefreshToken: 14 * 24 * 60 * 60, // 14 days
     Session: 14 * 24 * 60 * 60, // 14 days
     // Add others as needed
   },
};
// (configuration.features as any).sessionManagement = { enabled: true };
const oidc = new Provider(ISSUER_URL, configuration);

// Production readiness (proxy handling)
if (process.env.NODE_ENV === 'production') {
    oidc.proxy = true;
}

export default oidc;