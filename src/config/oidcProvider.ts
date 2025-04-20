import Provider, { Configuration, ClientMetadata } from 'oidc-provider';
import dotenv from 'dotenv';
import path from 'path';
import Account from './account'; // Import the Account class
import adapterFactory from './mongodb.adapter'; // Import the MongoDB adapter factory
import logger from './middlewares/logger';

dotenv.config(); // Load environment variables

const ISSUER_URL = process.env.ISSUER_URL;
const MONGODB_URI = process.env.MONGODB_URI; // Get MongoDB URI for adapter
// Client 1: arademia_front_client
const FRONTEND_URL = process.env.FRONTEND_URL;
const FRONTEND_CALLBACK_URL = FRONTEND_URL ? `${FRONTEND_URL}/auth/callback` : '';
const FRONTEND_LOGOUT_CALLBACK_URL = FRONTEND_URL ? `${FRONTEND_URL}/auth/logout` : '';
// Client 2: arademia_intranet_client
const INTRANET_URL = process.env.INTRANET_URL;
const INTRANET_CALLBACK_URL = INTRANET_URL ? `${INTRANET_URL}/auth/callback` : '';
const INTRANET_CLIENT_ID = process.env.INTRANET_CLIENT_ID || 'arademia_intranet_client';
const INTRANET_CLIENT_SECRET = process.env.INTRANET_CLIENT_SECRET || 'arademia_intranet_secret_change_this';
const INTRANET_LOGOUT_CALLBACK_URL = process.env.INTRANET_LOGOUT_CALLBACK_URL || `${INTRANET_URL}/auth/logout`;
// Client 3: moodle_oidc_client
const MOODLE_CALLBACK_URL = process.env.MOODLE_CALLBACK_URL+'';
const MOODLE_CLIENT_ID = process.env.MOODLE_CLIENT_ID || 'arademia_intranet_client';
const MOODLE_CLIENT_SECRET = process.env.MOODLE_CLIENT_SECRET || 'arademia_intranet_secret_change_this';
const MOODLE_LOGOUT_CALLBACK_URL = process.env.MOODLE_LOGOUT_CALLBACK_URL+''; // Example Moodle logout destination
// --- Environment Variable Validation ---
if (!ISSUER_URL || !MONGODB_URI || !process.env.SESSION_SECRET) {
  logger.error('FATAL ERROR: ISSUER_URL, MONGODB_URI, or SESSION_SECRET environment variable is not set.');
  process.exit(1);
}
if (!FRONTEND_CALLBACK_URL) {
    logger.warn('WARN: FRONTEND_URL environment variable is not set. Redirect URI for arademia_front_client will be empty.');
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
    post_logout_redirect_uris: [FRONTEND_LOGOUT_CALLBACK_URL],
  },
  {
    client_id: INTRANET_CLIENT_ID,
    client_secret: INTRANET_CLIENT_SECRET,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: INTRANET_CALLBACK_URL ? [INTRANET_CALLBACK_URL] : [],
    token_endpoint_auth_method: 'client_secret_post',
    post_logout_redirect_uris: [INTRANET_LOGOUT_CALLBACK_URL],

  },
  {
    client_id: MOODLE_CLIENT_ID,
    client_secret: MOODLE_CLIENT_SECRET,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [MOODLE_CALLBACK_URL],
    token_endpoint_auth_method: 'client_secret_post',
    post_logout_redirect_uris: [MOODLE_LOGOUT_CALLBACK_URL],
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
      profile: ['given_name', 'family_name', 'preferred_username'], // Removed 'name'
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
    resourceIndicators: { enabled: false },
  },
    // --- JWKS Configuration ---
  // REMOVED the jwks property entirely for development.
  // oidc-provider will generate ephemeral keys in memory on startup.
  //
  // IMPORTANT FOR PRODUCTION:
  // You MUST generate stable signing keys (e.g., RSA or EC) and configure them here.
  // Load keys securely (e.g., from environment variables or a key vault).
  // Example structure (DO NOT use these placeholders):
  // jwks: {
  //   keys: [
  //     { /* Your actual private key in JWK format */ }
  //   ],
  // },
  // --- End JWKS Configuration ---
  
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
    // Explicitly support S256 (used by oidc-client-ts)
    // Setting required: true is recommended for better security
    required: (ctx, client) => client.clientId !== MOODLE_CLIENT_ID,
    methods: ['S256'],
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

oidc.use((ctx, next) => {
  console.log('Incoming Request:', ctx.request.method, ctx.request.url);
  console.log('Headers:', ctx.request.headers);
  return next();
});

// Production readiness (proxy handling)
if (process.env.NODE_ENV === 'production') {
    oidc.proxy = true;
}

export default oidc;