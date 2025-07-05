/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { OAuth2Client, Credentials } from 'google-auth-library';
import * as http from 'http';
import url from 'url';
import crypto from 'crypto';
import * as net from 'net';
import open from 'open';
import path from 'node:path';
import { promises as fs, existsSync, readFileSync } from 'node:fs'; // Added existsSync, readFileSync
import * as os from 'os';

//  OAuth Client ID used to initiate OAuth2Client class.
const OAUTH_CLIENT_ID =
  '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';

// OAuth Secret value used to initiate OAuth2Client class.
const OAUTH_CLIENT_SECRET = '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';

// OAuth Scopes for Cloud Code authorization.
const OAUTH_SCOPE = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

const HTTP_REDIRECT = 301;
const SIGN_IN_SUCCESS_URL =
  'https://developers.google.com/gemini-code-assist/auth_success_gemini';
const SIGN_IN_FAILURE_URL =
  'https://developers.google.com/gemini-code-assist/auth_failure_gemini';

const GEMINI_DIR = '.gemini';
const CREDENTIAL_FILENAME = 'oauth_creds.json';
const GOOGLE_ACCOUNT_ID_FILENAME = 'google_account_id'; // New

/**
 * Data structure for the headless authentication challenge.
 */
export interface HeadlessAuthChallenge {
  isHeadlessChallenge: true;
  authUrl: string;
  state: string; // CSRF state token
  port: number; // Port allocated for redirectUri
  redirectUri: string; // Full redirect URI
}

/**
 * Indicates successful GUI authentication or that no challenge is needed.
 */
export interface AuthSuccess {
  isHeadlessChallenge: false;
}

/**
 * Union type for the result of the initial phase of web authentication.
 */
export type AuthMode = HeadlessAuthChallenge | AuthSuccess;

/**
 * Custom error to signal that headless authentication flow should be initiated by the UI.
 */
export class HeadlessAuthRequestError extends Error {
  constructor(
    public readonly challenge: HeadlessAuthChallenge,
    public readonly client: OAuth2Client, // The OAuth2Client instance to be used for token exchange
  ) {
    super('Headless authentication required. Please follow the prompts.');
    this.name = 'HeadlessAuthRequestError';
  }
}

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve with AuthMode, indicating
 * whether a headless challenge is needed or GUI auth completed/failed.
 */
export interface OauthWebLogin {
  authUrl: string;
  loginCompletePromise: Promise<AuthMode>;
}

export async function getOauthClient(): Promise<OAuth2Client> {
  const client = new OAuth2Client({
    clientId: OAUTH_CLIENT_ID,
    clientSecret: OAUTH_CLIENT_SECRET,
  });

  // Listen for token updates to cache them and the Google Account ID
  client.on('tokens', async (tokens: Credentials) => {
    await cacheCredentials(tokens); // This was implicitly part of setCredentials before, now explicit
    if (tokens.id_token) { // id_token is usually present on initial auth or if scopes demand it
      try {
        const googleAccountId = await getRawGoogleAccountId(client); // Re-use client, it has new tokens
        if (googleAccountId) {
          await cacheGoogleAccountId(googleAccountId);
        }
      } catch (error) {
        console.error(
          '[oauth2.getOauthClient] Failed to retrieve Google Account ID after token refresh:',
          error,
        );
      }
    }
  });

  if (await loadCachedCredentials(client)) {
    // Found valid cached credentials.
    // Check if we need to retrieve Google Account ID
    if (!getCachedGoogleAccountId()) {
      try {
        const googleAccountId = await getRawGoogleAccountId(client);
        if (googleAccountId) {
          await cacheGoogleAccountId(googleAccountId);
        }
      } catch (error) {
        console.error(
          '[oauth2.getOauthClient] Failed to retrieve Google Account ID for existing credentials:',
          error,
        );
      }
    }
    return client;
  }

  const webLogin = await authWithWeb(client);
  const authMode = await webLogin.loginCompletePromise;
  console.debug('[oauth2.getOauthClient] Received authMode.isHeadlessChallenge =', authMode.isHeadlessChallenge);

  if (authMode.isHeadlessChallenge) {
    console.debug('[oauth2.getOauthClient] Throwing HeadlessAuthRequestError with challenge:', authMode);
    throw new HeadlessAuthRequestError(authMode, client);
  }
  // For GUI success, Google Account ID is now fetched within authWithWeb's server part
  return client;
}

async function authWithWeb(client: OAuth2Client): Promise<OauthWebLogin> {
  const port = await getAvailablePort();
  const redirectUri = `http://localhost:${port}/oauth2callback`;
  const state = crypto.randomBytes(32).toString('hex');
  const authUrlGenerated: string = client.generateAuthUrl({
    redirect_uri: redirectUri,
    access_type: 'offline',
    scope: OAUTH_SCOPE,
    state,
  });

  const loginCompletePromise = new Promise<AuthMode>(async (resolve, reject) => {
    let server: http.Server | undefined;
    let browserOpenedSuccessfullyDetermined = false;

    console.debug('[oauth2.authWithWeb] Checking TTY and attempting to open browser...');
    if (process.stdout.isTTY) {
      console.debug('[oauth2.authWithWeb] stdout is a TTY, attempting open().');
      let openedFine = false;
      try {
        await open(authUrlGenerated);
        openedFine = true;
        console.debug('[oauth2.authWithWeb] open() call did not throw.');
      } catch (error) {
        console.debug('[oauth2.authWithWeb] open() call failed. Error:', (error as Error).message);
      }

      if (openedFine) {
        const termProgram = process.env.TERM_PROGRAM;
        const platform = os.platform();
        const isLikelyGuiTTY =
          termProgram === 'vscode' ||
          termProgram === 'Apple_Terminal' ||
          termProgram === 'WindowsTerminal' ||
          platform === 'win32' ||
          (platform === 'darwin' && !process.env.SSH_CONNECTION && !process.env.SSH_TTY);

        console.debug(
          '[oauth2.authWithWeb] open() succeeded. isLikelyGuiTTY:', isLikelyGuiTTY,
          'TERM_PROGRAM:', termProgram,
          'platform:', platform,
          'SSH_CONNECTION:', process.env.SSH_CONNECTION,
          'SSH_TTY:', process.env.SSH_TTY
        );
        browserOpenedSuccessfullyDetermined = openedFine && isLikelyGuiTTY;
      } else {
        browserOpenedSuccessfullyDetermined = false;
      }
    } else {
      console.debug('[oauth2.authWithWeb] stdout is not a TTY, assuming headless.');
      browserOpenedSuccessfullyDetermined = false;
    }

    console.debug('[oauth2.authWithWeb] Final browserOpenedSuccessfullyDetermined:', browserOpenedSuccessfullyDetermined);
    if (browserOpenedSuccessfullyDetermined) {
      console.debug('[oauth2.authWithWeb] Proceeding with GUI flow (starting HTTP server).');
      server = http.createServer(async (req, res) => {
        try {
          if (!req.url || req.url.indexOf('/oauth2callback') === -1) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
            return;
          }

          const qs = new url.URL(req.url, redirectUri).searchParams;
          const code = qs.get('code');
          const receivedState = qs.get('state');

          if (qs.get('error')) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
            reject(new Error(`Error during authentication: ${qs.get('error')}`));
            return;
          }

          if (receivedState !== state) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end('State mismatch. Possible CSRF attack.');
            reject(new Error('State mismatch. Possible CSRF attack.'));
            return;
          }

          if (code) {
            const { tokens } = await client.getToken({ code, redirect_uri: redirectUri });
            client.setCredentials(tokens); // This will trigger the 'tokens' event for caching
            // No need to call cacheCredentials here due to the event listener.
            // Fetch and cache Google Account ID
            try {
              const googleAccountId = await getRawGoogleAccountId(client);
              if (googleAccountId) {
                await cacheGoogleAccountId(googleAccountId);
              }
            } catch (error) {
              console.error('[oauth2.authWithWeb] Failed to retrieve Google Account ID during GUI authentication:', error);
            }

            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_SUCCESS_URL });
            res.end('Authentication successful! You can close this window.');
            resolve({ isHeadlessChallenge: false });
          } else {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end('No authorization code received.');
            reject(new Error('No authorization code received in callback.'));
          }
        } catch (e) {
          if (!res.headersSent) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end(`Authentication failed: ${(e as Error).message}.`);
          }
          reject(e);
        } finally {
          server?.close();
        }
      });
      server.on('error', (e) => reject(new Error(`Local callback server error: ${e.message}`)));
      server.listen(port);
    } else {
      const challenge: HeadlessAuthChallenge = {
        isHeadlessChallenge: true,
        authUrl: authUrlGenerated,
        state,
        port,
        redirectUri,
      };
      console.debug('[oauth2.authWithWeb] Proceeding with Headless flow. Resolving with HeadlessAuthChallenge:', challenge);
      resolve(challenge);
    }
  });

  return {
    authUrl: authUrlGenerated,
    loginCompletePromise,
  };
}

export async function completeHeadlessAuthProcess(
  client: OAuth2Client,
  pastedCallbackUrl: string,
  expectedState: string,
  redirectUri: string,
): Promise<void> {
  try {
    const callbackUrl = new URL(pastedCallbackUrl);
    const code = callbackUrl.searchParams.get('code');
    const receivedState = callbackUrl.searchParams.get('state');

    if (receivedState !== expectedState) {
      throw new Error('State mismatch from pasted URL. Possible CSRF attack.');
    }
    if (!code) {
      throw new Error('No authorization code found in the pasted URL.');
    }

    const { tokens } = await client.getToken({
      code,
      redirect_uri: redirectUri,
    });
    client.setCredentials(tokens); // This will trigger the 'tokens' event for caching
    // Fetch and cache Google Account ID
    try {
      const googleAccountId = await getRawGoogleAccountId(client);
      if (googleAccountId) {
        await cacheGoogleAccountId(googleAccountId);
      }
    } catch (error) {
      console.error('[oauth2.completeHeadlessAuthProcess] Failed to retrieve Google Account ID during headless authentication:', error);
    }
  } catch (error) {
    throw new Error(`Failed to complete headless authentication: ${(error as Error).message}`);
  }
}

export async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    let port = 0;
    try {
      const server = net.createServer();
      server.listen(0, () => {
        const address = server.address()! as net.AddressInfo;
        port = address.port;
      });
      server.on('listening', () => {
        server.close();
        server.unref();
      });
      server.on('error', (e) => reject(e));
      server.on('close', () => resolve(port));
    } catch (e) {
      reject(e);
    }
  });
}

async function loadCachedCredentials(client: OAuth2Client): Promise<boolean> {
  try {
    const keyFile = getCachedCredentialPath(); // Removed GOOGLE_APPLICATION_CREDENTIALS check, assume CLI managed only
    if (!existsSync(keyFile)) return false;

    const creds = await fs.readFile(keyFile, 'utf-8');
    const parsedCreds = JSON.parse(creds);
    client.setCredentials(parsedCreds); // This will trigger 'tokens' event if tokens are set

    // Verify tokens
    const { token } = await client.getAccessToken(); // This might refresh if expired
    if (!token) {
      console.debug('[oauth2.loadCachedCredentials] No access token found after loading credentials.');
      return false;
    }
    await client.getTokenInfo(token); // Validate token with server
    console.debug('[oauth2.loadCachedCredentials] Cached credentials loaded and validated successfully.');
    return true;
  } catch (error) {
    console.debug('[oauth2.loadCachedCredentials] Failed to load or validate cached credentials:', (error as Error).message);
    await clearCachedCredentialFile(); // Clear potentially corrupt/expired credentials
    return false;
  }
}

async function cacheCredentials(credentials: Credentials) {
  const filePath = getCachedCredentialPath();
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    const credString = JSON.stringify(credentials, null, 2);
    await fs.writeFile(filePath, credString);
    console.debug('[oauth2.cacheCredentials] Credentials cached successfully to:', filePath);
  } catch (error) {
    console.error('[oauth2.cacheCredentials] Error caching credentials:', error);
  }
}

function getCachedCredentialPath(): string {
  return path.join(os.homedir(), GEMINI_DIR, CREDENTIAL_FILENAME);
}

function getGoogleAccountIdCachePath(): string {
  return path.join(os.homedir(), GEMINI_DIR, GOOGLE_ACCOUNT_ID_FILENAME);
}

async function cacheGoogleAccountId(googleAccountId: string): Promise<void> {
  const filePath = getGoogleAccountIdCachePath();
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, googleAccountId, 'utf-8');
    console.debug('[oauth2.cacheGoogleAccountId] Google Account ID cached to:', filePath);
  } catch (error) {
    console.error('[oauth2.cacheGoogleAccountId] Error caching Google Account ID:', error);
  }
}

export function getCachedGoogleAccountId(): string | null {
  try {
    const filePath = getGoogleAccountIdCachePath();
    if (existsSync(filePath)) {
      const id = readFileSync(filePath, 'utf-8').trim();
      console.debug('[oauth2.getCachedGoogleAccountId] Found cached Google Account ID:', id ? id : 'empty_file');
      return id || null;
    }
    console.debug('[oauth2.getCachedGoogleAccountId] No cached Google Account ID file found.');
    return null;
  } catch (error) {
    console.debug('[oauth2.getCachedGoogleAccountId] Error reading cached Google Account ID:', error);
    return null;
  }
}

export async function clearCachedCredentialFile() {
  try {
    const credPath = getCachedCredentialPath();
    const idPath = getGoogleAccountIdCachePath();
    if (existsSync(credPath)) await fs.rm(credPath, { force: true });
    if (existsSync(idPath)) await fs.rm(idPath, { force: true });
    console.debug('[oauth2.clearCachedCredentialFile] Cleared cached credentials and Google Account ID.');
  } catch (error) {
    console.debug('[oauth2.clearCachedCredentialFile] Error clearing cached files:', error);
  }
}

export async function getRawGoogleAccountId(
  client: OAuth2Client,
): Promise<string | null> {
  console.debug('[oauth2.getRawGoogleAccountId] Attempting to retrieve Google Account ID.');
  try {
    let idToken = client.credentials.id_token;

    // If no id_token, or if it might be expired (though verifyIdToken handles actual expiry), try refreshing.
    // A more direct check for id_token presence is better than trying to decode it prematurely.
    if (!idToken) {
        console.debug('[oauth2.getRawGoogleAccountId] No initial id_token found on client credentials, attempting to refresh tokens.');
        // The 'tokens' event on the client (setup in getOauthClient) should handle caching
        // the new credentials, including a new id_token if provided by the refresh.
        const refreshedCredentials = await client.refreshAccessToken();

        if (!refreshedCredentials.credentials.id_token) {
            console.warn('[oauth2.getRawGoogleAccountId] No id_token obtained after refreshing tokens.');
            return null;
        }
        idToken = refreshedCredentials.credentials.id_token;
        // Note: client.credentials should be automatically updated by refreshAccessToken call.
        // The 'tokens' event listener will also fire and attempt to cache.
    } else {
        console.debug('[oauth2.getRawGoogleAccountId] Found existing id_token on client credentials.');
    }

    console.debug('[oauth2.getRawGoogleAccountId] Verifying ID token.');
    const ticket = await client.verifyIdToken({
      idToken: idToken, // idToken is now guaranteed to be string or this path isn't taken
      audience: OAUTH_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload?.sub) {
      console.warn('[oauth2.getRawGoogleAccountId] Could not extract sub (Google Account ID) from verified ID token payload.');
      return null;
    }
    console.debug('[oauth2.getRawGoogleAccountId] Successfully retrieved Google Account ID (sub):', payload.sub);
    return payload.sub;
  } catch (error) {
    console.error('[oauth2.getRawGoogleAccountId] Error retrieving or verifying Google Account ID:', (error as Error).message);
    return null;
  }
}
