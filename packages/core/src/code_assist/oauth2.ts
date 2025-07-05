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
import { promises as fs } from 'node:fs';
import * as os from 'os';
import isInteractive from 'is-interactive';
import { printNonInteractiveMessage } from '@google/gemini-cli-cli/src/utils/printNonInteractiveMessage.js';
import { Text } from 'ink';
import React from 'react';
import isInteractive from 'is-interactive';

//  OAuth Client ID used to initiate OAuth2Client class.
const OAUTH_CLIENT_ID =
  '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';

// OAuth Secret value used to initiate OAuth2Client class.
// Note: It's ok to save this in git because this is an installed application
// as described here: https://developers.google.com/identity/protocols/oauth2#installed
// "The process results in a client ID and, in some cases, a client secret,
// which you embed in the source code of your application. (In this context,
// the client secret is obviously not treated as a secret.)"
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

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve when the credentials have
 * been refreshed (or which throws error when refreshing credentials failed).
 */
export interface OauthWebLogin {
  authUrl: string;
  loginCompletePromise: Promise<void>;
}

export async function getOauthClient(): Promise<OAuth2Client> {
  const client = new OAuth2Client({
    clientId: OAUTH_CLIENT_ID,
    clientSecret: OAUTH_CLIENT_SECRET,
  });

  if (await loadCachedCredentials(client)) {
    // Found valid cached credentials.
    return client;
  }

  const webLogin = await authWithWeb(client);

  if (isInteractive()) {
    console.log(
      `

Code Assist login required.
` +
        `Attempting to open authentication page in your browser.
` +
        `If that does not work, navigate to:

${webLogin.authUrl}

`,
    );
    await open(webLogin.authUrl);
  } else {
    printNonInteractiveMessage(
      <Text>
        {'

Code Assist login required.
' +
          'Please open the following URL in your browser to authenticate:

' +
          webLogin.authUrl +
          '

'}
      </Text>,
    );
  }
  printNonInteractiveMessage(<Text>Waiting for authentication...</Text>);

  await webLogin.loginCompletePromise;

  return client;
}

async function authWithWeb(client: OAuth2Client): Promise<OauthWebLogin> {
  const port = await getAvailablePort();
  const redirectUri = `http://localhost:${port}/oauth2callback`;
  const state = crypto.randomBytes(32).toString('hex');
  const authUrl: string = client.generateAuthUrl({
    redirect_uri: redirectUri,
    access_type: 'offline',
    scope: OAUTH_SCOPE,
    state,
  });

  const loginCompletePromise = new Promise<void>((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      try {
        if (req.url!.indexOf('/oauth2callback') === -1) {
          res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
          res.end();
          reject(new Error('Unexpected request: ' + req.url));
        }
        // acquire the code from the querystring, and close the web server.
        const qs = new url.URL(req.url!, 'http://localhost:3000').searchParams;
        if (qs.get('error')) {
          res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
          res.end();

          reject(new Error(`Error during authentication: ${qs.get('error')}`));
        } else if (qs.get('state') !== state) {
          res.end('State mismatch. Possible CSRF attack');

          reject(new Error('State mismatch. Possible CSRF attack'));
        } else if (qs.get('code')) {
          const { tokens } = await client.getToken({
            code: qs.get('code')!,
            redirect_uri: redirectUri,
          });
          client.setCredentials(tokens);
          await cacheCredentials(client.credentials);

          res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_SUCCESS_URL });
          res.end();
          resolve();
        } else {
          reject(new Error('No code found in request'));
        }
      } catch (e) {
        reject(e);
      } finally {
        server.close();
      }
    });
    server.listen(port);
  });

  return {
    authUrl,
    loginCompletePromise,
  };
}

export function getAvailablePort(): Promise<number> {
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
    const keyFile =
      process.env.GOOGLE_APPLICATION_CREDENTIALS || getCachedCredentialPath();

    const creds = await fs.readFile(keyFile, 'utf-8');
    client.setCredentials(JSON.parse(creds));

    // This will verify locally that the credentials look good.
    const { token } = await client.getAccessToken();
    if (!token) {
      return false;
    }

    // This will check with the server to see if it hasn't been revoked.
    await client.getTokenInfo(token);

    return true;
  } catch (_) {
    return false;
  }
}

async function cacheCredentials(credentials: Credentials) {
  const filePath = getCachedCredentialPath();
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  const credString = JSON.stringify(credentials, null, 2);
  await fs.writeFile(filePath, credString);
}

function getCachedCredentialPath(): string {
  return path.join(os.homedir(), GEMINI_DIR, CREDENTIAL_FILENAME);
}

export async function clearCachedCredentialFile() {
  try {
    await fs.rm(getCachedCredentialPath());
  } catch (_) {
    /* empty */
  }
}
