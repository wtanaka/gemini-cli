/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useCallback, useEffect } from 'react';
import { LoadedSettings, SettingScope } from '../../config/settings.js';
import {
  AuthType,
  Config,
  clearCachedCredentialFile,
  getErrorMessage,
  HeadlessAuthRequestError,
  HeadlessAuthChallenge,
  completeHeadlessAuthProcess,
  // OAuth2Client was incorrectly imported from core
} from '@google/gemini-cli-core';
import { OAuth2Client } from 'google-auth-library';
import { HistoryItemWithoutId, MessageType } from '../types.js';

// Renamed original performAuthFlow to avoid conflict, and to modify its behavior
async function performActualAuth(
  authMethod: AuthType,
  config: Config,
  setHeadlessChallenge: (challenge: HeadlessAuthChallenge | null) => void,
  setHeadlessClient: (client: OAuth2Client | null) => void,
  setIsHeadlessPrompt: (visible: boolean) => void,
  setIsAuthDialogCurrentlyOpen: (isOpen: boolean) => void,
  addItem: (item: HistoryItemWithoutId, timestamp: number) => void,
) {
  console.debug('[useAuthCommand.performActualAuth] Attempting authentication for method:', authMethod);
  try {
    await config.refreshAuth(authMethod);
    // If refreshAuth completes without throwing HeadlessAuthRequestError,
    // it means GUI auth succeeded or other auth types (API key) are fine.
    addItem(
      { type: MessageType.INFO, text: `Successfully authenticated via ${authMethod}.` },
      Date.now()
    );
    setIsHeadlessPrompt(false); // Ensure headless prompt is not visible
    setHeadlessChallenge(null);
    setHeadlessClient(null);
    return true; // Indicate success
  } catch (err) {
    if (err instanceof HeadlessAuthRequestError) {
      console.debug('[useAuthCommand.performActualAuth] Caught HeadlessAuthRequestError. Challenge:', err.challenge, 'Client:', err.client ? 'present' : 'missing');
      setHeadlessChallenge(err.challenge);
      setHeadlessClient(err.client);
      setIsHeadlessPrompt(true);
      console.debug('[useAuthCommand.performActualAuth] Setting isHeadlessPromptVisible = true, hiding AuthDialog.');
      setIsAuthDialogCurrentlyOpen(false); // Close main auth dialog to show headless prompt
      // Don't log "Authenticated via..." yet. Don't throw here, let UI handle prompt.
      return false; // Indicate headless challenge
    }
    // For other errors, rethrow to be caught by calling useEffect
    console.debug('[useAuthCommand.performActualAuth] Caught other error during refreshAuth:', (err as Error).message);
    throw err;
  }
}

export const useAuthCommand = (
  settings: LoadedSettings,
  setAppAuthError: (error: string | null) => void, // Renamed to avoid conflict with local error states
  config: Config,
  addItem: (item: HistoryItemWithoutId, timestamp: number) => void,
) => {
  // Initial state for AuthDialog: open if no auth type is selected.
  const [isAuthDialogOpen, setIsAuthDialogOpen] = useState(
    settings.merged.selectedAuthType === undefined,
  );
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  // State for headless flow
  const [headlessAuthChallenge, setHeadlessAuthChallenge] =
    useState<HeadlessAuthChallenge | null>(null);
  const [headlessOAuthClient, setHeadlessOAuthClient] =
    useState<OAuth2Client | null>(null);
  const [isHeadlessPromptVisible, setIsHeadlessPromptVisible] = useState(false);
  const [headlessAuthPromptError, setHeadlessAuthPromptError] = useState<
    string | undefined
  >(undefined);

  const openAuthDialog = useCallback(() => {
    setIsHeadlessPromptVisible(false); // Ensure headless is hidden
    setHeadlessAuthChallenge(null);
    setHeadlessOAuthClient(null);
    setIsAuthDialogOpen(true);
  }, []);

  // This useEffect attempts auto-authentication if an auth type is already set
  useEffect(() => {
    const authFlow = async () => {
      if (isAuthDialogOpen || isHeadlessPromptVisible || !settings.merged.selectedAuthType) {
        // Don't auto-auth if a dialog is already open/pending, or no auth type set
        return;
      }

      setIsAuthenticating(true);
      setAppAuthError(null);
      try {
        await performActualAuth(
          settings.merged.selectedAuthType as AuthType,
          config,
          setHeadlessAuthChallenge,
          setHeadlessOAuthClient,
          setIsHeadlessPromptVisible,
          setIsAuthDialogOpen, // Pass this to allow performActualAuth to close main dialog
           addItem,
        );
        // If performActualAuth led to headless, isHeadlessPromptVisible will be true.
         // If it succeeded directly, addItem call happened there.
      } catch (e) {
        // This catches errors other than HeadlessAuthRequestError from performActualAuth
        setAppAuthError(`Failed to login: ${getErrorMessage(e)}`);
        openAuthDialog(); // Open dialog to allow user to fix/change method
      } finally {
        setIsAuthenticating(false);
      }
    };

    void authFlow();
  }, [
    isAuthDialogOpen,
    isHeadlessPromptVisible, // Depend on this to prevent re-triggering
    settings.merged.selectedAuthType,
    config,
    setAppAuthError,
    openAuthDialog,
    addItem,
  ]);

  const handleAuthSelect = useCallback(
    async (authMethodStr: string | undefined, scope: SettingScope) => {
      const authMethod = authMethodStr as AuthType | undefined;
      setAppAuthError(null); // Clear previous errors
      setIsHeadlessPromptVisible(false); // Hide headless if it was somehow visible

      if (authMethod) {
        await clearCachedCredentialFile(); // Clear old creds before trying new/same method via dialog
        settings.setValue(scope, 'selectedAuthType', authMethod); // Tentatively set

        setIsAuthenticating(true);
        try {
          const authResult = await performActualAuth(
            authMethod,
            config,
            setHeadlessAuthChallenge,
            setHeadlessOAuthClient,
            setIsHeadlessPromptVisible,
            setIsAuthDialogOpen, // Pass this to allow performActualAuth to close main dialog
             addItem,
          );

          if (authResult) { // True means non-headless success
            setIsAuthDialogOpen(false); // Close dialog on direct success
          }
          // If authResult is false, it means headless flow was initiated,
          // and performActualAuth already handled setting setIsHeadlessPromptVisible=true
          // and setIsAuthDialogOpen=false.
        } catch (e) {
          // Catches non-headless errors from performActualAuth
          setAppAuthError(
            `Authentication failed for ${authMethod}: ${getErrorMessage(e)}`,
          );
          // Keep AuthDialog open by not calling setIsAuthDialogOpen(false)
        } finally {
          setIsAuthenticating(false);
        }
      } else {
        // Auth method cleared
        settings.setValue(scope, 'selectedAuthType', undefined);
        setIsAuthDialogOpen(false); // Close if "None" is selected
      }
    },
    [settings, config, setAppAuthError, addItem],
  );

  const submitHeadlessUrl = useCallback(
    async (pastedUrl: string) => {
      if (!headlessAuthChallenge || !headlessOAuthClient) {
        setHeadlessAuthPromptError('Internal error: Auth challenge details missing. Please cancel and retry.');
        return;
      }
      setHeadlessAuthPromptError(undefined);
      setIsAuthenticating(true); // Indicate activity

      try {
        await completeHeadlessAuthProcess(
          headlessOAuthClient,
          pastedUrl,
          headlessAuthChallenge.state,
          headlessAuthChallenge.redirectUri,
        );
        // Headless auth successful!
         settings.setValue(SettingScope.User, 'selectedAuthType', AuthType.LOGIN_WITH_GOOGLE); // Confirm GCA
         addItem(
           { type: MessageType.INFO, text: `Successfully authenticated via Google (headless flow).` },
           Date.now()
         );

        setIsHeadlessPromptVisible(false);
        setHeadlessAuthChallenge(null);
        setHeadlessOAuthClient(null);
        setIsAuthDialogOpen(false); // Ensure main dialog is also closed
        setAppAuthError(null);
      } catch (err) {
        const rawErrorMessage = getErrorMessage(err);
        if (rawErrorMessage.includes('State mismatch')) {
          setHeadlessAuthPromptError('Authentication failed: Invalid session data. Please cancel (Esc) and try authenticating again.');
        } else if (rawErrorMessage.includes('No authorization code found')) {
          setHeadlessAuthPromptError('No authorization code found in the pasted URL. Please ensure you copied the full URL (it should start with http://localhost) and try again.');
        } else if (rawErrorMessage.includes('invalid_grant')) {
          setHeadlessAuthPromptError('Authentication failed: The authorization code is invalid or has expired. Please cancel (Esc) and try authenticating again.');
        } else {
          setHeadlessAuthPromptError(`Authentication error: ${rawErrorMessage}. Please try again or contact support if this persists.`);
        }
      } finally {
        setIsAuthenticating(false);
      }
    },
     [headlessAuthChallenge, headlessOAuthClient, settings, config, setAppAuthError, addItem],
  );

  const cancelHeadlessPrompt = useCallback(() => {
    setIsHeadlessPromptVisible(false);
    setHeadlessAuthChallenge(null);
    setHeadlessOAuthClient(null);
    setHeadlessAuthPromptError(undefined);
    setIsAuthenticating(false);
    openAuthDialog(); // Re-open main selection dialog
  }, [openAuthDialog]);

  const handleAuthHighlight = useCallback((_authMethod: string | undefined) => {
    // For now, we don't do anything on highlight.
  }, []);

  const cancelAuthentication = useCallback(() => {
    // Generic cancel, could be for GUI or if user closes main auth dialog
    setIsAuthenticating(false);
    // If headless prompt is active, specific cancelHeadlessPrompt should be used by its UI.
    // This primarily stops the `isAuthenticating` flag.
  }, []);

  return {
    isAuthDialogOpen,
    openAuthDialog,
    handleAuthSelect,
    handleAuthHighlight,
    isAuthenticating, // General flag for spinner in AuthDialog or App
    cancelAuthentication,

    // Headless flow specific
    isHeadlessPromptVisible,
    headlessAuthChallenge,
    headlessAuthPromptError,
    submitHeadlessUrl,
    cancelHeadlessPrompt,
  };
};
