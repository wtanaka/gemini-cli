/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { render } from 'ink';
import { AppWrapper } from './ui/App.js';
import { loadCliConfig } from './config/config.js';
import { readStdin } from './utils/readStdin.js';
import { basename } from 'node:path';
import v8 from 'node:v8';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { start_sandbox } from './utils/sandbox.js';
import {
  LoadedSettings,
  loadSettings,
  SettingScope,
} from './config/settings.js';
import { themeManager } from './ui/themes/theme-manager.js';
import { getStartupWarnings } from './utils/startupWarnings.js';
import { runNonInteractive } from './nonInteractiveCli.js';
import { loadExtensions, Extension } from './config/extension.js';
import { cleanupCheckpoints } from './utils/cleanup.js';
import {
  ApprovalMode,
  Config,
  EditTool,
  ShellTool,
  WriteFileTool,
  sessionId,
  logUserPrompt,
  AuthType,
  HeadlessAuthRequestError,
  completeHeadlessAuthProcess,
  getOauthClient,
} from '@google/gemini-cli-core';
import { OAuth2Client } from 'google-auth-library';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { validateAuthMethod } from './config/auth.js';
import { setMaxSizedBoxDebugging } from './ui/components/shared/MaxSizedBox.js';

function getNodeMemoryArgs(config: Config): string[] {
  const totalMemoryMB = os.totalmem() / (1024 * 1024);
  const heapStats = v8.getHeapStatistics();
  const currentMaxOldSpaceSizeMb = Math.floor(
    heapStats.heap_size_limit / 1024 / 1024,
  );

  // Set target to 50% of total memory
  const targetMaxOldSpaceSizeInMB = Math.floor(totalMemoryMB * 0.5);
  if (config.getDebugMode()) {
    console.debug(
      `Current heap size ${currentMaxOldSpaceSizeMb.toFixed(2)} MB`,
    );
  }

  if (process.env.GEMINI_CLI_NO_RELAUNCH) {
    return [];
  }

  if (targetMaxOldSpaceSizeInMB > currentMaxOldSpaceSizeMb) {
    if (config.getDebugMode()) {
      console.debug(
        `Need to relaunch with more memory: ${targetMaxOldSpaceSizeInMB.toFixed(2)} MB`,
      );
    }
    return [`--max-old-space-size=${targetMaxOldSpaceSizeInMB}`];
  }

  return [];
}

async function relaunchWithAdditionalArgs(additionalArgs: string[]) {
  const nodeArgs = [...additionalArgs, ...process.argv.slice(1)];
  const newEnv = { ...process.env, GEMINI_CLI_NO_RELAUNCH: 'true' };

  const child = spawn(process.execPath, nodeArgs, {
    stdio: 'inherit',
    env: newEnv,
  });

  await new Promise((resolve) => child.on('close', resolve));
  process.exit(0);
}

export async function main() {
  const workspaceRoot = process.cwd();
  const settings = loadSettings(workspaceRoot);

  await cleanupCheckpoints();
  if (settings.errors.length > 0) {
    for (const error of settings.errors) {
      let errorMessage = `Error in ${error.path}: ${error.message}`;
      if (!process.env.NO_COLOR) {
        errorMessage = `\x1b[31m${errorMessage}\x1b[0m`;
      }
      console.error(errorMessage);
      console.error(`Please fix ${error.path} and try again.`);
    }
    process.exit(1);
  }

  const extensions = loadExtensions(workspaceRoot);
  const config = await loadCliConfig(settings.merged, extensions, sessionId);

  // set default fallback to gemini api key
  // this has to go after load cli because thats where the env is set
  if (!settings.merged.selectedAuthType && process.env.GEMINI_API_KEY) {
    settings.setValue(
      SettingScope.User,
      'selectedAuthType',
      AuthType.USE_GEMINI,
    );
  }

  setMaxSizedBoxDebugging(config.getDebugMode());

  // Initialize centralized FileDiscoveryService
  config.getFileService();

  // Handle initial OAuth for GCA if needed, before sandbox or main UI
  // This is primarily for headless scenarios where user interaction is needed upfront.
  if (settings.merged.selectedAuthType === AuthType.LOGIN_WITH_GOOGLE) {
    // We call this to potentially trigger the headless stdout flow if creds are missing/invalid.
    // If auth is fine, or if it's GUI and can somehow proceed, it won't block here by exiting.
    // If it handles headless auth, it returns true and exits on failure, or continues on success.
    // If it returns false, it means auth was okay or not applicable for this pre-check.
    await handleInitialHeadlessAuth(config, settings);
    // Note: handleInitialHeadlessAuth will process.exit(1) on auth failure.
    // If it returns true, auth was done via stdout. If false, either creds were ok,
    // or it's a GUI case that getOauthClient might have tried to handle (less likely here),
    // or it's not LOGIN_WITH_GOOGLE.
  }

  if (config.getCheckpointingEnabled()) {
    try {
      await config.getGitService();
    } catch {
      // For now swallow the error, later log it.
    }
  }

  if (settings.merged.theme) {
    if (!themeManager.setActiveTheme(settings.merged.theme)) {
      // If the theme is not found during initial load, log a warning and continue.
      // The useThemeCommand hook in App.tsx will handle opening the dialog.
      console.warn(`Warning: Theme "${settings.merged.theme}" not found.`);
    }
  }

  const memoryArgs = settings.merged.autoConfigureMaxOldSpaceSize
    ? getNodeMemoryArgs(config)
    : [];

  // hop into sandbox if we are outside and sandboxing is enabled
  if (!process.env.SANDBOX) {
    const sandboxConfig = config.getSandbox();
    if (sandboxConfig) {
      if (settings.merged.selectedAuthType) {
        // Validate authentication here because the sandbox will interfere with the Oauth2 web redirect.
        try {
          const err = validateAuthMethod(settings.merged.selectedAuthType);
          if (err) {
            throw new Error(err);
          }
          await config.refreshAuth(settings.merged.selectedAuthType);
        } catch (err) {
          console.error('Error authenticating:', err);
          process.exit(1);
        }
      }
      await start_sandbox(sandboxConfig, memoryArgs);
      process.exit(0);
    } else {
      // Not in a sandbox and not entering one, so relaunch with additional
      // arguments to control memory usage if needed.
      if (memoryArgs.length > 0) {
        await relaunchWithAdditionalArgs(memoryArgs);
        process.exit(0);
      }
    }
  }
  let input = config.getQuestion();
  const startupWarnings = await getStartupWarnings();

  // Render UI, passing necessary config values. Check that there is no command line question.
  if (process.stdin.isTTY && input?.length === 0) {
    setWindowTitle(basename(workspaceRoot), settings);
    render(
      <React.StrictMode>
        <AppWrapper
          config={config}
          settings={settings}
          startupWarnings={startupWarnings}
        />
      </React.StrictMode>,
      { exitOnCtrlC: false },
    );
    return;
  }
  // If not a TTY, read from stdin
  // This is for cases where the user pipes input directly into the command
  if (!process.stdin.isTTY) {
    input += await readStdin();
  }
  if (!input) {
    console.error('No input provided via stdin.');
    process.exit(1);
  }

  logUserPrompt(config, {
    'event.name': 'user_prompt',
    'event.timestamp': new Date().toISOString(),
    prompt: input,
    prompt_length: input.length,
  });

  // Non-interactive mode handled by runNonInteractive
  const nonInteractiveConfig = await loadNonInteractiveConfig(
    config,
    extensions,
    settings,
  );

  await runNonInteractive(nonInteractiveConfig, input);
  process.exit(0);
}

function setWindowTitle(title: string, settings: LoadedSettings) {
  if (!settings.merged.hideWindowTitle) {
    process.stdout.write(`\x1b]2; Gemini - ${title} \x07`);

    process.on('exit', () => {
      process.stdout.write(`\x1b]2;\x07`);
    });
  }
}

// --- Global Unhandled Rejection Handler ---
process.on('unhandledRejection', (reason, _promise) => {
  // Log other unexpected unhandled rejections as critical errors
  console.error('=========================================');
  console.error('CRITICAL: Unhandled Promise Rejection!');
  console.error('=========================================');
  console.error('Reason:', reason);
  console.error('Stack trace may follow:');
  if (!(reason instanceof Error)) {
    console.error(reason);
  }
  // Exit for genuinely unhandled errors
  process.exit(1);
});

async function loadNonInteractiveConfig(
  config: Config,
  extensions: Extension[],
  settings: LoadedSettings,
) {
  let finalConfig = config;
  if (config.getApprovalMode() !== ApprovalMode.YOLO) {
    // Everything is not allowed, ensure that only read-only tools are configured.
    const existingExcludeTools = settings.merged.excludeTools || [];
    const interactiveTools = [
      ShellTool.Name,
      EditTool.Name,
      WriteFileTool.Name,
    ];

    const newExcludeTools = [
      ...new Set([...existingExcludeTools, ...interactiveTools]),
    ];

    const nonInteractiveSettings = {
      ...settings.merged,
      excludeTools: newExcludeTools,
    };
    finalConfig = await loadCliConfig(
      nonInteractiveSettings,
      extensions,
      config.getSessionId(),
    );
  }

  return await validateNonInterActiveAuth(
    settings.merged.selectedAuthType,
    finalConfig,
  );
}

async function validateNonInterActiveAuth(
  selectedAuthType: AuthType | undefined,
  nonInteractiveConfig: Config,
) {
  // making a special case for the cli. many headless environments might not have a settings.json set
  // so if GEMINI_API_KEY is set, we'll use that. However since the oauth things are interactive anyway, we'll
  // still expect that exists
  if (!selectedAuthType && !process.env.GEMINI_API_KEY) {
    console.error(
      'Please set an Auth method in your .gemini/settings.json OR specify GEMINI_API_KEY env variable file before running',
    );
    process.exit(1);
  }

  selectedAuthType = selectedAuthType || AuthType.USE_GEMINI;
  const err = validateAuthMethod(selectedAuthType);
  if (err != null) {
    console.error(err);
    process.exit(1);
  }

  await nonInteractiveConfig.refreshAuth(selectedAuthType);
  return nonInteractiveConfig;
}

async function handleInitialHeadlessAuth(config: Config, settings: LoadedSettings): Promise<boolean> {
  if (settings.merged.selectedAuthType === AuthType.LOGIN_WITH_GOOGLE) {
    console.debug('[gemini.tsx] Initial auth check for LOGIN_WITH_GOOGLE');
    try {
      // Try to get client. If creds are cached and valid, it returns.
      // If fresh login needed & GUI, it handles it (less likely pre-Ink).
      // If fresh login needed & headless, it throws HeadlessAuthRequestError.
      await getOauthClient(); // We don't need the client instance here, just checking if it throws for headless.
      console.debug('[gemini.tsx] getOauthClient succeeded or handled GUI auth (initial check).');
      return false; // Auth is fine or was handled by GUI flow if one could start.
    } catch (err) {
      if (err instanceof HeadlessAuthRequestError) {
        console.debug('[gemini.tsx] Caught HeadlessAuthRequestError during initial check.');
        const { challenge, client } = err;

        process.stdout.write("\n\n\n");
        process.stdout.write("--- Initial Authentication Required ---\n");
        process.stdout.write("Gemini CLI needs you to authenticate with Google.\n");
        process.stdout.write("Please open the following URL in your browser:\n");
        process.stdout.write(`\x1b]8;;${challenge.authUrl}\x07${challenge.authUrl}\x1b]8;;${"\x07"}\n`); // OSC 8 Link
        process.stdout.write("\nAfter authenticating, your browser will redirect to a localhost URL (it may show an error page).\n");
        process.stdout.write("Copy the ENTIRE URL from your browser's address bar.\n");
        process.stdout.write("---------------------------------------\n");

        const rl = readline.createInterface({ input, output });
        try {
          const pastedCallbackUrl = await rl.question('Paste the full callback URL here and press Enter: ');
          rl.close(); // Close readline interface immediately after getting input

          if (!pastedCallbackUrl.trim()) {
            process.stderr.write("\nAuthentication cancelled: No URL provided.\n");
            process.exit(1);
          }

          await completeHeadlessAuthProcess(client, pastedCallbackUrl.trim(), challenge.state, challenge.redirectUri);
          process.stdout.write("\nAuthentication successful! You can now use Gemini CLI.\n\n");
          return true; // Indicates initial headless auth was performed.
        } catch (authProcessError) {
          rl.close(); // Ensure readline is closed on error too
          process.stderr.write(`\nAuthentication failed: ${(authProcessError as Error).message}\nPlease check the pasted URL or try restarting the CLI.\n`);
          process.exit(1);
        }
      } else {
        // Other errors during the initial getOauthClient call
        process.stderr.write(`\nAn unexpected error occurred during initial authentication setup: ${ (err as Error).message}\nPlease try again or check your configuration.\n`);
        process.exit(1);
      }
    }
  }
  return false; // No OAuth pre-handling was done or needed for other auth types.
}
