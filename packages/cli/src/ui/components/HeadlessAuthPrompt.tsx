/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react'; // Added back useEffect, useRef
import { Box, Text, Newline, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { Colors } from '../colors.js';

interface HeadlessAuthPromptProps {
  authUrl: string;
  errorMessage?: string;
  onSubmit: (pastedUrl: string) => void;
  onCancel: () => void;
}

export const HeadlessAuthPrompt: React.FC<HeadlessAuthPromptProps> = ({
  authUrl,
  errorMessage,
  onSubmit,
  onCancel,
}) => {
  const [pastedUrl, setPastedUrl] = useState('');
  const hasPrintedFullUrl = useRef(false);

  useInput((input, key) => {
    if (key.escape) {
      onCancel();
    }
  });

  useEffect(() => {
    if (!hasPrintedFullUrl.current) {
      process.stdout.write("\n\n\n");
      process.stdout.write("--- Full Authentication URL (TRY CLICKING OR COPYING THIS LINE) ---\n");
      process.stdout.write(`\x1b]8;;${authUrl}\x07${authUrl}\x1b]8;;${"\x07"}\n`);
      process.stdout.write("------------------------------------------------------------\n\n");
      hasPrintedFullUrl.current = true;
    }
  }, [authUrl]);

  const handleSubmit = () => {
    if (pastedUrl.trim()) {
      onSubmit(pastedUrl.trim());
    }
  };

  return (
    <Box flexDirection="column" padding={1} borderColor={Colors.AccentBlue} borderStyle="round">
      <Text bold>Headless Authentication Required</Text>
      <Newline />
      <Text>
        To authenticate, please follow these steps:
      </Text>
      <Text>
        1. A clickable/copyable authentication URL has been printed to your console (you may need to scroll up).
      </Text>
      <Text>
           For visual reference, the URL is also shown below. Please open it in your browser:
      </Text>
      <Box marginY={1} paddingX={1} borderStyle="round" borderColor={Colors.Gray}>
        <Text color={Colors.AccentCyan} wrap="wrap">{authUrl}</Text>
      </Box>
      <Text color={Colors.AccentYellow}>
        (When copying the URL from above, select carefully if it wraps.)
      </Text>
      <Text>
        2. Sign in with your Google account.
      </Text>
      <Text>
        3. After signing in, your browser will be redirected to an 'http://localhost:...' URL.
      </Text>
      <Text color={Colors.AccentYellow}>
           This page in your browser might show an error (e.g., "This site can’t be reached"). This is expected.
      </Text>
      <Text>
        4. Copy the ENTIRE URL from your browser's address bar at that point.
      </Text>
      <Text>
        5. Paste the copied URL into the input field below and press Enter.
      </Text>
      <Newline />
      <Box>
        <Text>Paste URL here: </Text>
        <TextInput
          value={pastedUrl}
          onChange={setPastedUrl}
          onSubmit={handleSubmit}
          placeholder="http://localhost:..."
        />
      </Box>
      {errorMessage && (
        <Box marginTop={1}>
          <Text color={Colors.AccentRed}>Error: {errorMessage}</Text>
        </Box>
      )}
      <Newline />
      <Text color={Colors.Gray}>Press Enter to submit, Esc to cancel.</Text>
    </Box>
  );
};
