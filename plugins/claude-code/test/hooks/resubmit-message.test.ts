// The resubmit block reason: the user's own prompt, pointerized, presented
// copyably. Pure builder — importable directly, no hook process needed.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { resubmitMessage } from '../../src/hooks/resubmit-message.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// Composed at runtime so the repo's own secret scan never flags this file.
const RAW_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const POINTERIZED = `deploy with [[aka:secret:0123456789abcdef0123456789abcdef]] please`;

const REF: BlockedDetectionRef = {
  reference: 'BLK-1234',
  ruleId: 'aws-access-key',
  maskedValue: 'A**************E',
};

describe('resubmitMessage', () => {
  it('embeds the rewrite verbatim, delimited on its own lines', () => {
    const message = resubmitMessage({
      ruleIds: 'aws-access-key',
      rewrite: POINTERIZED,
      clipboardWrote: false,
    });
    const lines = message.split('\n');
    const open = lines.findIndex((l) => l.includes('safe prompt') && l.startsWith('-----'));
    expect(open).toBeGreaterThan(-1);
    // The rewrite is its own line, exactly as given, inside the delimiters.
    expect(lines[open + 1]).toBe(POINTERIZED);
    expect(lines[open + 2]).toContain('end safe prompt');
  });

  it('states what was caught and that the secret never reached the model', () => {
    const message = resubmitMessage({
      ruleIds: 'aws-access-key, stripe-secret-key',
      rewrite: POINTERIZED,
      clipboardWrote: false,
    });
    expect(message).toContain('aws-access-key, stripe-secret-key');
    expect(message).toContain('never reached the model');
    expect(message).toContain('paste and resubmit');
    expect(message).toContain('local vault');
  });

  it('carries no raw value when given a pointerized rewrite', () => {
    const message = resubmitMessage({
      ruleIds: 'aws-access-key',
      rewrite: POINTERIZED,
      clipboardWrote: true,
      blockedRef: REF,
    });
    // Positive control on the SAME bytes: the rewrite is embedded verbatim, so
    // a message that stopped carrying it would go red here rather than passing
    // the absence check below on bytes that lost their content. A builder
    // returns `string`, so expectNoEchoOf's toBeDefined() guard is inert on it.
    expect(message).toContain(POINTERIZED);
    // Run by run — this message is handed straight to the user, and a rewrite
    // that pointerized only part of the value would leave a live prefix in it.
    expectNoEchoOf(message, RAW_KEY);
  });

  it('mentions the clipboard only when the write succeeded', () => {
    const opts = { ruleIds: 'aws-access-key', rewrite: POINTERIZED };
    const wrote = resubmitMessage({ ...opts, clipboardWrote: true });
    const failed = resubmitMessage({ ...opts, clipboardWrote: false });
    expect(wrote).toContain('clipboard');
    expect(wrote).toContain('paste and resubmit');
    expect(failed).not.toContain('clipboard');
    expect(failed).toContain('paste and resubmit');
  });

  it('includes the exception-approve guidance only with a ledger ref', () => {
    const opts = { ruleIds: 'aws-access-key', rewrite: POINTERIZED, clipboardWrote: false };
    const withRef = resubmitMessage({ ...opts, blockedRef: REF });
    const withoutRef = resubmitMessage(opts);
    expect(withRef).toContain('aka exception approve BLK-1234');
    expect(withoutRef).not.toContain('aka exception approve');
  });
});
