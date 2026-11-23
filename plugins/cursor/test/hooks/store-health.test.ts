// This plugin's store-health seam. The module itself is tested once, in
// packages/plugin-runtime/test/store-health.test.ts; this suite pins that the
// seam re-exports it rather than a copy, and what each hook passes in.
import { readFileSync } from 'node:fs';

import * as shared from '@akasecurity/plugin-runtime';
import { describe, expect, it } from 'vitest';

import * as seam from '../../src/hooks/store-health.ts';

describe('the store-health seam', () => {
  it.each([
    'claimStoreDegradedWarning',
    'claimStoreUnavailableWarning',
    'isSessionMarked',
    'markSession',
    'storeAheadMessage',
    'storeBusyMessage',
    'storeDegradedMessage',
    'storeOpenCause',
    'storeRedirectedMessage',
    'storeUnavailableMessage',
    'warnIfStoreRedirected',
    'openGateway',
    'openGatewayOrNull',
  ] as const)('re-exports the shared %s', (name) => {
    expect(seam[name]).toBe(shared[name]);
  });
});

describe('the event each hook names on a locked store', () => {
  it.each([
    ['pre-tool-use-run.ts', 'tool call'],
    ['post-tool-use-run.ts', 'tool result'],
    ['before-submit-prompt-run.ts', 'prompt'],
  ])('%s names a %s', (file, subject) => {
    const source = readFileSync(new URL(`../../src/hooks/${file}`, import.meta.url), 'utf8');
    expect(source).toContain(`storeDegradedMessage(config.dbPath, error, '${subject}')`);
  });
});
