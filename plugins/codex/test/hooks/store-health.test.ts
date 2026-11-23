// This plugin's store-health seam. The module itself is tested once, in
// packages/plugin-runtime/test/store-health.test.ts; this suite pins that the
// seam re-exports it rather than a copy, and what each hook passes in.
import { readFileSync } from 'node:fs';

import * as shared from '@akasecurity/plugin-runtime';
import { describe, expect, it } from 'vitest';

import * as seam from '../../src/hooks/store-health.ts';

describe('the store-health seam', () => {
  const sharedNames = Object.keys(shared.storeHealth).sort();
  const exported = seam as Record<string, unknown>;

  it('re-exports every function of the shared module, by identity', () => {
    expect(sharedNames.length).toBeGreaterThan(0);
    for (const name of sharedNames) {
      expect(exported[name], name).toBe(
        shared.storeHealth[name as keyof typeof shared.storeHealth],
      );
    }
  });
});

describe('the event each hook names on a locked store', () => {
  it.each([
    ['pre-tool-use.ts', 'tool call', 'opened.error'],
    ['user-prompt-submit.ts', 'prompt', 'opened.error'],
  ])('%s names a %s', (file: string, subject: string, errorArg: string) => {
    const source = readFileSync(new URL(`../../src/hooks/${file}`, import.meta.url), 'utf8');
    expect(source).toContain(`storeDegradedMessage(config.dbPath, ${errorArg}, '${subject}')`);
    // The claim must see the same error, or a lock falls back to the
    // once-per-session gate.
    expect(source).toMatch(
      new RegExp(
        `claimStoreDegradedWarning\\(config\\.dataDir, [^\\n]+, ${errorArg.replace('.', '\\.')}\\)`,
        'u',
      ),
    );
  });
});
