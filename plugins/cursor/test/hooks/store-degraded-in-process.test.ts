/**
 * The store-open branch, driven through the real handlers against a real
 * store this build cannot open BECAUSE IT IS NEWER.
 *
 * The message is chosen by `instanceof StoreAheadOfBuildError` reaching across
 * the package boundary, so a case that gets the skew wording out of a handler
 * proves both that the error survives this package's import graph and that the
 * call site routes it to `storeDegradedMessage`. A corrupt store is driven
 * beside it, so the two messages are told apart rather than both matching on
 * their shared opening.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runBeforeSubmitPrompt } from '../../src/hooks/before-submit-prompt-run.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';
import type { TempStore } from '../helpers/store.ts';
import { FIXTURE, payload, tempStore } from '../helpers/store.ts';

// Lexically past every real tag, so it sorts last and cannot collide with one
// a future migration adds.
const FUTURE_MIGRATION_TAG = '9999_from_a_newer_build';

let store: TempStore;
let stderr: StderrCapture;

beforeEach(() => {
  store = tempStore('aka-cursor-store-ahead-');
  stderr = captureStderr();
});

afterEach(() => {
  vi.restoreAllMocks();
  store.cleanup();
});

/**
 * A ledger tag from a migration this build does not define, plus a table its
 * repositories prepare against turned into a view. Every byte is intact and an
 * up-to-date build reads it.
 */
function seedStoreAheadOfBuild(): void {
  const dir = join(store.akaHome, 'data');
  mkdirSync(dir, { recursive: true });
  openLocalDatabase(dir).close();
  const raw = new DatabaseSync(join(dir, 'aka.db'));
  try {
    raw.exec('ALTER TABLE classified_data RENAME TO classified_data_backing');
    raw.exec('CREATE VIEW classified_data AS SELECT * FROM classified_data_backing');
    raw
      .prepare('INSERT OR IGNORE INTO migration_ledger (tag, applied_at) VALUES (?, ?)')
      .run(FUTURE_MIGRATION_TAG, Date.now());
    raw.exec('PRAGMA user_version = 9999');
  } finally {
    raw.close();
  }
}

function seedCorruptStore(): void {
  const dir = join(store.akaHome, 'data');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'aka.db'), 'AKA corrupt-store fixture — not a database\n'.repeat(64));
}

const HOOKS = [
  {
    name: 'preToolUse',
    run: () =>
      runPreToolUse(
        'preToolUse',
        JSON.stringify(
          payload('preToolUse', {
            conversation_id: 'ahead-pre-tool-use',
            cwd: store.cwd,
            tool_input: { command: `echo ${FIXTURE.example}` },
          }),
        ),
        { akaHome: store.akaHome },
      ),
  },
  {
    name: 'beforeSubmitPrompt',
    run: () =>
      runBeforeSubmitPrompt(
        'beforeSubmitPrompt',
        JSON.stringify(
          payload('beforeSubmitPrompt', {
            conversation_id: 'ahead-prompt',
            workspace_roots: [store.cwd],
            prompt: `use ${FIXTURE.example}`,
          }),
        ),
        { akaHome: store.akaHome },
      ),
  },
  {
    name: 'postToolUse',
    run: () =>
      runPostToolUse(
        'postToolUse',
        JSON.stringify(
          payload('postToolUse', {
            conversation_id: 'ahead-post-tool-use',
            cwd: store.cwd,
            tool_output: FIXTURE.example,
          }),
        ),
        { akaHome: store.akaHome },
      ),
  },
] as const;

describe.each(HOOKS)('$name, when the store cannot be opened', ({ run }) => {
  it('names the version gap for a newer store, never the file, and passes through', async () => {
    seedStoreAheadOfBuild();
    expect(await run()).toBeUndefined();
    const notice = stderr.filtered();
    expect(notice).toContain(FUTURE_MIGRATION_TAG);
    expect(notice).toContain('this AKA build is older than the store');
    expect(notice).not.toMatch(/aside|recreate/i);
  });

  it('keeps the file-repair advice for a corrupt store (the control)', async () => {
    seedCorruptStore();
    expect(await run()).toBeUndefined();
    const notice = stderr.filtered();
    expect(notice).toContain('could not open its local store');
    expect(notice).toMatch(/aside/i);
    expect(notice).not.toContain('older than the store');
  });
});
