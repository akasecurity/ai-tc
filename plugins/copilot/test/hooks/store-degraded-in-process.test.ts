/**
 * The store-open branch, driven through the real handlers against a real
 * store this build cannot open BECAUSE IT IS NEWER, on both dialects.
 *
 * The message is chosen by `instanceof StoreAheadOfBuildError` reaching across
 * the package boundary, so a case that gets the skew wording out of a handler
 * proves both that the error survives this package's import graph and that the
 * call site routes it to `storeDegradedMessage`. A corrupt store is driven
 * beside it, so the two messages are told apart rather than both matching on
 * their shared opening.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookHandler } from '../../src/hooks/shared.ts';
import { runUserPromptSubmit } from '../../src/hooks/user-prompt-submit-run.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

// Lexically past every real tag, so it sorts last and cannot collide with one
// a future migration adds.
const FUTURE_MIGRATION_TAG = '9999_from_a_newer_build';

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

let root: string;
let akaHome: string;
let cwd: string;
let stderr: StderrCapture;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-store-degraded-'));
  akaHome = join(root, 'aka-home');
  cwd = join(root, 'checkout');
  mkdirSync(cwd);
  stderr = captureStderr();
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([root]);
});

/**
 * A ledger tag from a migration this build does not define, plus a table its
 * repositories prepare against turned into a view. Every byte is intact and an
 * up-to-date build reads it.
 */
function seedStoreAheadOfBuild(): void {
  const dir = join(akaHome, 'data');
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
  const dir = join(akaHome, 'data');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'aka.db'), 'AKA corrupt-store fixture — not a database\n'.repeat(64));
}

interface Case {
  name: string;
  dialect: 'cli' | 'vscode';
  event: string;
  run: HookHandler;
  payload: () => Record<string, unknown>;
}

const CASES: readonly Case[] = [
  {
    name: 'preToolUse',
    dialect: 'cli',
    event: 'preToolUse',
    run: runPreToolUse,
    payload: () => {
      const base = fixture('cli', 'preToolUse.json');
      return { ...base, cwd, toolArgs: { ...(base.toolArgs as object), command: 'ls -la' } };
    },
  },
  {
    name: 'PreToolUse',
    dialect: 'vscode',
    event: 'PreToolUse',
    run: runPreToolUse,
    payload: () => {
      const base = fixture('vscode-provisional', 'PreToolUse.json');
      return { ...base, cwd, tool_input: { ...(base.tool_input as object), command: 'ls -la' } };
    },
  },
  {
    name: 'userPromptSubmitted',
    dialect: 'cli',
    event: 'userPromptSubmitted',
    run: runUserPromptSubmit,
    payload: () => ({ ...fixture('cli', 'userPromptSubmitted.json'), cwd, prompt: 'hello' }),
  },
  {
    name: 'UserPromptSubmit',
    dialect: 'vscode',
    event: 'UserPromptSubmit',
    run: runUserPromptSubmit,
    payload: () => ({
      ...fixture('vscode-provisional', 'UserPromptSubmit.json'),
      cwd,
      prompt: 'hello',
    }),
  },
  {
    name: 'postToolUse',
    dialect: 'cli',
    event: 'postToolUse',
    run: runPostToolUse,
    payload: () => ({
      ...fixture('cli', 'postToolUse.json'),
      cwd,
      toolResult: { resultType: 'success', textResultForLlm: 'total 0' },
    }),
  },
  {
    name: 'PostToolUse',
    dialect: 'vscode',
    event: 'PostToolUse',
    run: runPostToolUse,
    payload: () => ({
      ...fixture('vscode-provisional', 'PostToolUse.json'),
      cwd,
      tool_response: 'total 0',
    }),
  },
];

/** The message on the channel this dialect has for it. */
async function notice(c: Case): Promise<string> {
  const output = await c.run(c.event, JSON.stringify(c.payload()), { akaHome });
  if (c.dialect === 'vscode') {
    return String((output as { systemMessage?: unknown } | undefined)?.systemMessage);
  }
  expect(output).toBeUndefined();
  return stderr.filtered();
}

describe.each(CASES)('$name, when the store cannot be opened', (c) => {
  it('names the version gap for a newer store, never the file', async () => {
    seedStoreAheadOfBuild();
    const text = await notice(c);
    expect(text).toContain(FUTURE_MIGRATION_TAG);
    expect(text).toContain('this AKA build is older than the store');
    expect(text).not.toMatch(/aside|recreate/iu);
  });

  it('keeps the file-repair advice for a corrupt store (the control)', async () => {
    seedCorruptStore();
    const text = await notice(c);
    expect(text).toContain('could not open its local store');
    expect(text).toMatch(/aside/iu);
    expect(text).not.toContain('older than the store');
  });
});

/**
 * Holds the store exclusively from a second connection until released, so
 * every hook's open waits out its busy timeout and fails with SQLITE_BUSY.
 */
function holdStoreLocked(): () => void {
  const dir = join(akaHome, 'data');
  mkdirSync(dir, { recursive: true });
  openLocalDatabase(dir).close();
  const holder = new DatabaseSync(join(dir, 'aka.db'));
  holder.exec('PRAGMA journal_mode = WAL');
  holder.exec('PRAGMA locking_mode = EXCLUSIVE');
  holder.exec('BEGIN EXCLUSIVE');
  holder.prepare('SELECT count(*) FROM migration_ledger').get();
  return () => {
    holder.exec('ROLLBACK');
    holder.close();
  };
}

const BUSY_SENTENCE = 'another process held it locked longer than AKA waits';

// A lock lasts for one event, so each hook reports it every time rather than
// spending the once-per-session warning. Both runs share one session id, so a
// call site that stopped passing the open error to the claim would fall back to
// the once-per-session gate and the second run would say nothing.
describe.each(CASES)('$name, when another process holds the store', (c) => {
  it('reports the lock on every event in one session, without repair advice', async () => {
    const release = holdStoreLocked();
    let texts: string[];
    try {
      texts = [await notice(c), await notice(c)];
    } finally {
      release();
    }
    const all = c.dialect === 'cli' ? (texts[1] ?? '') : texts.join('\n');
    expect(all.split(BUSY_SENTENCE)).toHaveLength(3);
    expect(all).not.toMatch(/aside|recreate|corrupt/iu);
  }, 30_000);
});
