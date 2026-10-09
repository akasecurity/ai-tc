// The handoff notes (src/mod/handoff.ts): one file per note, so concurrent helpers
// lose none; spent exactly once; and aged out, a note dated ahead included.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { build } from 'esbuild';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  consumeModHandoff,
  consumeToolHandoff,
  HANDOFF_SKEW_MS,
  HANDOFF_TTL_MS,
  recordModHandoff,
  recordToolHandoff,
} from '../../src/mod/handoff.ts';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-handoff-'));
});
afterEach(() => {
  removeTree(dir);
});

const notes = (): string[] => readdirSync(join(dir, 'mod-handoff'));
function firstNote(): string {
  const [name] = notes();
  if (name === undefined) throw new Error('expected a note');
  return name;
}

describe('expiry', () => {
  it('honours a note inside the TTL and spends it', () => {
    recordModHandoff(dir, 'rewritten', 10_000);
    expect(consumeModHandoff(dir, 'rewritten', 10_000 + HANDOFF_TTL_MS - 1)).toBe(true);
    expect(consumeModHandoff(dir, 'rewritten', 10_000 + 1)).toBe(false);
  });

  it('does not honour a note at or past the TTL, and spends it', () => {
    recordModHandoff(dir, 'rewritten', 10_000);
    expect(consumeModHandoff(dir, 'rewritten', 10_000 + HANDOFF_TTL_MS)).toBe(false);
    expect(notes()).toEqual([]);
  });

  it('does not honour a note dated ahead of the clock, however far', () => {
    const now = 1_000_000;
    recordModHandoff(dir, 'rewritten', now + 365 * 24 * 60 * 60 * 1000);
    recordToolHandoff(dir, 'Bash', { command: 'x' }, Number.MAX_SAFE_INTEGER);
    expect(consumeModHandoff(dir, 'rewritten', now)).toBe(false);
    expect(consumeToolHandoff(dir, 'Bash', { command: 'x' }, now)).toBe(false);
  });

  it('does not honour a note just past the skew', () => {
    const now = 1_000_000;
    recordModHandoff(dir, 'rewritten', now + HANDOFF_SKEW_MS + 1);
    expect(consumeModHandoff(dir, 'rewritten', now)).toBe(false);
  });

  it('allows a small skew between the writer and the reader', () => {
    const now = 1_000_000;
    recordModHandoff(dir, 'rewritten', now + HANDOFF_SKEW_MS);
    expect(consumeModHandoff(dir, 'rewritten', now)).toBe(true);
  });

  it('treats a corrupt note as no note and removes it', () => {
    recordModHandoff(dir, 'rewritten');
    writeFileSync(join(dir, 'mod-handoff', firstNote()), '{nope');
    expect(consumeModHandoff(dir, 'rewritten')).toBe(false);
    expect(notes()).toEqual([]);
  });
});

describe('notes', () => {
  it('keeps two notes for the same text apart and spends each once', () => {
    recordModHandoff(dir, 'same');
    recordModHandoff(dir, 'same');
    expect(consumeModHandoff(dir, 'same')).toBe(true);
    expect(consumeModHandoff(dir, 'same')).toBe(true);
    expect(consumeModHandoff(dir, 'same')).toBe(false);
  });

  it('sweeps stale files, a bounded number per record, and leaves fresh ones', () => {
    recordModHandoff(dir, 'old');
    const old = firstNote();
    const longAgo = new Date(Date.now() - 10 * HANDOFF_TTL_MS);
    utimesSync(join(dir, 'mod-handoff', old), longAgo, longAgo);
    recordModHandoff(dir, 'fresh');
    expect(notes().some((n) => n === old)).toBe(false);
    expect(consumeModHandoff(dir, 'fresh')).toBe(true);
  });

  it('removes the shared file earlier builds kept', () => {
    writeFileSync(join(dir, 'mod-handoff.json'), '[]');
    recordModHandoff(dir, 'x');
    expect(existsSync(join(dir, 'mod-handoff.json'))).toBe(false);
  });
});

describe('concurrent helpers', () => {
  let script: string;
  beforeAll(async () => {
    // A script that records through the real module, bundled so a plain `node`
    // can run it (the module's one workspace import is stubbed: two file modes and the fingerprint key functions, which the concurrent notes never reach).
    const out = mkdtempSync(join(tmpdir(), 'aka-handoff-bundle-'));
    script = join(out, 'record.mjs');
    await build({
      stdin: {
        contents: `
          import { recordModHandoff, recordToolHandoff } from ${JSON.stringify(
            new URL('../../src/mod/handoff.ts', import.meta.url).pathname,
          )};
          const [dir, start, who, count] = process.argv.slice(2);
          while (Date.now() < Number(start)) { /* start together */ }
          for (let i = 0; i < Number(count); i += 1) {
            if (i % 2 === 0) recordModHandoff(dir, 'prompt-' + who + '-' + i);
            else recordToolHandoff(dir, 'Bash', { command: 'run-' + who + '-' + i });
          }
        `,
        resolveDir: out,
        loader: 'ts',
      },
      bundle: true,
      platform: 'node',
      format: 'esm',
      outfile: script,
      logLevel: 'silent',
      plugins: [
        {
          name: 'sdk-modes',
          setup(b) {
            b.onResolve({ filter: /^@akasecurity\/plugin-sdk$/ }, () => ({
              path: 'sdk-modes',
              namespace: 'stub',
            }));
            b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({
              contents: [
                'export const DATA_DIR_MODE = 0o700; export const DATA_FILE_MODE = 0o600;',
                'export const fingerprintValue = () => ""; export const loadOrCreateFingerprintKey = () => null;',
                'export const readFingerprintKey = () => null;',
              ].join('\n'),
              loader: 'js',
            }));
          },
        },
      ],
    });
  });

  it('keeps every note from many processes writing at once, each consumable once', async () => {
    const writers = 12;
    const each = 6;
    const start = Date.now() + 1500;
    await Promise.all(
      Array.from(
        { length: writers },
        (_, who) =>
          new Promise<void>((resolve, reject) => {
            const child = spawn(
              process.execPath,
              [script, dir, String(start), String(who), String(each)],
              { stdio: 'ignore' },
            );
            child.on('error', reject);
            child.on('exit', (code) => {
              if (code === 0) resolve();
              else reject(new Error(`writer exited ${String(code)}`));
            });
          }),
      ),
    );

    expect(notes()).toHaveLength(writers * each);
    for (let who = 0; who < writers; who += 1) {
      for (let i = 0; i < each; i += 1) {
        const found =
          i % 2 === 0
            ? consumeModHandoff(dir, `prompt-${String(who)}-${String(i)}`)
            : consumeToolHandoff(dir, 'Bash', { command: `run-${String(who)}-${String(i)}` });
        expect(found).toBe(true);
        const again =
          i % 2 === 0
            ? consumeModHandoff(dir, `prompt-${String(who)}-${String(i)}`)
            : consumeToolHandoff(dir, 'Bash', { command: `run-${String(who)}-${String(i)}` });
        expect(again).toBe(false);
      }
    }
    expect(notes()).toEqual([]);
  }, 30_000);
});
