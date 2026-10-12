// The three mod helpers' logic (src/mod/*-run.ts), driven in-process against a
// throwaway store so its lines are measured; test/e2e/mod-*.e2e.test.ts drives
// the same cases through the built scripts.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runModReveal } from '../../src/mod/reveal-run.ts';
import { runModTokenize } from '../../src/mod/tokenize-run.ts';
import { runModToolCall } from '../../src/mod/tool-call-run.ts';

const RULE_ID = 'secrets/twilio-key';
const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const SECRET = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0] ?? '';
const UNBACKED = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');

let home: string;
let cwd: string;

function seed(
  policy: BuiltinPolicyId,
  settings: { vault: boolean; reveal?: 'full' | 'masked' | 'off' },
): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, policy);
  } finally {
    db.close();
  }
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({
      onboardedAt: '2026-01-01T00:00:00Z',
      ...(settings.reveal === undefined ? {} : { vaultInlineReveal: settings.reveal }),
      ...(settings.vault
        ? {
            vaultConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: VAULT_CONSENT_VERSION,
            },
          }
        : {}),
    }),
  );
}

const tokenize = (body: Record<string, unknown>) =>
  runModTokenize(JSON.stringify({ v: 1, sessionId: 's', cwd, ...body }));

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-helper-run-'));
  cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
});

afterEach(() => {
  vi.unstubAllEnvs();
  removeTree(home);
});

describe('runModTokenize', () => {
  it.each([
    ['not json', 'nope'],
    ['no text', JSON.stringify({ v: 1 })],
    ['another version', JSON.stringify({ v: 2, text: 'x' })],
    ['a row with no door', JSON.stringify({ v: 1, text: 'x', row: {} })],
  ])('answers nothing for %s', async (_name, stdin) => {
    expect(await runModTokenize(stdin)).toEqual({ code: 1, stdout: '' });
  });

  it('answers a one-way marker without consent', async () => {
    seed('redact', { vault: false });
    const run = await tokenize({ text: `key ${SECRET} now` });
    expect(run.code).toBe(0);
    const answer = JSON.parse(run.stdout) as { text: string; note: string | null };
    expect(answer.text).toBe('key [REDACTED:SECRET] now');
    expect(answer.note).toBeNull();
  });

  it('answers a pointer and a note with consent, and a row gets no note', async () => {
    seed('vault', { vault: true });
    const prompt = JSON.parse((await tokenize({ text: `key ${SECRET}` })).stdout) as {
      text: string;
      note: string | null;
    };
    expect(prompt.text).toMatch(/\[\[aka:secret:/);
    expect(prompt.note).toContain('Use each pointer verbatim');
    const row = JSON.parse(
      (await tokenize({ text: `key ${SECRET}`, row: { door: 'attachment' } })).stdout,
    ) as { text: string; note: string | null };
    expect(row.text).toMatch(/\[\[aka:secret:/);
    expect(row.note).toBeNull();
  });

  it('answers nothing when the policy is not a redact', async () => {
    seed('monitor', { vault: true });
    expect(await tokenize({ text: `key ${SECRET}` })).toEqual({ code: 1, stdout: '' });
  });
});

describe('runModReveal', () => {
  const reveal = (items: unknown) => runModReveal(JSON.stringify({ v: 1, items }));

  it.each([
    ['not json', 'nope'],
    ['no items', JSON.stringify({ v: 1, items: [] })],
    [
      'too many',
      JSON.stringify({ v: 1, items: Array(33).fill({ token: UNBACKED, reveal: true }) }),
    ],
    ['a non-object item', JSON.stringify({ v: 1, items: ['x'] })],
    ['a bad token', JSON.stringify({ v: 1, items: [{ token: 'x', reveal: true }] })],
    ['a bad flag', JSON.stringify({ v: 1, items: [{ token: UNBACKED, reveal: 'y' }] })],
  ])('answers nothing for %s', async (_name, stdin) => {
    expect(await runModReveal(stdin)).toEqual({ code: 1, stdout: '' });
  });

  it('answers no items without consent or with reveal off', async () => {
    seed('vault', { vault: false, reveal: 'full' });
    expect(JSON.parse((await reveal([{ token: UNBACKED, reveal: true }])).stdout)).toEqual({
      v: 1,
      mode: 'off',
      items: [],
    });
  });

  it('full mode reveals a minted pointer, masks a declined one, and nulls an unbacked one', async () => {
    seed('vault', { vault: true, reveal: 'full' });
    const minted = JSON.parse((await tokenize({ text: `key ${SECRET}` })).stdout) as {
      text: string;
    };
    const token = /\[\[aka:[^\]]+\]\]/.exec(minted.text)?.[0] ?? '';
    const answer = JSON.parse(
      (
        await reveal([
          { token, reveal: true },
          { token, reveal: false },
          { token: UNBACKED, reveal: true },
        ])
      ).stdout,
    ) as { mode: string; items: { badge: string; revealed: string | null }[] };
    expect(answer.mode).toBe('full');
    expect(answer.items[0]?.revealed).toBe(`${SECRET} [scrubbed:secret]`);
    expect(answer.items[1]?.revealed).toBeNull();
    expect(answer.items[2]?.revealed).toBeNull();
  });

  it('masked mode never resolves a value', async () => {
    seed('vault', { vault: true, reveal: 'masked' });
    const run = await reveal([{ token: UNBACKED, reveal: true }]);
    expect(run.stdout).not.toContain(SECRET);
    expect((JSON.parse(run.stdout) as { mode: string }).mode).toBe('masked');
  });
});

describe('runModToolCall', () => {
  const call = (body: Record<string, unknown>) =>
    runModToolCall(JSON.stringify({ v: 1, sessionId: 's', cwd, ...body }));

  it.each([
    ['not json', 'nope'],
    ['no tool', JSON.stringify({ v: 1, input: {} })],
    ['an empty tool', JSON.stringify({ v: 1, tool: '', input: {} })],
    ['an array input', JSON.stringify({ v: 1, tool: 'Bash', input: [] })],
    ['a null input', JSON.stringify({ v: 1, tool: 'Bash', input: null })],
  ])('answers nothing for %s', async (_name, stdin) => {
    expect(await runModToolCall(stdin)).toEqual({ code: 1, stdout: '' });
  });

  it('answers a rewrite for a redacted value and a deny for a blocked one', async () => {
    seed('redact', { vault: false });
    const rewritten = JSON.parse(
      (await call({ tool: 'Write', input: { file_path: join(cwd, 'a.txt'), content: SECRET } }))
        .stdout,
    ) as { deny: string | null; input: { content: string } | null };
    expect(rewritten.deny).toBeNull();
    expect(JSON.stringify(rewritten.input)).not.toContain(SECRET);
    const dir = join(home, '.aka', 'data');
    const db = openLocalDatabase(dir);
    try {
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, 'block');
    } finally {
      db.close();
    }
    const denied = JSON.parse(
      (await call({ tool: 'Bash', input: { command: `run ${SECRET}` } })).stdout,
    ) as { deny: string | null };
    expect(denied.deny).not.toBeNull();
  });

  it('answers a pass for a call with nothing in it', async () => {
    seed('redact', { vault: false });
    const run = await call({ tool: 'Bash', input: { command: 'ls' } });
    expect(run.code).toBe(0);
    expect(JSON.parse(run.stdout)).toMatchObject({ deny: null, input: null });
  });

  it('answers nothing when there is no tool to scan', async () => {
    seed('redact', { vault: false });
    expect(await call({ tool: 'NoSuchTool', input: { a: 1 } })).toEqual({ code: 1, stdout: '' });
  });
});
