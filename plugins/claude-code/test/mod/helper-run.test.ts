// The three mod helpers' logic (src/mod/*-run.ts), driven in-process against a
// throwaway store so its lines are measured; test/e2e/mod-*.e2e.test.ts drives
// the same cases through the built scripts.
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { ATTACHED_CAPTURE_SETTINGS_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ISSUED_TWILIO_SID } from '../../../../test/helpers/issued-secret.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runModReveal } from '../../src/mod/reveal-run.ts';
import { runModTokenize } from '../../src/mod/tokenize-run.ts';
import { runModToolCall } from '../../src/mod/tool-call-run.ts';

const RULE_ID = 'secrets/twilio-key';
const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const SECRET = ISSUED_TWILIO_SID;
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

function responseRows(): { content: string }[] {
  const file = join(home, '.aka', 'data', 'aka.db');
  if (!existsSync(file)) return [];
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return db
      .prepare("SELECT content FROM audit_events WHERE event_type = 'response' ORDER BY rowid")
      .all() as { content: string }[];
  } finally {
    db.close();
  }
}

function captureSettings(body: Record<string, unknown>): void {
  const dir = join(home, '.aka', 'data');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ATTACHED_CAPTURE_SETTINGS_FILENAME), JSON.stringify({ v: 1, ...body }));
}

describe('runModTokenize — a tool result handed over to be forwarded', () => {
  const forwardRow = (text: string, forward: Record<string, unknown>) =>
    tokenize({ text, row: { door: 'tool-result', tool: 'Read', forward } });

  it('records a clean result under the cap, with the length it was cut from', async () => {
    seed('redact', { vault: false });
    captureSettings({ toolOutput: { maxChars: 100 } });
    const run = await forwardRow('a clean tool result', { maxChars: 100, length: 4_000 });
    expect(run).toEqual({ code: 1, stdout: '' });
    expect(responseRows()).toEqual([{ content: 'a clean tool result' }]);
  });

  it('records nothing without settings, or for a repository they do not name', async () => {
    seed('redact', { vault: false });
    expect(await forwardRow('a clean tool result', { maxChars: 100 })).toEqual({
      code: 1,
      stdout: '',
    });
    captureSettings({ toolOutput: { maxChars: 100, repos: ['github.com/acme/app'] } });
    await forwardRow('a clean tool result', { maxChars: 100 });
    expect(responseRows()).toEqual([]);
  });

  it('records nothing for a result with a finding', async () => {
    seed('monitor', { vault: false });
    captureSettings({ toolOutput: { maxChars: 100 } });
    expect(await forwardRow(`key ${SECRET}`, { maxChars: 100 })).toEqual({ code: 1, stdout: '' });
    expect(responseRows()).toEqual([]);
  });

  it('records nothing when the settings name repositories, which PostToolUse keys by file', async () => {
    seed('redact', { vault: false });
    captureSettings({ toolOutput: { maxChars: 100, repos: ['github.com/acme/app'] } });
    expect(await forwardRow('a clean tool result', { maxChars: 100 })).toEqual({
      code: 1,
      stdout: '',
    });
    expect(responseRows()).toEqual([]);
  });

  it('takes a malformed mark as an ordinary row', async () => {
    seed('redact', { vault: false });
    captureSettings({ toolOutput: { maxChars: 100 } });
    const run = await forwardRow(`key ${SECRET}`, { maxChars: 'many' });
    expect(run.code).toBe(0);
  });
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

  it('places a finding from a subagent row in the subagent', async () => {
    seed('redact', { vault: false });
    const whereOf = async (row: object) =>
      (
        JSON.parse((await tokenize({ text: `key ${SECRET}`, row })).stdout) as {
          findings: { where: string }[];
        }
      ).findings.map((f) => f.where);
    expect(await whereOf({ door: 'attachment', agentId: 'agent-7' })).toEqual(['subagent']);
    expect(await whereOf({ door: 'attachment' })).toEqual(['attachment']);
  });

  it('answers the rewrite when building the finding records throws', async () => {
    seed('redact', { vault: false });
    const toIso = Object.getOwnPropertyDescriptor(Date.prototype, 'toISOString')?.value as (
      this: Date,
    ) => string;
    const fault = vi.spyOn(Date.prototype, 'toISOString').mockImplementation(function (this: Date) {
      if (new Error().stack?.includes('modFindingsFrom') === true) throw new RangeError('fault');
      return toIso.call(this);
    });
    try {
      const run = await tokenize({ text: `key ${SECRET} now` });
      expect(run.code).toBe(0);
      expect(JSON.parse(run.stdout)).toMatchObject({
        text: 'key [REDACTED:SECRET] now',
        findings: [],
      });
      expect(fault).toHaveBeenCalled();
    } finally {
      fault.mockRestore();
    }
  });

  it('labels a custom rule with no short name by its full name', async () => {
    seed('redact', { vault: false });
    const raw = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'));
    try {
      raw
        .prepare(
          `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, policy_id, created_at, updated_at)
           VALUES ('custom-tickets', 'acme', 'tickets', '1.0.0', 'Acme tickets', :rules, 1, 'redact', 1, 1)`,
        )
        .run({
          rules: JSON.stringify([
            {
              specVersion: 1,
              id: 'acme/ticket',
              name: 'Acme support ticket reference',
              category: 'custom',
              severity: 'high',
              matcher: { type: 'regex', pattern: 'ACME-[0-9]{6}', flags: 'g' },
              examples: ['ACME-123456'],
            },
          ]),
        });
    } finally {
      raw.close();
    }
    const run = await tokenize({ text: 'see ACME-123456 today' });
    expect(run.code).toBe(0);
    const answer = JSON.parse(run.stdout) as { findings: { ruleId: string; shortName?: string }[] };
    expect(answer.findings).toEqual([
      expect.objectContaining({
        ruleId: 'acme/ticket',
        shortName: 'Acme support ticket reference',
      }),
    ]);
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

  // The vault the SDK resolves through is opened once per module instance, under
  // the home of the first case that reveals; a fresh instance per pane request
  // opens it under this case's home.
  const revealPane = async (items: unknown) => {
    vi.resetModules();
    const fresh = await import('../../src/mod/reveal-run.ts');
    return fresh.runModReveal(JSON.stringify({ v: 1, pane: true, items }));
  };

  it.each(['masked', 'off'] as const)(
    'a pane request reveals under valid consent with reveal %s',
    async (setting) => {
      seed('vault', { vault: true, reveal: setting });
      const minted = JSON.parse((await tokenize({ text: `key ${SECRET}` })).stdout) as {
        text: string;
      };
      const token = minted.text.slice('key '.length);
      const answer = JSON.parse(
        (
          await revealPane([
            { token, reveal: true },
            { token, reveal: false },
          ])
        ).stdout,
      ) as { mode: string; items: { revealed: string | null }[] };
      expect(answer.mode).toBe('full');
      expect(answer.items[0]?.revealed).toBe(`${SECRET} [scrubbed:secret]`);
      expect(answer.items[1]?.revealed).toBeNull();
    },
  );

  it('a pane request without consent answers off and reveals nothing', async () => {
    seed('vault', { vault: false, reveal: 'full' });
    expect(JSON.parse((await revealPane([{ token: UNBACKED, reveal: true }])).stdout)).toEqual({
      v: 1,
      mode: 'off',
      items: [],
    });
  });

  it('a pane request with no items answers the consent alone', async () => {
    seed('vault', { vault: true, reveal: 'masked' });
    expect(JSON.parse((await revealPane([])).stdout)).toEqual({ v: 1, mode: 'full', items: [] });
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
    ) as {
      deny: string | null;
      input: { content: string } | null;
      message: string | null;
      findings: unknown[];
    };
    expect(rewritten.deny).toBeNull();
    expect(JSON.stringify(rewritten.input)).not.toContain(SECRET);
    expect(rewritten.findings).toHaveLength(1);
    expect(rewritten.message).toContain('aka exception approve');
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

  it('leaves no message when it says only what the findings show', async () => {
    seed('vault', { vault: true });
    const answer = JSON.parse(
      (await call({ tool: 'Write', input: { file_path: join(cwd, 'a.txt'), content: SECRET } }))
        .stdout,
    ) as { input: unknown; message: string | null; findings: unknown[] };
    expect(JSON.stringify(answer.input)).not.toContain(SECRET);
    expect(answer.findings).toHaveLength(1);
    expect(answer.message).toBeNull();
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
