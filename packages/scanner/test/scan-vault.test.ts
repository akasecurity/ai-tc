import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { scanWorktree } from '../src/scan.ts';

// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + ['R7XM', '2QTB', '9KZP', '4HWN'].join('');
const POINTER = /\[\[aka:[a-z_]+:[A-Z0-9]+\.[A-Z2-7]+\.[A-Z2-7]+\]\]/g;

const line = (value: string): string => `export const AWS_ACCESS_KEY_ID = '${value}';\n`;

let home: string;
let repo: string;

function configWith(consent: boolean): PluginConfig {
  mkdirSync(join(home, 'settings'), { recursive: true });
  writeFileSync(
    join(home, 'settings', 'settings.json'),
    JSON.stringify(
      consent ? { vaultConsent: { acknowledgedAt: new Date().toISOString(), version: 1 } } : {},
    ),
  );
  return loadConfig(home);
}

function query<T>(config: PluginConfig, sql: string): T[] {
  const raw = new DatabaseSync(config.dbPath, { readOnly: true });
  try {
    return raw.prepare(sql).all() as unknown as T[];
  } finally {
    raw.close();
  }
}

const vaultRows = (config: PluginConfig): { pointer_id: string; variable_name: string | null }[] =>
  query(config, 'SELECT pointer_id, variable_name FROM secret_vault');

const sightings = (
  config: PluginConfig,
): { pointer_id: string; location: string; kind: string }[] =>
  query(config, 'SELECT pointer_id, location, kind FROM secret_vault_sighting');

const storedContents = (config: PluginConfig): string[] =>
  query<{ content: string }>(
    config,
    `SELECT content FROM audit_events WHERE event_type = 'code_change' ORDER BY rowid`,
  ).map((row) => row.content);

const findingKeys = (config: PluginConfig): string[] =>
  query<{ finding_key: string }>(config, 'SELECT finding_key FROM inspection_findings')
    .map((row) => row.finding_key)
    .sort();

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-scan-vault-home-'));
  repo = mkdtempSync(join(tmpdir(), 'aka-scan-vault-repo-'));
});

afterEach(() => {
  removeTrees([home, repo]);
});

describe('scanWorktree — vault', () => {
  it('vaults a detected secret once with a file sighting and stores the pointer in its place', async () => {
    const config = configWith(true);
    const file = join(repo, 'deploy.ts');
    writeFileSync(file, line(VALUE));

    const summary = await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    expect(summary.findings).toBeGreaterThan(0);

    const rows = vaultRows(config);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.variable_name).toBe('AWS_ACCESS_KEY_ID');

    const [content] = storedContents(config);
    expect(content).not.toContain(VALUE);
    const pointers = [...(content ?? '').matchAll(POINTER)].map((m) => m[0]);
    expect(pointers).toHaveLength(1);
    expect(content).toBe(line(pointers[0] ?? ''));

    expect(sightings(config)).toEqual([
      { pointer_id: rows[0]?.pointer_id, location: file, kind: 'file' },
    ]);
  });

  it('keeps finding keys and adds no rows when the file is scanned again', async () => {
    const plain = configWith(false);
    writeFileSync(join(repo, 'deploy.ts'), line(VALUE));
    await scanWorktree(plain, { rootDir: repo, sourceTool: 'claude-code' });
    const keys = findingKeys(plain);

    const config = configWith(true);
    // A changed file is read again rather than skipped as unchanged.
    writeFileSync(join(repo, 'deploy.ts'), `${line(VALUE)}\n`);
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(findingKeys(config)).toEqual(keys);
    expect(vaultRows(config)).toHaveLength(1);
    expect(sightings(config)).toHaveLength(1);
  });

  it('reuses the row a hook already vaulted for the same value', async () => {
    const config = configWith(true);
    const hook = createVaultGlue({ base: home });
    try {
      await hook.tokenizeText(`use ${VALUE}`, {
        sighting: { location: 'prompt', kind: 'prompt' },
        findings: [
          {
            ruleId: 'secrets/aws-access-key',
            category: 'secret',
            severity: 'critical',
            rawMatch: VALUE,
            confidence: 0.9,
            span: { start: 4, end: 4 + VALUE.length },
          },
        ],
      });
    } finally {
      hook.close();
    }

    writeFileSync(join(repo, 'deploy.ts'), line(VALUE));
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(vaultRows(config)).toHaveLength(1);
    expect(
      sightings(config)
        .map((s) => s.kind)
        .sort(),
    ).toEqual(['file', 'prompt']);
  });

  it('re-reads an unchanged file once consent is granted and vaults it', async () => {
    writeFileSync(join(repo, 'deploy.ts'), line(VALUE));
    await scanWorktree(configWith(false), { rootDir: repo, sourceTool: 'claude-code' });

    const config = configWith(true);
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(vaultRows(config)).toHaveLength(1);
    const contents = storedContents(config);
    expect(contents.at(-1)).not.toContain(VALUE);
    expect([...(contents.at(-1) ?? '').matchAll(POINTER)]).toHaveLength(1);
  });

  it('records a file sighting for an identical file at a second path', async () => {
    const config = configWith(true);
    const first = join(repo, 'deploy.ts');
    const second = join(repo, 'copy', 'deploy.ts');
    mkdirSync(join(repo, 'copy'));
    writeFileSync(first, line(VALUE));
    writeFileSync(second, line(VALUE));

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(vaultRows(config)).toHaveLength(1);
    expect(
      sightings(config)
        .map((s) => s.location)
        .sort(),
    ).toEqual([first, second].sort());
  });

  it('records a sighting for a second path whose content an earlier scan recorded', async () => {
    const config = configWith(true);
    const first = join(repo, 'deploy.ts');
    writeFileSync(first, line(VALUE));
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    const second = join(repo, 'later.ts');
    writeFileSync(second, line(VALUE));
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(
      sightings(config)
        .map((s) => s.location)
        .sort(),
    ).toEqual([first, second].sort());
  });

  it('mints nothing and stores the file as read without vault consent', async () => {
    const config = configWith(false);
    const text = line(VALUE);
    writeFileSync(join(repo, 'deploy.ts'), text);

    const summary = await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(summary.findings).toBeGreaterThan(0);
    expect(vaultRows(config)).toHaveLength(0);
    expect(storedContents(config)).toEqual([text]);
  });
});
