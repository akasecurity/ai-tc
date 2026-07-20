import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { MaskedSecretFinding } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import { resolveRemediationDeliverable } from '../../src/remediation/deliverable.ts';
import { renderChecklistMarkdown } from '../../src/remediation/rotation-checklist.ts';

const RAW_VALUES = [
  ['sk', '_live_', 'exampleRawStripeOne'].join(''),
  ['sk', '_live_', 'exampleRawStripeTwo'].join(''),
  ['AKIA', 'EXAMPLERAWVALUE'].join(''),
] as const;

const findings: readonly MaskedSecretFinding[] = [
  {
    provider: 'stripe',
    maskedToken: 'sk_live_…one',
    where: { filePath: '/transcripts/one.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-03T00:00:00Z',
  },
  {
    provider: 'aws',
    maskedToken: 'AKIA…ALUE',
    where: { filePath: '/transcripts/one.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-01T00:00:00Z',
  },
  {
    provider: 'stripe',
    maskedToken: 'sk_live_…two',
    where: { filePath: '/transcripts/two.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-02T00:00:00Z',
  },
];

describe('resolveRemediationDeliverable', () => {
  const temporaryDirectories: string[] = [];

  afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('writes and summarizes one masked, ordered checklist model', () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), 'aka-deliverable-repo-'));
    temporaryDirectories.push(repositoryRoot);
    mkdirSync(join(repositoryRoot, '.git'));
    const invocationDirectory = join(repositoryRoot, 'packages', 'fixture');
    mkdirSync(invocationDirectory, { recursive: true });

    const result = resolveRemediationDeliverable({
      findings,
      redactedKeys: 3,
      cwd: invocationDirectory,
    });

    expect(result.writeResult.status).toBe('written');
    if (result.writeResult.status !== 'written') throw new Error('expected checklist write');

    const markdown = readFileSync(result.writeResult.filePath, 'utf8');
    expect(markdown).toBe(renderChecklistMarkdown(result.entries));
    expect(result.entries.map((entry) => entry.maskedToken)).toEqual([
      'AKIA…ALUE',
      'sk_live_…two',
      'sk_live_…one',
    ]);
    expect(result.summary).toContain('✓ Redacted 3 keys across 2 transcripts');
    expect(result.summary).toContain('✓ Drafted rotation-checklist.md (repo root)');

    const previewLines = result.summary.split('\n').filter((line) => line.startsWith('- [ ] '));
    expect(previewLines).toEqual(renderChecklistMarkdown(result.entries).trimEnd().split('\n'));
    for (const rawValue of RAW_VALUES) {
      expect(markdown).not.toContain(rawValue);
      expect(result.summary).not.toContain(rawValue);
    }
  });

  it('returns an honest degraded note without throwing when the target cannot be written', () => {
    const failureRoot = mkdtempSync(join(tmpdir(), 'aka-deliverable-failure-'));
    temporaryDirectories.push(failureRoot);
    const missingTarget = join(failureRoot, 'missing-parent', 'invocation');

    expect(() =>
      resolveRemediationDeliverable({ findings, redactedKeys: 3, cwd: missingTarget }),
    ).not.toThrow();

    const result = resolveRemediationDeliverable({
      findings,
      redactedKeys: 3,
      cwd: missingTarget,
    });
    expect(result.writeResult).toEqual({
      status: 'degraded',
      note: `Could not draft rotation-checklist.md at ${missingTarget}.`,
    });
    expect(result.summary).toContain(`Could not draft rotation-checklist.md at ${missingTarget}.`);
    expect(result.summary).not.toContain('✓ Drafted rotation-checklist.md');
  });
});
