import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { MaskedSecretFinding } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import {
  buildChecklistEntries,
  generateRotationChecklist,
  renderChecklistMarkdown,
  resolveRotationChecklistTarget,
  writeRotationChecklist,
} from '../../src/remediation/rotation-checklist.ts';

const RAW_FIXTURE_VALUES = [
  ['sk', '_live_', '51N4exampleRawStripeValue'].join(''),
  ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
  ['ghp_', 'exampleRawGithubTokenValue123456'].join(''),
  ['mystery_', 'exampleRawProviderTokenValue'].join(''),
  ['unknown_', 'exampleRawProviderTokenValue'].join(''),
] as const;

function finding(
  provider: string,
  maskedToken: string,
  filePath: string,
  observedAt?: string,
): MaskedSecretFinding {
  return {
    provider,
    maskedToken,
    where: { filePath },
    state: 'unknown',
    ...(observedAt === undefined ? {} : { observedAt }),
  };
}

const findings: readonly MaskedSecretFinding[] = [
  finding('stripe', 'sk_live_…4f2c', '/transcripts/stripe-a.jsonl'),
  finding('stripe', 'sk_live_…4f2c', '/transcripts/stripe-b.jsonl'),
  finding('aws', 'AKIA…MPLE', '/transcripts/aws-a.jsonl', '2026-04-03T00:00:00Z'),
  finding('aws', 'AKIA…MPLE', '/transcripts/aws-b.jsonl', '2026-03-01T00:00:00Z'),
  finding('aws', 'AKIA…MPLE', '/transcripts/aws-c.jsonl', '2026-04-01T00:00:00Z'),
  finding('aws', 'AKIA…MPLE', '/transcripts/aws-c.jsonl', '2026-02-01T00:00:00Z'),
  finding('mysteryvendor', 'mystery_…alue', '/transcripts/mystery-a.jsonl', '2026-01-01T00:00:00Z'),
  finding('mysteryvendor', 'mystery_…alue', '/transcripts/mystery-b.jsonl', '2026-03-01T00:00:00Z'),
  finding('unknown', 'unknown_…alue', '/transcripts/unknown-a.jsonl', '2026-02-01T00:00:00Z'),
  finding('unknown', 'unknown_…alue', '/transcripts/unknown-b.jsonl', '2026-02-02T00:00:00Z'),
  finding('github', 'ghp_…3456', '/transcripts/github.jsonl', '2026-01-01T00:00:00Z'),
  finding('anthropic', 'sk-ant-…wxyz', '/transcripts/anthropic.jsonl', '2026-01-01T00:00:00Z'),
];

describe('rotation checklist', () => {
  const temporaryDirectories: string[] = [];

  afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('groups leaked keys and orders them by spread, age, then provider and token', () => {
    const entries = buildChecklistEntries(findings);

    expect(
      entries.map(({ provider, maskedToken, occurrenceSpread }) => ({
        provider,
        maskedToken,
        occurrenceSpread,
      })),
    ).toEqual([
      { provider: 'aws', maskedToken: 'AKIA…MPLE', occurrenceSpread: 3 },
      { provider: 'mysteryvendor', maskedToken: 'mystery_…alue', occurrenceSpread: 2 },
      { provider: 'unknown', maskedToken: 'unknown_…alue', occurrenceSpread: 2 },
      { provider: 'stripe', maskedToken: 'sk_live_…4f2c', occurrenceSpread: 2 },
      { provider: 'anthropic', maskedToken: 'sk-ant-…wxyz', occurrenceSpread: 1 },
      { provider: 'github', maskedToken: 'ghp_…3456', occurrenceSpread: 1 },
    ]);
  });

  it('renders recognized provider paths and generic fallback entries without raw values', () => {
    const markdown = renderChecklistMarkdown(buildChecklistEntries(findings));

    expect(markdown).toContain(
      '- [ ] stripe — sk_live_…4f2c — dashboard.stripe.com → Developers → API keys',
    );
    expect(markdown).toContain(
      "- [ ] mysteryvendor — mystery_…alue — rotate via the provider's own console",
    );
    expect(markdown).toContain(
      "- [ ] unknown — unknown_…alue — rotate via the provider's own console",
    );
    for (const rawValue of RAW_FIXTURE_VALUES) expect(markdown).not.toContain(rawValue);
  });

  it('writes the rendered checklist into the caller-supplied directory', () => {
    const targetDirectory = mkdtempSync(join(tmpdir(), 'aka-rotation-checklist-'));
    temporaryDirectories.push(targetDirectory);
    const entries = buildChecklistEntries(findings);

    writeRotationChecklist(entries, targetDirectory);

    const written = readFileSync(join(targetDirectory, 'rotation-checklist.md'), 'utf8');
    expect(written).toBe(renderChecklistMarkdown(entries));
    for (const rawValue of RAW_FIXTURE_VALUES) expect(written).not.toContain(rawValue);
  });

  it('resolves an invocation inside a repository to its root', () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), 'aka-rotation-repo-'));
    temporaryDirectories.push(repositoryRoot);
    mkdirSync(join(repositoryRoot, '.git'));
    const nestedDirectory = join(repositoryRoot, 'packages', 'example');
    mkdirSync(nestedDirectory, { recursive: true });

    expect(resolveRotationChecklistTarget(nestedDirectory)).toEqual({
      directory: repositoryRoot,
      locationLabel: 'repo root',
    });

    const entries = buildChecklistEntries(findings);
    const result = generateRotationChecklist({ entries, cwd: nestedDirectory });

    expect(result).toEqual({
      status: 'written',
      filePath: join(repositoryRoot, 'rotation-checklist.md'),
      locationLabel: 'repo root',
      resolvedLine: '✓ I drafted a rotation checklist for you (repo root).',
    });
    expect(readFileSync(join(repositoryRoot, 'rotation-checklist.md'), 'utf8')).toBe(
      renderChecklistMarkdown(entries),
    );
  });

  it('uses and names the invocation working directory outside a repository', () => {
    const invocationDirectory = mkdtempSync(join(tmpdir(), 'aka-rotation-no-repo-'));
    temporaryDirectories.push(invocationDirectory);

    const entries = buildChecklistEntries(findings);
    const result = generateRotationChecklist({ entries, cwd: invocationDirectory });

    expect(result).toEqual({
      status: 'written',
      filePath: join(invocationDirectory, 'rotation-checklist.md'),
      locationLabel: `invocation working directory: ${invocationDirectory}`,
      resolvedLine: `✓ I drafted a rotation checklist for you (invocation working directory: ${invocationDirectory}).`,
    });
    expect(readFileSync(join(invocationDirectory, 'rotation-checklist.md'), 'utf8')).toBe(
      renderChecklistMarkdown(entries),
    );
  });

  it('degrades honestly without throwing when the checklist cannot be written', () => {
    const parentDirectory = mkdtempSync(join(tmpdir(), 'aka-rotation-failure-'));
    temporaryDirectories.push(parentDirectory);
    const fileAsWorkingDirectory = join(parentDirectory, 'not-a-directory');
    writeFileSync(fileAsWorkingDirectory, 'occupied', 'utf8');

    expect(() =>
      generateRotationChecklist({
        entries: buildChecklistEntries(findings),
        cwd: fileAsWorkingDirectory,
      }),
    ).not.toThrow();
    expect(
      generateRotationChecklist({
        entries: buildChecklistEntries(findings),
        cwd: fileAsWorkingDirectory,
      }),
    ).toEqual({
      status: 'degraded',
      note: `Could not draft rotation-checklist.md at ${fileAsWorkingDirectory}.`,
    });
  });
});
