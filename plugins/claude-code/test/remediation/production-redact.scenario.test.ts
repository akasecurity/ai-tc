import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, dataDir, openLocalDatabase } from '@akasecurity/persistence';
import type { PluginRuntime } from '@akasecurity/plugin-sdk';
import { createVaultGlue, safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type { MaskedSecretFinding } from '@akasecurity/schema';
import { pointerTokenScanner, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// A toggle a single test flips to make the adapter's runtime `close()` throw —
// every other test leaves it off, so the real teardown path still runs
// everywhere else in this suite. `vi.hoisted` makes it exist before the mock
// factory below runs.
const { runtimeCloseShouldThrow } = vi.hoisted(() => ({
  runtimeCloseShouldThrow: { value: false },
}));

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const realCreatePluginRuntime = actual.createPluginRuntime as (
    ...args: unknown[]
  ) => PluginRuntime;
  return {
    ...actual,
    createPluginRuntime: (...args: unknown[]): PluginRuntime => {
      const runtime = realCreatePluginRuntime(...args);
      return {
        ...runtime,
        close: async () => {
          if (runtimeCloseShouldThrow.value) throw new Error('simulated runtime close fault');
          await runtime.close();
        },
      };
    },
  };
});

import { deriveProvider } from '@akasecurity/setup-wizard';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { redactSurfacedSecrets } from '../../src/remediation/surfaced-redact.ts';

// The PRODUCTION redaction adapter: unlike `redactLeakedKeys`,
// which trusts whatever `RedactionScope` a caller builds, `redactSurfacedSecrets`
// derives its own transcript/temp artifact scope and refuses a caller's attempt
// to widen it into a project working tree. This suite proves both halves: a
// legitimately-supplied temp root is honoured (genuine transcript/temp artifacts
// are redacted), and a project root passed off as the temp scope is rejected —
// the project file is left byte-identical no matter how it is offered.

const AWS_RULE_ID = 'secrets/aws-access-key';
const PROVIDER = deriveProvider(AWS_RULE_ID);

// Canonical test AWS access-key ids, composed at runtime so the repo's own secret
// scan does not flag this file (mirrors redact.test.ts and redact-only.scenario.test.ts).
// Each passes the real detection engine's entropy validator (proven already by
// history/scan.test.ts, which runs the same values through the same engine).
const TRANSCRIPT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

function findingFor(filePath: string, rawValue: string): MaskedSecretFinding {
  return {
    provider: PROVIDER,
    maskedToken: safeMaskedMatch(rawValue),
    where: { filePath },
    state: 'unknown',
  };
}

// Record a valid vault consent in the throwaway ~/.aka the adapter reads —
// what flips the strike from the one-way placeholder to recoverable pointers.
function grantVaultConsent(base: string): void {
  applyOnboarding(
    { vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION } },
    base,
  );
}

describe('redactSurfacedSecrets — the production redaction adapter', () => {
  // A throwaway HOME (transcripts live at `<home>/.claude/projects/...`, exactly
  // what `transcriptsDir` derives) and a throwaway `~/.aka` base for the runtime's
  // local store — so this suite never touches the developer's real machine state.
  let home: string;
  let dataDirBase: string;
  // A genuinely bounded scratch directory a caller could legitimately name as its
  // own temp root, and a directory standing in for a real project working tree
  // (marked with a `.git` entry, exactly like a real repo root) that a caller
  // might — wrongly — try to pass off as that same temp root.
  let legitTempRoot: string;
  let projectRoot: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-prodredact-home-'));
    dataDirBase = mkdtempSync(join(tmpdir(), 'aka-prodredact-store-'));
    legitTempRoot = mkdtempSync(join(tmpdir(), 'aka-prodredact-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-prodredact-project-'));
    mkdirSync(join(projectRoot, '.git'));
  });

  afterEach(() => {
    for (const dir of [home, dataDirBase, legitTempRoot, projectRoot]) {
      removeTree(dir);
    }
  });

  it('redacts genuine transcript and temp artifacts when a legitimate temp root is supplied', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    const tempFile = join(legitTempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);

    const findings = [findingFor(transcriptFile, TRANSCRIPT_KEY), findingFor(tempFile, TEMP_KEY)];

    const result = await redactSurfacedSecrets(findings, {
      home,
      dataDirBase,
      tempRoot: legitTempRoot,
    });

    expect(result.redactedKeys).toBe(2);
    expect(result.unredacted).toEqual([]);
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');
    const tempAfter = readFileSync(tempFile, 'utf8');
    expect(tempAfter).not.toContain(TEMP_KEY);
    expect(tempAfter).toContain('[REDACTED:SECRET]');
  });

  it('rejects a project root offered as the temp scope — no project file is redacted, transcript artifacts still are, and the count reflects only real strikes', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    // The "temp root" this call supplies is actually a project working tree
    // (marked with `.git`) — an attempt to widen redaction beyond the
    // transcript/temp artifact class by mislabeling it.
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);
    const projectListingBefore = readdirSync(projectRoot);

    const projectFinding = findingFor(projectFile, PROJECT_KEY);
    const findings = [findingFor(transcriptFile, TRANSCRIPT_KEY), projectFinding];

    const result = await redactSurfacedSecrets(findings, {
      home,
      dataDirBase,
      tempRoot: projectRoot,
    });

    // Only the genuine transcript artifact was redacted — the project-root scope
    // was refused outright, not partially honoured. The out-of-scope finding is
    // reported back as unredacted, never silently dropped.
    expect(result.redactedKeys).toBe(1);
    expect(result.unredacted).toEqual([projectFinding]);
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');

    // The project file is byte-for-byte unchanged and its directory listing
    // untouched — the rejected scope never widened redaction into it.
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
    expect(readdirSync(projectRoot)).toEqual(projectListingBefore);
  });

  it('returns 0 and touches nothing for an empty findings set', async () => {
    const result = await redactSurfacedSecrets([], { home, dataDirBase });
    expect(result).toEqual({ redactedKeys: 0, pointeredKeys: 0, unredacted: [] });
  });

  it('with vault consent, the strike becomes recoverable pointers — one pointer per distinct value, detokenizable back to the key', async () => {
    grantVaultConsent(dataDirBase);
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const fileA = join(projectDir, 'a.jsonl');
    const fileB = join(projectDir, 'b.jsonl');
    // The SAME key leaked into two transcripts — it must resolve to ONE
    // pointer, substituted in both files.
    writeFileSync(fileA, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);
    writeFileSync(fileB, `{"content":"same key ${TRANSCRIPT_KEY} again"}`);

    const result = await redactSurfacedSecrets(
      [findingFor(fileA, TRANSCRIPT_KEY), findingFor(fileB, TRANSCRIPT_KEY)],
      { home, dataDirBase },
    );

    expect(result.redactedKeys).toBe(2);
    expect(result.pointeredKeys).toBe(2);
    expect(result.unredacted).toEqual([]);

    const afterA = readFileSync(fileA, 'utf8');
    const afterB = readFileSync(fileB, 'utf8');
    for (const after of [afterA, afterB]) {
      expect(after).not.toContain(TRANSCRIPT_KEY);
      expect(after).not.toContain('[REDACTED:SECRET]');
    }
    const pointersA = afterA.match(pointerTokenScanner());
    const pointersB = afterB.match(pointerTokenScanner());
    expect(pointersA).toHaveLength(1);
    // One distinct value → one pointer, identical across both artifacts.
    expect(pointersB).toEqual(pointersA);

    // The pointer is genuinely recoverable: the same store detokenizes it back
    // to the original key.
    const glue = createVaultGlue({ base: dataDirBase });
    const back = await glue.detokenizeText(afterA, { target: 'human', reason: 'display' });
    expect(back.revealed).toBe(1);
    expect(back.text).toBe(`{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);
  });

  // This adapter strikes what a PERSON pointed at, whatever their pack is
  // assigned — see the comment on `buildPointerReplacements`. Anything reading
  // the vault against today's assignment therefore has to be told, or it reads
  // these rows as vaulting nothing authorizes: `aka vault prune` would restore
  // the raw key into this very transcript and destroy the entry.
  it('marks the vault rows it writes as user-authorized, and keeps the mark when a pack path vaults the same key later', async () => {
    grantVaultConsent(dataDirBase);
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    const result = await redactSurfacedSecrets([findingFor(transcriptFile, TRANSCRIPT_KEY)], {
      home,
      dataDirBase,
    });
    // Positive control: the strike really was the recoverable one, so the row
    // below exists because this call vaulted something.
    expect(result.pointeredKeys).toBe(1);

    const marks = (): boolean[] => {
      const db = openLocalDatabase(dataDir(dataDirBase));
      try {
        return db.secretVault.listAll().map((row) => row.userAuthorized);
      } finally {
        db.close();
      }
    };
    expect(marks()).toEqual([true]);

    // The same value vaulted again by an ordinary enforcing path. One value is
    // one row, so this lands on the row above — and what the user said about
    // the value does not expire because a pack saw it again.
    const glue = createVaultGlue({ base: dataDirBase });
    try {
      await glue.tokenizeValue(TRANSCRIPT_KEY, {
        ruleId: AWS_RULE_ID,
        category: 'secret',
        maskedMatch: safeMaskedMatch(TRANSCRIPT_KEY),
      });
    } finally {
      glue.close();
    }

    expect(marks()).toEqual([true]);
  });

  it('without vault consent the strike is byte-identical to the legacy one-way redaction', async () => {
    // No consent is ever granted in this test — the default state of the
    // throwaway store.
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    const result = await redactSurfacedSecrets([findingFor(transcriptFile, TRANSCRIPT_KEY)], {
      home,
      dataDirBase,
    });

    expect(result.redactedKeys).toBe(1);
    expect(result.pointeredKeys).toBe(0);
    expect(result.unredacted).toEqual([]);
    expect(readFileSync(transcriptFile, 'utf8')).toBe(
      '{"content":"a key [REDACTED:SECRET] in a prompt"}',
    );
  });

  it('reports a vanished/unreadable artifact as unredacted rather than silently dropping it', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    // The finding references a transcript path inside the enforced scope that was
    // never actually written — mirrors a vanished/unreadable artifact at
    // redact-time, distinct from an out-of-scope path.
    const vanishedFinding = findingFor(transcriptFile, TRANSCRIPT_KEY);

    const result = await redactSurfacedSecrets([vanishedFinding], { home, dataDirBase });

    expect(result.redactedKeys).toBe(0);
    expect(result.unredacted).toEqual([vanishedFinding]);
  });

  it('reports a finding whose content changed since the calibration scan as unredacted, not silently dropped', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    // The artifact exists and is readable, but no longer contains the key the
    // finding references — the re-scan at redact-time finds no matching occurrence.
    writeFileSync(transcriptFile, 'this transcript no longer contains the leaked key');
    const staleFinding = findingFor(transcriptFile, TRANSCRIPT_KEY);

    const result = await redactSurfacedSecrets([staleFinding], { home, dataDirBase });

    expect(result.redactedKeys).toBe(0);
    expect(result.unredacted).toEqual([staleFinding]);
  });

  it('a runtime close() fault after targets were recovered does not drop them — the strike still lands and the count still reports it', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);
    const finding = findingFor(transcriptFile, TRANSCRIPT_KEY);

    runtimeCloseShouldThrow.value = true;
    try {
      const result = await redactSurfacedSecrets([finding], { home, dataDirBase });

      // The teardown fault must not rewrite the outcome: the target was
      // recovered and struck before close() ever ran, so it stays reported as
      // redacted rather than being dropped to a false "0 keys" / "unredacted".
      expect(result.redactedKeys).toBe(1);
      expect(result.unredacted).toEqual([]);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).not.toContain(TRANSCRIPT_KEY);
      expect(after).toContain('[REDACTED:SECRET]');
    } finally {
      runtimeCloseShouldThrow.value = false;
    }
  });
});
