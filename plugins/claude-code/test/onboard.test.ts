import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase, readWorkspaceSettings } from '@akasecurity/persistence';
import {
  applyCategoryPosture,
  applyOnboarding,
  severityFloorPosture,
} from '@akasecurity/plugin-sdk';
import { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { parsePosture } from '../src/onboard-posture.ts';
import { parseSurface } from '../src/setup-show.ts';
import { isModelJudgeConsentValid, MODEL_JUDGE_PAYLOAD_VERSION } from '../src/triage/consent.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/claude-code
const SCRIPT = join(HERE, '..', 'scripts', 'onboard.js');

interface Run {
  stdout: string;
  stderr: string;
  status: number;
}

// Runs the BUILT script the wizard actually shells out to, against a fresh,
// throwaway ~/.aka home per call so this suite's assertions stay independent
// of the real machine's store (mirrors start-light.test.ts's runStartLight).
function onboardRun(args: string[] = []): Run {
  const home = mkdtempSync(join(tmpdir(), 'aka-onboard-run-test-'));
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      env: { HOME: home, USERPROFILE: home },
      encoding: 'utf8',
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// The recommended-posture default map, frozen here so the test fails loudly if
// severityFloorPosture() ever drifts from it (the "unchanged from before the
// redesign" guarantee).
const RECOMMENDED_DEFAULTS = {
  secret: 'warn',
  pii: 'warn',
  financial: 'warn',
  phi: 'warn',
  code_flaw: 'warn',
  custom: 'warn',
  code_context: 'monitor',
  config: 'monitor',
} as const;

describe('recommended (unadjusted) posture — the default map', () => {
  it('severityFloorPosture() equals the recommended defaults exactly', () => {
    // Reuse the schema helper the onboard path already writes on `--floor`; do not
    // introduce a parallel constant.
    expect(severityFloorPosture()).toEqual(RECOMMENDED_DEFAULTS);
  });

  it('seeds exactly 8 packs, each at a valid palette level', () => {
    const posture = severityFloorPosture();
    expect(Object.keys(posture).sort()).toEqual([...DetectionCategory.options].sort());
    expect(Object.keys(posture)).toHaveLength(8);
    for (const level of Object.values(posture)) {
      expect(BuiltinPolicyId.safeParse(level).success).toBe(true);
    }
  });

  it('round-trips through the onboard --posture seam (parsePosture)', () => {
    // onboard.ts feeds `--posture <json>` through parsePosture; the recommended
    // map must survive that path unchanged so the wizard can drive it.
    const posture = severityFloorPosture();
    expect(parsePosture(JSON.stringify(posture))).toEqual(RECOMMENDED_DEFAULTS);
  });
});

describe('onboard writes a valid store/settings state with the recommended posture', () => {
  let base: string;
  let db: LocalDatabase;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-onboard-test-'));
    // The same real local store onboard.ts opens via openLocalDatabase(dataDir).
    db = openLocalDatabase(join(base, 'data'));
  });

  afterEach(() => {
    db.close();
    rmSync(base, { recursive: true, force: true });
  });

  it('applyOnboarding writes a valid settings.json (session-only historical access)', () => {
    const written = applyOnboarding({ historicalAccess: 'session-only' }, base);
    expect(written.historicalAccess).toBe('session-only');
    expect(written.onboardedAt).not.toBeNull();
    // Re-read from disk through the versioned schema — proves the file parses.
    const read = readWorkspaceSettings(base);
    expect(read.historicalAccess).toBe('session-only');
    expect(read.onboardedAt).not.toBeNull();
  });

  it('applyCategoryPosture persists the recommended map as 8 category rows (monitor→log)', async () => {
    applyCategoryPosture(severityFloorPosture(), db.policies, 'overwrite');
    const rows = await db.policies.readPolicies();
    const byCategory = new Map(
      rows
        .map((p) => [(p.target as { category?: string }).category, p.action] as const)
        .filter(([c]) => c !== undefined),
    );
    expect(byCategory.size).toBe(8);
    // warn packs store as 'warn'; monitor packs store as 'log' (the palette→
    // ActionTaken mapping), which surfaces back to the user as 'monitor'.
    expect(byCategory.get('secret')).toBe('warn');
    expect(byCategory.get('pii')).toBe('warn');
    expect(byCategory.get('financial')).toBe('warn');
    expect(byCategory.get('phi')).toBe('warn');
    expect(byCategory.get('code_flaw')).toBe('warn');
    expect(byCategory.get('custom')).toBe('warn');
    expect(byCategory.get('code_context')).toBe('log');
    expect(byCategory.get('config')).toBe('log');
  });

  it('the severity-floor fill-gaps write never downgrades an already-calibrated pack', () => {
    // The `--floor` fallback path onboard.ts takes on a too-thin backfill uses the
    // SAME map (severityFloorPosture) in fill-gaps mode: a confirmed calibration is
    // preserved. This behavior is unchanged by the redesign.
    db.policies.upsertCategoryAction('secret', 'block');
    applyCategoryPosture(severityFloorPosture(), db.policies, 'fill-gaps');
    expect(db.policies.getCategoryAction('secret')).toBe('block');
    // code_context keeps the default the store seeds on open ('log'); fill-gaps
    // never downgrades the already-calibrated 'secret' row.
    expect(db.policies.getCategoryAction('code_context')).toBe('log');
  });
});

describe('onboard --model-judge-consent records the distinct model-judge egress consent', () => {
  // Runs the BUILT script against a home dir it does NOT delete before reading,
  // so the persisted settings.json can be re-read through the versioned schema.
  function onboardRunKeepingHome(args: string[]): string {
    const home = mkdtempSync(join(tmpdir(), 'aka-onboard-consent-test-'));
    try {
      execFileSync(process.execPath, [SCRIPT, ...args], {
        env: { HOME: home, USERPROFILE: home },
        encoding: 'utf8',
      });
      // The script resolves ~/.aka from HOME, so the settings.json lands under
      // <home>/.aka — read it back through the versioned schema from there.
      const read = readWorkspaceSettings(join(home, '.aka'));
      return JSON.stringify(read);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }

  it('persists modelJudgeConsent at the current payload version, and it reads back as valid', () => {
    const settings = JSON.parse(onboardRunKeepingHome(['--model-judge-consent'])) as {
      modelJudgeConsent?: { acknowledgedAt: string; payloadVersion: number };
    };
    expect(settings.modelJudgeConsent?.payloadVersion).toBe(MODEL_JUDGE_PAYLOAD_VERSION);
    expect(settings.modelJudgeConsent?.acknowledgedAt).toEqual(expect.any(String));
    expect(isModelJudgeConsentValid(settings.modelJudgeConsent)).toBe(true);
  });

  it('leaves modelJudgeConsent absent when the flag is not passed', () => {
    const settings = JSON.parse(onboardRunKeepingHome(['--historical', 'session-only'])) as {
      modelJudgeConsent?: unknown;
    };
    expect(settings.modelJudgeConsent).toBeUndefined();
    expect(isModelJudgeConsentValid(undefined)).toBe(false);
  });
});

describe('onboard emits user-facing output inside SHOW regions', () => {
  it('--historical full wraps the warm confirmation as a SHOW region', () => {
    const run = onboardRun(['--historical', 'full']);
    const surface = parseSurface(run.stdout);
    expect(surface.shows.join('\n')).toContain("Got it — I'll look over Claude's recent work");
    expect(surface.status).not.toContain("Got it — I'll look over");
  });

  it('--floor wraps the applied-posture confirmation as a SHOW region', () => {
    const run = onboardRun(['--floor']);
    const surface = parseSurface(run.stdout);
    expect(surface.shows.join('\n')).toContain('safe defaults');
    expect(surface.status).not.toContain('safe defaults');
  });
});
