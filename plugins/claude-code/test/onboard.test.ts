import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
