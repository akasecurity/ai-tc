/**
 * The retained raw-free plan file.
 *
 * The setup wizard's confirm gate is only *binding* if `--confirmed` applies the
 * EXACT plan the user previewed. The previous flow re-ran the backfill and the
 * non-deterministic judge on confirm, so the user approved plan A while a freshly
 * derived plan B was written — silently defeating both the human FP gate and the
 * enforcement-downgrade surfacing. To close that, PREVIEW persists the resolved,
 * raw-free plan here and prints the path; `--confirmed --plan <path>` reads it
 * back and applies it verbatim — no re-scan, no re-judge. The file is deleted
 * after a successful apply.
 *
 * RAW SAFETY: every field is already raw-free by construction — entries/join came
 * through the raw-egress gate (join-file.ts), posture/current are enums, notes
 * were scrubbed in planTriageWriteback. As a backstop we serialize the whole
 * document and run assertRawFree over the exact bytes against the raw hit values
 * before anything touches disk: a leaked raw value fails the write
 * LOUDLY rather than persisting a secret to a temp file.
 */
import { mkdtempSync, readFileSync, rmdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';

import { assertRawFree } from '@akasecurity/plugin-sdk';
import { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { z } from 'zod';

import type { TriageWritebackPlan } from './writeback.ts';

// Mirrors SuppressionEntry (plugin-sdk) — a plain interface there, given a zod
// shape here so a persisted plan is validated on the way back in.
const SuppressionEntrySchema = z.object({
  ruleId: z.string(),
  category: DetectionCategory,
  valueFingerprint: z.string(),
  keyVersion: z.number(),
  maskedValue: z.string(),
  justification: z.string(),
});

// Mirrors ShowcaseCategory (writeback.ts) — the per-category showcase. Every
// field is raw-free by construction: reasoning was assertRawFree'd before it
// entered the plan, counts are numbers, action/category are enums.
const ShowcaseCategorySchema = z.object({
  category: DetectionCategory,
  action: BuiltinPolicyId,
  genuineCount: z.number(),
  fpCount: z.number(),
  reasoning: z.string(),
});

// Mirrors JoinEntry (join-file.ts).
const JoinEntrySchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  category: DetectionCategory,
  valueFingerprint: z.string().optional(),
  keyVersion: z.number().optional(),
  maskedMatch: z.string(),
  maskedContext: z.string(),
});

// Bump when the on-disk shape changes; readPlanFile rejects any other version so
// a stale file from an older plugin can never be replayed against newer apply
// logic. v3 dropped the unverified `token` field.
export const PLAN_FILE_VERSION = 3;

export const PersistedPlanSchema = z.object({
  version: z.literal(PLAN_FILE_VERSION),
  // partialRecord (not record): a posture only covers the categories present in
  // the evidence, so an exhaustive-key record would reject every real plan.
  posture: z.partialRecord(DetectionCategory, BuiltinPolicyId),
  entries: z.array(SuppressionEntrySchema),
  showcase: z.array(ShowcaseCategorySchema),
  join: z.array(JoinEntrySchema),
  notes: z.string(),
  // The store's per-category action at preview time. The downgrade view is
  // rendered from it at PREVIEW (renderPosturePlan); confirm reads it back ONLY to
  // compare against the live store and reject a stale plan (runConfirm's drift gate).
  current: z.partialRecord(DetectionCategory, ActionTaken),
});
export type PersistedPlan = z.infer<typeof PersistedPlanSchema>;

// Serialize a resolved plan + preview-time posture snapshot to its on-disk JSON.
// Split out so the raw-free backstop runs over the exact bytes to be written.
export function serializePlan(
  plan: TriageWritebackPlan,
  current: PersistedPlan['current'],
): string {
  const doc: PersistedPlan = {
    version: PLAN_FILE_VERSION,
    posture: plan.posture,
    entries: plan.entries,
    showcase: plan.showcase,
    join: plan.join,
    notes: plan.notes,
    current,
  };
  return JSON.stringify(doc, null, 2);
}

export interface WritePlanDeps {
  // Injectable for tests; default mints a fresh 0700 temp dir.
  mkTempDir?: () => string;
}

// Persist the resolved raw-free plan to a fresh temp file and return its path.
// BACKSTOP: assert the serialized document carries no raw hit value before it
// touches disk. The plan is raw-free by construction; this re-verifies at the
// persistence boundary and fails loud on any leak rather than writing a secret.
export function writePlanFile(
  plan: TriageWritebackPlan,
  current: PersistedPlan['current'],
  rawValues: readonly string[],
  deps: WritePlanDeps = {},
): string {
  const serialized = serializePlan(plan, current);
  // Throws RawEgressError if any raw value survived into the document.
  assertRawFree(serialized, rawValues);
  const dir = (deps.mkTempDir ?? (() => mkdtempSync(join(tmpdir(), 'aka-plan-'))))();
  const path = join(dir, 'setup-plan.json');
  writeFileSync(path, serialized, { encoding: 'utf8', mode: 0o600 });
  return path;
}

// Read + validate a persisted plan. Throws (never returns a partial) on a
// missing/unreadable file, malformed JSON, or a schema violation — so the
// confirm path fails loud instead of silently falling back to a re-judge.
export function readPlanFile(path: string): PersistedPlan {
  const text = readFileSync(path, 'utf8');
  const json: unknown = JSON.parse(text);
  return PersistedPlanSchema.parse(json);
}

// Remove the plan file after a successful apply (design: "deleted after apply"),
// then clean up its dedicated temp dir — but ONLY the file itself is removed
// unconditionally. The confirm path takes `--plan <path>` from user argv, so the
// parent directory is NOT ours to delete: we rmdir it only when it is a dir
// writePlanFile actually minted (an `aka-plan-*` mkdtemp) AND now empty. A
// user-supplied path in any other directory therefore never loses its parent or
// its neighbours — the old `rmSync(dirname, { recursive })` would have wiped the
// lot. `force` on the file unlink so an already-gone path is idempotent (`path`
// is always a validated file here — readPlanFile rejects a directory upstream).
export function deletePlanFile(path: string): void {
  rmSync(path, { force: true });
  const dir = dirname(path);
  if (!basename(dir).startsWith('aka-plan-')) return;
  try {
    rmdirSync(dir);
  } catch {
    // Already gone, or (defensively) not empty — leave the directory be.
  }
}
