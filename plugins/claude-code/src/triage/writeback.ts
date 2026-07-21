/**
 * Setup-triage FP writeback orchestration — the PURE, unit-testable
 * core that the `apply-suppressions` adapter script wires to real IO.
 *
 * Flow: parse the raw --triage stream -> build raw-free join entries + take the
 * model verdict -> raw-reject the model's per-category reasoning and notes
 * (fail-secure) -> resolve to SuppressionEntry[] (fail-secure) -> derive
 * the per-category posture. The two destructive writes are a separate step that
 * takes the already-resolved plan, so confirmation stays explicit and testable.
 *
 * RAW SAFETY: the model reasoning (persisted as an exception justification and
 * shown in the human gate) and the top-level notes are model-authored free text.
 * Prompt discipline is defence-in-depth, not the guarantee — so before either is
 * displayed or persisted we run assertRawFree over it against the raw hit values.
 * On a violation we fail secure: a category whose reasoning echoed a raw value is
 * distrusted wholesale (no suppression, no posture), and poisoned notes are
 * scrubbed rather than surfaced.
 */
import {
  applyCategoryPosture,
  applySetupTriageSuppressions,
  assertRawFree,
  type ExceptionWriter,
  RawEgressError,
  severityFloorPosture,
  type SuppressionEntry,
} from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  BuiltinPolicyId,
  DetectionCategory,
  TriageRecommendation,
} from '@akasecurity/schema';
import { TriageHit } from '@akasecurity/schema';

import { buildJoinEntries, type JoinEntry } from './join-file.ts';
import { resolveSuppressions } from './resolve.ts';

// Placeholder substituted for model notes that referenced a raw detected value.
// Kept as a stable constant so the adapter and its tests agree on the marker.
export const SCRUBBED_NOTES = '[notes withheld: model text referenced a raw detected value]';

// -------------------------------------------------------------------------
// parseTriageStream
// -------------------------------------------------------------------------

// The --triage stream terminator (mirrors backfill.ts's triageSentinel). Its
// presence is the ONLY proof the stream was not truncated mid-scan. The status
// set MUST stay in lockstep with backfill.ts's producer TriageStatus — a value
// one side emits and the other doesn't is a silent skew (see isKnownStatus).
// `complete:no-history` is a completed, non-truncated scan over an empty history
// set (no hits to act on), passed through so the adapter can branch on it.
export const TRIAGE_STATUSES = ['complete', 'complete:no-history', 'skipped:no-consent'] as const;
type TriageStatus = (typeof TRIAGE_STATUSES)[number];

// `status` is only shape-checked (string) here; parseTriageStream validates it
// against TRIAGE_STATUSES via isKnownStatus and fails loud on anything else.
interface Sentinel {
  done: true;
  count: number;
  status: string;
}

function isSentinel(v: unknown): v is Sentinel {
  return (
    typeof v === 'object' &&
    v !== null &&
    (v as { done?: unknown }).done === true &&
    typeof (v as { count?: unknown }).count === 'number' &&
    typeof (v as { status?: unknown }).status === 'string'
  );
}

function isKnownStatus(status: string): status is TriageStatus {
  return (TRIAGE_STATUSES as readonly string[]).includes(status);
}

// Parse a completed `backfill --triage` stream into validated TriageHits. The
// stream is JSONL (one TriageHit per line) terminated by a sentinel; a stream
// with no sentinel is a truncated (crashed/EPIPE) scan and MUST fail loud rather
// than be mistaken for a clean zero-hit result (see backfill.ts). A
// `skipped:*` sentinel means the scan intentionally produced nothing.
export function parseTriageStream(text: string): { hits: TriageHit[]; status: TriageStatus } {
  const lines = text.split('\n').filter((l) => l.trim() !== '');
  const last = lines.at(-1);
  if (last === undefined) {
    throw new Error('triage stream is empty (no sentinel): treating as truncated, not zero-hit');
  }
  // The stream lines carry RAW hit values; a JSON.parse failure echoes the
  // offending line in its SyntaxError, so never let that error propagate — a
  // truncated last line is exactly the (raw-bearing) case we must not leak.
  let tail: unknown;
  try {
    tail = JSON.parse(last);
  } catch {
    throw new Error('triage stream final line is not valid JSON — refusing a truncated stream');
  }
  if (!isSentinel(tail)) {
    throw new Error('triage stream has no completion sentinel — refusing a truncated stream');
  }
  // A sentinel-shaped line whose status we don't recognise (a version-skewed or
  // corrupted producer) must fail LOUD — never be quietly converted into a clean
  // zero-hit "skip", which would tell the user their history was cleanly triaged
  // when the scan's outcome was in fact never understood. The status value is not
  // interpolated into the message: it is the producer's own field, kept out of
  // the error to hold the raw-free line.
  if (!isKnownStatus(tail.status)) {
    throw new Error(
      'triage stream sentinel carries an unrecognized status — refusing to treat it as a clean scan',
    );
  }
  const hitLines = lines.slice(0, -1);
  if (tail.status !== 'complete') {
    // A skip (skipped:no-consent) or a completed empty-history scan
    // (complete:no-history): zero hits to act on, status passed through for the
    // adapter to branch on. Both a non-empty body and a nonzero count are
    // malformed under these zero-hit sentinels, so guard against either.
    if (hitLines.length > 0) {
      throw new Error(
        `triage stream carried ${String(hitLines.length)} hits under a ${tail.status} sentinel`,
      );
    }
    if (tail.count !== 0) {
      throw new Error(
        `triage stream sentinel reported ${String(tail.count)} hits under a ${tail.status} sentinel`,
      );
    }
    return { hits: [], status: tail.status };
  }
  if (tail.count !== hitLines.length) {
    throw new Error(
      `triage stream count ${String(tail.count)} !== ${String(hitLines.length)} hit lines seen`,
    );
  }
  // Both JSON.parse (raw line in a SyntaxError) and TriageHit.parse (raw value
  // in a ZodError) would echo raw content on failure. Report only the line index
  // and a raw-free reason so a malformed hit can never leak through the error.
  const hits = hitLines.map((l, i) => {
    let obj: unknown;
    try {
      obj = JSON.parse(l);
    } catch {
      throw new Error(`triage stream hit line ${String(i)} is not valid JSON`);
    }
    const parsed = TriageHit.safeParse(obj);
    if (!parsed.success) {
      throw new Error(`triage stream hit line ${String(i)} failed TriageHit validation`);
    }
    return parsed.data;
  });
  return { hits, status: 'complete' };
}

// -------------------------------------------------------------------------
// planTriageWriteback (pure)
// -------------------------------------------------------------------------

// One row of the intelligence showcase: the evidence behind a SINGLE
// surviving category's posture decision. Present for EVERY raw-free category in
// the verdict, not just those with FP suppressions — so the preview can show
// "look what it caught and correctly dismissed" even for a genuine-hit category
// with zero suppressions. RAW SAFETY: `reasoning` passed assertRawFree in
// planTriageWriteback (a poisoned category is dropped before it reaches here);
// counts are numbers and action/category are enums, so the whole row is raw-free.
export interface ShowcaseCategory {
  category: DetectionCategory;
  action: BuiltinPolicyId;
  genuineCount: number;
  fpCount: number;
  reasoning: string;
}

export interface TriageWritebackPlan {
  // Resolved FP suppressions to write (raw-free, fail-secure).
  entries: SuppressionEntry[];
  // Per-category enforcement calibration to overwrite (surviving categories only).
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>;
  // The per-category showcase (severity/genuine/fp -> recommendation) for the
  // preview — one entry per surviving category, raw-free by construction.
  showcase: ShowcaseCategory[];
  // Raw-free join entries, for the human gate display.
  join: JoinEntry[];
  // Model notes, scrubbed to SCRUBBED_NOTES if they echoed a raw value.
  notes: string;
  // Everything dropped and why (raw-egress rejections + resolve fail-secure skips).
  skipped: { category: string; reason: string }[];
}

// Turn the raw hits + model verdict into a writeback plan. Pure: no IO, no writes.
// The raw-egress reject runs HERE so a poisoned category never reaches
// resolve (its reasoning becomes the exception justification) or the human gate.
export function planTriageWriteback(
  hits: readonly TriageHit[],
  rec: TriageRecommendation,
): TriageWritebackPlan {
  const join = buildJoinEntries(hits);
  const rawValues = hits.map((h) => h.rawMatch);
  const skipped: { category: string; reason: string }[] = [];
  const posture: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {};
  const showcase: ShowcaseCategory[] = [];
  const safeCategories: TriageRecommendation['perCategory'] = [];
  const seen = new Set<DetectionCategory>();

  // Per-category raw-reject + posture/showcase derivation. An explicit loop (not a
  // side-effecting `.filter` predicate) so the raw-reject -> posture/showcase
  // coupling is legible, and `seen` guards against a duplicate category being
  // processed twice (or a poisoned first occurrence being "rescued" by a later
  // duplicate — once a category leaked raw we distrust it for the whole run).
  for (const cat of rec.perCategory) {
    if (seen.has(cat.category)) {
      skipped.push({
        category: cat.category,
        reason: 'duplicate category in the verdict; ignored (first occurrence decides)',
      });
      continue;
    }
    seen.add(cat.category);
    // A reasoning that echoes a raw value distrusts the whole category — no
    // justification to persist, no posture to apply, no showcase entry.
    try {
      assertRawFree(cat.reasoning, rawValues);
    } catch (err) {
      if (err instanceof RawEgressError) {
        skipped.push({
          category: cat.category,
          reason: 'reasoning referenced a raw detected value; category rejected (fail-secure)',
        });
        continue;
      }
      throw err;
    }
    posture[cat.category] = cat.action;
    safeCategories.push(cat);
    // Showcase: the evidence behind this surviving category's posture. Its
    // reasoning is raw-free (asserted just above), so the row is safe to persist
    // and display — including for a genuine-hit category with zero suppressions.
    showcase.push({
      category: cat.category,
      action: cat.action,
      genuineCount: cat.genuineCount,
      fpCount: cat.fpCount,
      reasoning: cat.reasoning,
    });
  }

  const { entries, skipped: resolveSkips } = resolveSuppressions(
    { perCategory: safeCategories, notes: rec.notes },
    join,
  );
  skipped.push(...resolveSkips);

  // Notes are model free text shown in the wizard showcase — scrub, don't reject
  // the run, if they echoed a raw value.
  let notes = rec.notes;
  try {
    assertRawFree(rec.notes, rawValues);
  } catch (err) {
    if (err instanceof RawEgressError) notes = SCRUBBED_NOTES;
    else throw err;
  }

  return { entries, posture, showcase, join, notes, skipped };
}

// The full recommended posture the preview shows: the cold-start severity floor
// for all 8 packs, overlaid with the evidence-derived actions the judge assigned.
// Single-sourced so the previewed posture matches the 8-pack the confirm write
// establishes — the 'Set all N detection categories' count is the size of this
// map (8), not the survivor subset the evidence produced. The confirm write does NOT
// blanket-overwrite this map: the reviewed evidence packs overwrite, the floor
// packs only fill gaps (see performTriageWriteback), so a pack the user already
// hardened is never silently downgraded to the weak floor.
export function recommendedPosture(
  evidence: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
): Record<DetectionCategory, BuiltinPolicyId> {
  return { ...severityFloorPosture(), ...evidence };
}

// -------------------------------------------------------------------------
// performTriageWriteback (destructive; takes an already-resolved plan)
// -------------------------------------------------------------------------

// The policies-repo slice applyCategoryPosture needs. Structural, so the adapter
// passes db.policies and tests pass a fake.
export interface CategoryPolicyWriter {
  getCategoryAction(category: DetectionCategory): ActionTaken | undefined;
  upsertCategoryAction(category: DetectionCategory, action: ActionTaken): void;
}

export interface TriageWritebackWriters {
  policies: CategoryPolicyWriter;
  exceptions: ExceptionWriter;
  // Run `fn` as a single all-or-nothing DB transaction (BEGIN/COMMIT, ROLLBACK on
  // throw) so the posture overwrite and the suppression inserts commit together or
  // not at all — a mid-batch suppression fault must never leave a half-applied
  // store (the confirm gate would then mis-report and route the user to a floor
  // that can't undo the posture). Optional: in-memory-fake tests omit it and the
  // writes run ungrouped (nothing to roll back). When present, the exceptions repo
  // detects the open transaction and skips its own inner BEGIN IMMEDIATE, which
  // node:sqlite forbids nesting.
  transaction?: <T>(fn: () => Promise<T>) => Promise<T>;
}

// Perform the two destructive writes for an already-resolved/confirmed plan:
// overwrite the per-category posture, then write one 30-day FP suppression per
// entry — as ONE transaction when the writer provides one. Kept separate from the
// pure plan so the confirmation gate is explicit and this step is testable with fakes.
export async function performTriageWriteback(
  plan: TriageWritebackPlan,
  writers: TriageWritebackWriters,
  opts: {
    createdBy: string;
    now: number;
    // The cold-start severity floor to establish for the packs the evidence did
    // not cover, so the confirmed store holds all 8 packs. Optional: omit it
    // and only the plan's own posture is written (the pure-plan tests do this).
    floor?: Partial<Record<DetectionCategory, BuiltinPolicyId>>;
  },
): Promise<{ written: number; skippedDuplicate: number; categoriesWritten: number }> {
  const applyBoth = async (): Promise<{ written: number; skippedDuplicate: number }> => {
    // The reviewed, drift-gated evidence posture: overwrite the surviving
    // categories the user saw in the gate.
    applyCategoryPosture(plan.posture, writers.policies, 'overwrite');
    // The cold-start floor for the remaining packs, when supplied: fill-gaps
    // ONLY. A pack the user already hardened out-of-band (not in the evidence, so
    // never reviewed or drift-checked) is left untouched — the floor establishes
    // a posture only where none exists, never a downgrade (mirrors onboard.ts's
    // --floor semantics).
    if (opts.floor) applyCategoryPosture(opts.floor, writers.policies, 'fill-gaps');
    return applySetupTriageSuppressions(plan.entries, writers.exceptions, {
      createdBy: opts.createdBy,
      now: opts.now,
    });
  };
  const { written, skippedDuplicate } = writers.transaction
    ? await writers.transaction(applyBoth)
    : await applyBoth();
  // Every category that now holds a posture: the reviewed evidence packs plus the
  // floor packs (8 when the floor is supplied), so the tuned count is honest.
  const tuned = new Set<DetectionCategory>(Object.keys(plan.posture) as DetectionCategory[]);
  if (opts.floor) for (const c of Object.keys(opts.floor) as DetectionCategory[]) tuned.add(c);
  return { written, skippedDuplicate, categoriesWritten: tuned.size };
}
