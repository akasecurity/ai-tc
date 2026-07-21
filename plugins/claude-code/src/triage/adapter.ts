/**
 * The `apply-suppressions` adapter core — the
 * dependency-injected orchestration behind the thin apply-suppressions.js script.
 *
 * Two modes, and the binding gate lives in the split between them:
 *   - PREVIEW (no --confirmed): read the backfill --triage stream, run the
 *     ephemeral judge, build the plan, render the human gate, then PERSIST the
 *     resolved raw-free plan to a temp file and print its path. Nothing is written
 *     to the store.
 *   - CONFIRM (--confirmed --plan <path>): read + validate the persisted plan and
 *     apply it VERBATIM (applyCategoryPosture + applySetupTriageSuppressions).
 *     It does NOT read the stream and does NOT run the judge — so the user applies
 *     exactly the plan they approved, never a freshly re-derived one.
 *
 * All IO (stream read, judge spawn, DB, clock, stdout/stderr) is injected so this
 * is unit-testable with fakes; the script wires the real implementations.
 */
import { assertRawFree, type ExceptionWriter, severityFloorPosture } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  CalibrationPreview,
  DetectionCategory,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

import { frameCalibration, frameEmptyState } from '../calibration.ts';
import { readRegisteredCommands } from '../command-registry.ts';
import { fenced, show } from '../present.ts';
import { renderApplied, renderRecommendedPosture, STORE_UNAVAILABLE_NOTE } from '../render.ts';
import { frameJsonBlock } from '../setup-frame-json.ts';
import { dedupeForJudge } from './dedupe.ts';
import { deriveFalsePositivePatterns } from './false-positive-patterns.ts';
import { renderPosturePlan, renderShowcase, renderSuppressionGate } from './gate-display.ts';
import { chunkForJudge, chunkIds, groundVerdict, mergeRecommendations } from './merge.ts';
import { deletePlanFile, readPlanFile, writePlanFile } from './plan-file.ts';
import { deriveSurfacedSecretFindings } from './surfaced-secrets.ts';
import {
  type CategoryPolicyWriter,
  parseTriageStream,
  performTriageWriteback,
  planTriageWriteback,
  recommendedPosture,
} from './writeback.ts';

export interface AdapterDb {
  policies: CategoryPolicyWriter;
  exceptions: ExceptionWriter;
  // Run `fn` as one all-or-nothing DB transaction. Supplied by the real store so
  // the confirm write (posture overwrite + suppression inserts) is atomic; the
  // exceptions repo detects the open transaction and skips its own inner BEGIN.
  transaction?: <T>(fn: () => Promise<T>) => Promise<T>;
  close(): void;
}

// The persist/read/delete seam. Defaults to the real plan-file implementation;
// tests can override to point at a controlled path or assert calls.
export interface PlanFileIO {
  write: typeof writePlanFile;
  read: typeof readPlanFile;
  delete: typeof deletePlanFile;
}

const DEFAULT_PLAN_IO: PlanFileIO = {
  write: writePlanFile,
  read: readPlanFile,
  delete: deletePlanFile,
};

export interface AdapterDeps {
  argv: string[];
  // Called ONLY on the preview path. Reads the --triage stream (stdin or a path).
  readStream: (streamPath: string | undefined) => string;
  // Called ONLY on the preview path. The ephemeral judge subprocess.
  runJudge: (hits: readonly TriageHit[]) => TriageRecommendation;
  openDb: () => AdapterDb;
  now: () => number;
  createdBy: () => string;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  planIO?: PlanFileIO;
  // Byte budget per judging batch. Defaults to chunkForJudge's own; injectable
  // so a test can drive the multi-batch path without a quarter-megabyte of
  // fixture, which is otherwise the only way to reach it. `--max-judge-bytes`
  // (below) exposes the same override on the command line, so the batch path
  // can be exercised on a real machine without a giant history.
  maxJudgeBytes?: number;
}

function getFlag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return undefined;
  const next = argv[i + 1];
  return next !== undefined && !next.startsWith('--') ? next : '';
}

// The per-batch byte budget, from `--max-judge-bytes N` or the injected dep.
// Reaching the batch path otherwise takes a quarter-megabyte of real history,
// so this is how the fallback gets exercised deliberately — set it low (a few
// thousand) against a small history and every hit becomes its own batch.
// Ignores a missing/zero/non-numeric value and falls back to the default,
// rather than letting a typo silently disable batching.
function resolveMaxJudgeBytes(deps: AdapterDeps): number | undefined {
  const flag = getFlag(deps.argv, 'max-judge-bytes');
  if (flag !== undefined && flag !== '') {
    const parsed = Number(flag);
    if (Number.isInteger(parsed) && parsed > 0) return parsed;
  }
  return deps.maxJudgeBytes;
}

// Returns a process exit code (0 ok, 1 failure). Never calls process.exit itself.
export async function runApply(deps: AdapterDeps): Promise<number> {
  const planIO = deps.planIO ?? DEFAULT_PLAN_IO;
  const confirmed = deps.argv.includes('--confirmed');
  return confirmed ? runConfirm(deps, planIO) : runPreview(deps, planIO);
}

// PREVIEW: judge, build the plan, render the gate, persist the raw-free plan, and
// print the plan-file path for the wizard to hand to the confirm step.
function runPreview(deps: AdapterDeps, planIO: PlanFileIO): number {
  const streamPath = getFlag(deps.argv, 'stream');
  const streamText = deps.readStream(streamPath === '' ? undefined : streamPath);

  const { hits, status } = parseTriageStream(streamText);
  if (hits.length === 0) {
    if (status === 'complete') {
      // A scan ran and surfaced nothing: render the honest scan-ran-clean empty
      // state over the recommended posture, plus its zero-count CalibrationFrame.
      const empty = frameEmptyState('scan-clean', severityFloorPosture());
      deps.stdout(show(fenced(empty.copy)));
      deps.stdout(frameJsonBlock(empty.frame));
      return 0;
    }
    if (status === 'complete:no-history') {
      // A scan ran over an empty history set: render the honest no-history empty
      // state over the start-light posture, plus its zero-count CalibrationFrame.
      const empty = frameEmptyState('no-history', severityFloorPosture());
      deps.stdout(show(fenced(empty.copy)));
      deps.stdout(frameJsonBlock(empty.frame));
      return 0;
    }
    // The only status that reaches here is `skipped:no-consent` — the backfill
    // refused to read history because access was never granted. Nothing was
    // examined, so this must not borrow the looked-and-found-nothing copy above:
    // that would report a clean bill of health for a scan that never ran.
    deps.stdout(show("I didn't review anything — historical access wasn't granted."));
    return 0;
  }

  // Preview egress boundary: everything below handles the raw hits, so any error
  // it throws is scrubbed against the raw values before it can leave this process.
  // A message that echoed a raw value is withheld wholesale; a clean one passes
  // through unchanged. This is what lets the top-level apply-suppressions catch
  // safely print err.message — the guarantee is enforced here, not by auditing
  // every current throw site (a future throw is covered too). The scrub inherits
  // assertRawFree's MIN_RAW_LEN floor (values shorter than 4 chars are not
  // matched) — the same containment bound used at every other raw-egress
  // checkpoint (plan-file backstop, reasoning/notes checks), not a weaker one.
  const rawValues = hits.map((h) => h.rawMatch);
  try {
    // Collapse repeated occurrences of the same detected value to one
    // representative BEFORE the judge — value-scoped suppression means one
    // representative's verdict covers every occurrence, so the judge (and every
    // downstream derivation below) reasons over distinct values, not raw counts.
    const reps = dedupeForJudge(hits);
    const chunks = chunkForJudge(reps, resolveMaxJudgeBytes(deps));
    if (chunks.length > 1) {
      // Say so BEFORE the judging runs: each batch is its own `claude -p`
      // subprocess, so a large history sits here for a while with nothing else
      // on screen. It also makes the fallback observable — otherwise the only
      // difference between one batch and ten is how long the wizard hangs.
      deps.stdout(
        show(
          `Reviewing ${String(reps.length)} distinct values in ${String(chunks.length)} batches — this is the large-history path, so give it a moment.`,
        ),
      );
    }
    let rec: TriageRecommendation;
    if (chunks.length === 1) {
      const [soleChunk] = chunks;
      // chunkForJudge always returns at least one chunk for a non-empty input
      // (reps is non-empty: runPreview already returned on hits.length === 0).
      if (soleChunk === undefined) throw new Error('chunkForJudge returned no chunks');
      // Grounded even though there is only one batch: the judge saw the
      // representative set, not the full hit list, so an fpId naming a
      // collapsed duplicate is still an id it never read — and a value-scoped
      // consumer would expand that one id across the whole value class.
      rec = groundVerdict(deps.runJudge(soleChunk), chunkIds(soleChunk));
    } else {
      // Each chunk's verdict is paired with the ids that chunk actually
      // contained: the merge drops any fpId naming a hit its judge never saw,
      // which a single judgment guaranteed structurally and chunking does not.
      rec = mergeRecommendations(chunks.map((c) => ({ rec: deps.runJudge(c), ids: chunkIds(c) })));
    }
    // Fed the SAME representative set the judge saw, so the join/fpIds the plan
    // resolves suppressions from line up with the ids the verdict references.
    const plan = planTriageWriteback(reps, rec);

    // Read the store's current per-category action for the downgrade view.
    // Read-only; retained in the plan file so confirm needn't re-read the DB.
    // Fail-open: this is the calibration step's only store read, and an unreadable
    // store (missing / corrupt / locked db) must degrade the downgrade comparison
    // to the honest store-unavailable note rather than throw and break the wizard.
    // The calibrated counts below come from the reviewed plan, not the store, so
    // they still render truthfully — no fabricated count stands in for the fault.
    const current: Partial<Record<DetectionCategory, ActionTaken>> = {};
    let storeUnavailable = false;
    try {
      const db = deps.openDb();
      try {
        for (const category of Object.keys(plan.posture) as DetectionCategory[]) {
          const action = db.policies.getCategoryAction(category);
          if (action !== undefined) current[category] = action;
        }
      } finally {
        db.close();
      }
    } catch {
      storeUnavailable = true;
    }

    // Collect every human-copy piece of the gate — the human gate is ONE
    // consolidated SHOW region below, not a sequence of separate emits.
    const gate: string[] = [];
    if (storeUnavailable) {
      gate.push(STORE_UNAVAILABLE_NOTE);
    }
    // With no readable store the downgrade comparison has no baseline, so pass an
    // empty current — every category renders as new rather than a partial/false view.
    gate.push(renderPosturePlan(plan.posture, storeUnavailable ? {} : current));
    gate.push(renderShowcase(plan.showcase));
    gate.push(renderSuppressionGate(plan.entries, plan.join));
    if (plan.skipped.length > 0) {
      gate.push(
        `Skipped (fail-secure): ${plan.skipped.map((s) => `${s.category} — ${s.reason}`).join('; ')}`,
      );
    }
    gate.push(`Notes: ${plan.notes}`);

    // Emit the structured calibration frame ALONGSIDE the human gate
    // above — additive, not a replacement. Counts and category lists come from
    // the raw-free plan's per-category genuine/suppressed split (surviving
    // categories only; a poisoned category was already dropped). The posture is
    // the full recommended view — the severity floor overlaid with the
    // evidence-derived actions the judge assigned — so every pack is present.
    // The retroactive scan reads at-rest history (transcripts, temp files, agent
    // memory), so every triaged kind is an at-rest exposure, not an
    // outbound-leak: egress is false across the board here. The frame carries
    // only masked/enum/count data, so it stays within this raw-egress boundary.
    const preview: CalibrationPreview = {
      categories: plan.showcase.map((c) => ({
        category: c.category,
        genuineCount: c.genuineCount,
        fpCount: c.fpCount,
        egress: false,
      })),
      posture: recommendedPosture(plan.posture),
    };
    // The surfaced secret leaks the remediation table renders from: the
    // secret hits the model did NOT dismiss as false positives, projected to the
    // raw-free MaskedSecretFinding shape and carried additively in the frame.
    // Empty for a clean/all-suppressed run, so the optional field is omitted.
    // Fed the FULL hit list, NOT `reps`: this is the pipeline's one
    // location-scoped consumer — each finding carries a single filePath, and
    // that path is both the only thing that puts a file in the redaction pass's
    // scope and the unit the complete-vs-partial redaction gate counts. One key
    // pasted into three transcripts must surface as three findings or redaction
    // strikes one file and still reports the run resolved. The judge's
    // value-scoped dismissal is expanded back over each class inside.
    const maskedFindings = deriveSurfacedSecretFindings(hits, rec, plan);
    // The masked false-positive pattern groups the fixture/exception offer names
    // its pattern and count from: the marked hits, re-derived to their masked
    // token and grouped, carried additively in the frame. Empty when nothing was
    // marked a false positive, so the optional field is omitted (fail-open).
    // `reps` on purpose (unlike maskedFindings above): the offer writes
    // fingerprint-keyed exceptions, so its unit is the distinct VALUE — one
    // exception covers every occurrence, and counting occurrences here would
    // inflate the offer's count over the number of exceptions it can grant.
    const falsePositivePatterns = deriveFalsePositivePatterns(reps, rec, plan);
    const calibration = frameCalibration(preview, maskedFindings, falsePositivePatterns);

    // The calibrated-result card: the real-count headline over the
    // preview's genuine/suppressed split, then the condensed one-row-per-pack
    // recommended posture. Both are raw-free (counts, category enums, and palette
    // levels only) and template over this run's numbers, never a fixed value.
    gate.push(calibration.copy);
    gate.push(renderRecommendedPosture(preview.posture));

    // The whole human gate — the posture plan, showcase, suppression gate, notes,
    // and the calibrated-result card — is ONE relay region: the model pastes it
    // verbatim, so it must read as a single coherent screen, not several stray
    // fragments the model has to stitch back together.
    deps.stdout(show(fenced(gate.join('\n\n'))));

    // The machine-readable calibration frame carrying the same counts/posture the
    // card above renders, for downstream consumers (the installed-summary handoff).
    deps.stdout(frameJsonBlock(calibration.frame));

    // Persist the EXACT resolved raw-free plan the user is about to approve. The
    // backstop (assertRawFree over the serialized doc) runs inside write(). With an
    // unreadable store the baseline is empty (matching the displayed view), so a
    // later confirm re-reads and drift-gates rather than trusting a partial read.
    const planPath = planIO.write(plan, storeUnavailable ? {} : current, rawValues);
    deps.stdout(`\nPlan saved to: ${planPath}\n`);
    deps.stdout(
      `Re-run with: apply-suppressions.js --confirmed --plan ${planPath}\n` +
        `(applies this exact plan — no re-scan, no re-judge; the file is deleted after apply)\n`,
    );
    return 0;
  } catch (err) {
    const original = err instanceof Error ? err.message : String(err);
    // assertRawFree returns `original` when it holds no raw value, or throws
    // RawEgressError when it does — in which case the whole message is withheld.
    let safe: string;
    try {
      safe = assertRawFree(original, rawValues);
    } catch {
      safe =
        'apply-suppressions preview failed (message withheld: it referenced a raw detected value)';
    }
    // Deliberately NOT chaining `err` as `cause`: the caught error is the very
    // thing being scrubbed — its message/stack may carry the raw value, and a
    // cause would re-expose it via util.inspect/loggers. Only the scrubbed
    // message crosses this boundary.
    // eslint-disable-next-line preserve-caught-error -- caught error may carry raw; see above
    throw new Error(safe);
  }
}

// CONFIRM: apply the persisted plan VERBATIM. No stream read, no judge. Any
// problem with --plan fails loud rather than falling back to a re-derived plan.
async function runConfirm(deps: AdapterDeps, planIO: PlanFileIO): Promise<number> {
  const planPath = getFlag(deps.argv, 'plan');
  if (planPath === undefined || planPath === '') {
    deps.stderr(
      'AKA apply-suppressions failed: --confirmed requires --plan <path> ' +
        '(the raw-free plan file printed by the preview run). Refusing to re-judge.\n',
    );
    return 1;
  }

  let plan;
  try {
    plan = planIO.read(planPath);
  } catch (err) {
    deps.stderr(
      `AKA apply-suppressions failed: could not read/validate plan file ${planPath}: ` +
        `${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 1;
  }

  const db = deps.openDb();
  // Close EXACTLY once: a post-write plan-file delete or stdout throw must not
  // reach a second db.close() (node:sqlite double-close throws) and re-report a
  // completed write as failure.
  let closed = false;
  const closeOnce = () => {
    if (closed) return;
    closed = true;
    db.close();
  };

  // Store-drift gate. The plan was approved against the per-category actions the
  // preview captured in `plan.current`. If the store changed since (a CLI edit, a
  // web-ui save, another wizard run), applying the plan blindly could turn an
  // approved non-downgrade into a SILENT downgrade — the exact case the preview's
  // renderPosturePlan surfaces via its "Heads up" downgrade note. Re-read each planned category and
  // compare; on drift, fail loud with no write so the wizard routes to the floor
  // fallback and the user re-previews against the store they can actually see.
  // undefined (no row) compares equal on both sides, so an added/removed row
  // counts as drift too. The read is same-process, immediately before the
  // transactional write below; a concurrent edit landing in the sub-millisecond
  // gap between them is an accepted residual window for this local single-user
  // store, not covered here.
  try {
    const drifted: DetectionCategory[] = [];
    for (const category of Object.keys(plan.posture) as DetectionCategory[]) {
      if (db.policies.getCategoryAction(category) !== plan.current[category]) {
        drifted.push(category);
      }
    }
    if (drifted.length > 0) {
      closeOnce();
      deps.stderr(
        `AKA apply-suppressions failed: the detection store changed since this plan was previewed ` +
          `(${drifted.join(', ')}). Refusing to apply a stale plan — re-run /aka:setup to review ` +
          `against the current store.\n`,
      );
      return 1;
    }
  } catch (err) {
    closeOnce();
    deps.stderr(
      `AKA apply-suppressions failed: could not verify the plan against the current store ` +
        `(${err instanceof Error ? err.message : 'read error'}). Refusing to apply.\n`,
    );
    return 1;
  }

  try {
    const res = await performTriageWriteback(
      // The write only reads posture + entries; join/showcase/notes/skipped are
      // preview-display fields, so they are not reconstructed here. The store's
      // `transaction` makes the posture + suppression writes ALL-OR-NOTHING, so a
      // mid-batch fault rolls the posture overwrite back too — the store is never
      // left half-applied (and the floor fallback below is safe: nothing persisted).
      // Establish the full 8-pack the preview showed so settings holds
      // all 8 packs and the confirmation reads 'Set all 8 detection categories': the reviewed,
      // drift-gated evidence packs (plan.posture) OVERWRITE, and the severity floor
      // fills the remaining packs with FILL-GAPS. The floor packs are not covered by
      // the drift gate above (only the reviewed evidence is), so they must never
      // overwrite — an out-of-band-hardened pack (e.g. code_context=block) is left
      // as-is rather than silently reset to the weak floor.
      {
        posture: plan.posture,
        entries: plan.entries,
        showcase: [],
        join: [],
        notes: plan.notes,
        skipped: [],
      },
      {
        policies: db.policies,
        exceptions: db.exceptions,
        // Only set when the store provides one (exactOptionalPropertyTypes).
        ...(db.transaction ? { transaction: db.transaction } : {}),
      },
      { createdBy: deps.createdBy(), now: deps.now(), floor: severityFloorPosture() },
    );
    // The write COMMITTED. From here nothing may flip the result to failure:
    // cleanup (plan-file delete) and reporting (stdout) are best-effort, and a
    // throw in either must not mask a persisted, successful apply.
    closeOnce();
    try {
      planIO.delete(planPath);
    } catch {
      // A leftover temp plan file is harmless; the apply already succeeded.
    }
    try {
      // The applying confirmation — the tuned-category and routine-dismissed
      // counts threaded from the real writeback result, never a literal; the
      // Ready line's curated set validated against the installed command registry.
      deps.stdout(
        show(renderApplied(res.categoriesWritten, res.written, readRegisteredCommands())),
      );
    } catch {
      // Reporting failed but the write did not — still a success.
    }
    return 0;
  } catch (err) {
    closeOnce();
    deps.stderr(
      `AKA apply-suppressions failed: ${err instanceof Error ? err.message : 'could not apply suppressions'}\n`,
    );
    return 1;
  }
}
