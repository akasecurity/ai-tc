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
import { assertRawFree, type ExceptionWriter } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectionCategory,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

import { renderPosturePlan, renderShowcase, renderSuppressionGate } from './gate-display.ts';
import { deletePlanFile, readPlanFile, writePlanFile } from './plan-file.ts';
import {
  type CategoryPolicyWriter,
  parseTriageStream,
  performTriageWriteback,
  planTriageWriteback,
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
}

function getFlag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return undefined;
  const next = argv[i + 1];
  return next !== undefined && !next.startsWith('--') ? next : '';
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
    deps.stdout(`No triage hits to review (${status}). Nothing to suppress.\n`);
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
    const rec = deps.runJudge(hits);
    const plan = planTriageWriteback(hits, rec);

    // Read the store's current per-category action for the downgrade view.
    // Read-only; retained in the plan file so confirm needn't re-read the DB.
    const current: Partial<Record<DetectionCategory, ActionTaken>> = {};
    const db = deps.openDb();
    try {
      for (const category of Object.keys(plan.posture) as DetectionCategory[]) {
        const action = db.policies.getCategoryAction(category);
        if (action !== undefined) current[category] = action;
      }
    } finally {
      db.close();
    }

    deps.stdout(renderPosturePlan(plan.posture, current) + '\n\n');
    deps.stdout(renderShowcase(plan.showcase) + '\n\n');
    deps.stdout(renderSuppressionGate(plan.entries, plan.join) + '\n');
    if (plan.skipped.length > 0) {
      deps.stdout(
        `\nSkipped (fail-secure): ${plan.skipped
          .map((s) => `${s.category} — ${s.reason}`)
          .join('; ')}\n`,
      );
    }
    deps.stdout(`\nNotes: ${plan.notes}\n`);

    // Persist the EXACT resolved raw-free plan the user is about to approve. The
    // backstop (assertRawFree over the serialized doc) runs inside write().
    const planPath = planIO.write(plan, current, rawValues);
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
  // renderPosturePlan WARNING exists to surface. Re-read each planned category and
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
      { createdBy: deps.createdBy(), now: deps.now() },
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
      deps.stdout(
        `AKA suppressions applied: ${String(res.written)} written` +
          (res.skippedDuplicate > 0 ? `, ${String(res.skippedDuplicate)} already active` : '') +
          `; posture calibrated for ${String(res.categoriesWritten)} categories.\n`,
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
