/**
 * The production entry for the secret-leak remediation chain — the shipped
 * script `commands/setup.md` runs when the user chooses "Review leaked keys"
 * at frame 0.6. Untestable glue only: it composes the existing DI core
 * (findings loader, batched-decision presenter, decision layout renderer,
 * option router, standing-posture writer, deliverable resolver) with real IO —
 * no logic lives here that isn't already tested in its own module.
 *
 *   Present:  node scripts/remediate.js
 *   Route:    node scripts/remediate.js --option <redact-rotation-checklist|redact-only|set-secret-redact|leave>
 *             [--posture <redact|warn|block|monitor>]  (required for the two redact options)
 *
 * Both modes read the SAME calibration frame text from stdin: the frame JSON
 * block the calibration preview (apply-suppressions.js) emitted at frame 0.4,
 * carrying the raw-free `maskedFindings` this flow presents. That text is the
 * only place the surfaced secret-leak findings exist outside the store, so the
 * wizard threads the SAME captured text through both invocations unchanged —
 * mirroring how apply-suppressions.js's own preview/confirm split reads its
 * plan back rather than re-deriving it.
 *
 * The chain is invoked with a findings set plus a RemediationEntryContext and
 * holds no wizard state, so this entry is one caller among the
 * entry-point-agnostic chain's callers — nothing here is specific to the
 * frame-0.6 first-run entry beyond the `entrySource` it supplies.
 *
 * Redaction is bound to the hardened production adapter (redactSurfacedSecrets),
 * which derives its own transcript/temp artifact scope rather than trusting a
 * caller-supplied root — never the raw `redactLeakedKeys` primitive a caller
 * could widen. Fail-open throughout: an unreadable frame or a store/redaction
 * fault degrades to an honest note rather than throwing and breaking the Claude
 * session; a malformed `--option`, or a redact route missing a valid
 * `--posture`, fails loud (a wizard wiring bug, not a session fault),
 * mirroring apply-suppressions.js's malformed `--plan` handling.
 *
 * Both redact options carry a follow-up standing-posture step after redacting:
 * the wizard collects a standing-posture level (Redact/Warn/Block/Monitor) and
 * threads it straight through as `--posture` — no second script call. This
 * script only persists the chosen level. `redact-only` prints the redaction
 * confirmation, then the posture confirmation. `redact-rotation-checklist`
 * prints the posture confirmation, then the resolved summary — which reports the
 * redaction (with the transcript count) itself, so the standalone confirmation
 * is not repeated ahead of it.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { loadConfig } from '@akasecurity/plugin-sdk';
import {
  BuiltinPolicyId,
  CalibrationFrame,
  type MaskedSecretFinding,
  RemediationOption,
} from '@akasecurity/schema';

import { readRegisteredCommands } from '../command-registry.ts';
import { fenced } from '../present.ts';
import { frameJsonBlock, readFrameJsonBlock } from '../setup-frame-json.ts';
import { presentBatchedRemediation, routeRemediationOption } from './chain.ts';
import { resolveRemediationDeliverable } from './deliverable.ts';
import { loadSecretLeakFindings } from './findings.ts';
import { type StandingPostureResult, writeStandingSecretPosture } from './posture.ts';
import { renderRedactionOutcome, renderRemediationDecision } from './render.ts';
import { redactSurfacedSecrets } from './surfaced-redact.ts';

function fail(message: string): never {
  process.stderr.write(`AKA remediate failed: ${message}\n`);
  process.exit(1);
}

// The honest note both modes print when the calibration frame could not be read
// or parsed. `loadSecretLeakFindings` returns `undefined` on a read/parse fault
// (distinct from `[]`, a clean read with no secrets), so neither mode fabricates
// an all-clear ("No secret-leak findings to review.") or a false success
// ("✓ Redacted 0 keys.") off a frame it never actually read.
const FRAME_READ_NOTE =
  'Could not read the calibration frame — the surfaced findings were unavailable.\n';

// The batched remediation decision's chaining line "N more worth a look" count: the calibration
// preview's whole-run surfaced count minus the secret findings this batch
// already covers — real and non-negative, never fabricated. Best-effort: an
// unreadable/malformed frame yields 0 (no fabricated figure) rather than
// throwing — the caller already degraded honestly if the frame itself could
// not be read.
function moreWorthALook(frameText: string, secretCount: number): number {
  try {
    const frame = CalibrationFrame.parse(readFrameJsonBlock(frameText));
    return Math.max(0, frame.counts.important - secretCount);
  } catch {
    return 0;
  }
}

// Present the batched remediation decision over the findings the
// calibration frame carries: the templated-count prompt, the full layout
// (finding table, recommendation line, registry-driven chaining line), and the
// exactly-four options as a machine-readable block for the wizard/harness to
// read alongside the human copy.
function present(frameText: string): void {
  const findings = loadSecretLeakFindings(() => frameText);
  if (findings === undefined) {
    process.stdout.write(FRAME_READ_NOTE);
    return;
  }
  const decision = presentBatchedRemediation(findings, { entrySource: 'first-run' });
  if (decision.kind !== 'decision') {
    process.stdout.write('No secret-leak findings to review.\n');
    return;
  }
  const layout = renderRemediationDecision(
    findings,
    moreWorthALook(frameText, decision.secretCount),
    readRegisteredCommands(),
  );
  process.stdout.write(`${decision.prompt}\n\n${fenced(layout)}\n`);
  process.stdout.write(frameJsonBlock(decision));
}

// The posture confirmation line both the redact routes' post-redact posture
// write and the 'set-secret-redact' shortcut print.
function postureConfirmation(result: StandingPostureResult): string {
  return result.persisted
    ? `✓ Set 'secret' posture to ${result.level}\n`
    : "Could not persist the 'secret' posture — the local store was unavailable.\n";
}

// Persist the chosen standing 'secret' posture to the policies store, opening
// and closing the local store within this one call — the same fail-open path
// the 'set-secret-redact' shortcut has always used. A store that can't even be
// opened reports a non-persisted result rather than throwing. The teardown
// `close()` is best-effort: a fault there must never override the write result
// `writeStandingSecretPosture` already computed and returned — a real persisted
// write is not a false failure just because closing the connection afterward
// happened to throw.
export function writeSecretPosture(level: BuiltinPolicyId): StandingPostureResult {
  let db: ReturnType<typeof openLocalDatabase>;
  try {
    db = openLocalDatabase(loadConfig().dataDir);
  } catch {
    return { persisted: false };
  }
  try {
    return writeStandingSecretPosture(level, db.policies);
  } finally {
    try {
      db.close();
    } catch {
      // best-effort teardown — see comment above
    }
  }
}

// Validate the wizard-supplied `--posture` for a redact route via the
// schema-sourced `BuiltinPolicyId`. A missing or malformed value fails loud (a
// wizard-wiring bug, not a session fault) rather than redacting with no posture
// recorded.
function requireRedactPosture(rawPosture: string | undefined): BuiltinPolicyId {
  const parsedPosture = BuiltinPolicyId.safeParse(rawPosture);
  if (!parsedPosture.success) {
    fail(`redact route requires a valid --posture (got ${JSON.stringify(rawPosture)})`);
  }
  return parsedPosture.data;
}

// Route the chosen remediation option through the domain router
// (routeRemediationOption): the two redact options strike the leaked keys via the
// hardened production adapter, 'set-secret-redact' persists the standing 'secret'
// posture on its own with no redaction, and 'leave' does nothing. On a redact
// outcome this entry then persists the standing posture the wizard's
// follow-up prompt collected (`--posture`) and, for 'redact-rotation-checklist'
// only, prints the resolved summary. A redact route with a missing or
// malformed `--posture` fails loud rather than redacting with no posture
// recorded.
async function route(
  frameText: string,
  rawOption: string,
  rawPosture: string | undefined,
): Promise<void> {
  const parsedOption = RemediationOption.safeParse(rawOption);
  if (!parsedOption.success) fail(`unknown --option "${rawOption}"`);
  const option = parsedOption.data;

  // A redact route validates its `--posture` before reading the frame, so a
  // wizard-wiring bug fails loud regardless of frame readability — mirroring the
  // malformed `--option` guard above, which also fires before the frame load.
  // `postureLevel` is set iff this is a redact route (it maps 1:1 to the router's
  // 'redacted' outcome).
  const isRedactRoute = option === 'redact-only' || option === 'redact-rotation-checklist';
  const postureLevel = isRedactRoute ? requireRedactPosture(rawPosture) : undefined;

  const findings = loadSecretLeakFindings(() => frameText);
  if (findings === undefined) {
    process.stdout.write(FRAME_READ_NOTE);
    return;
  }

  // Redact (async, hardened adapter) before dispatch, then hand the router a sync
  // closure returning the count — the router owns which options redact and
  // whether a rotation checklist was requested. `unredacted` names exactly which
  // findings the redaction pass did not strike (out of scope, vanished/unreadable
  // artifact, or a recovery/write failure) — threaded to the deliverable below so
  // a partial redaction never reports the same "resolved" framing as a complete one.
  const redaction = isRedactRoute
    ? await redactSurfacedSecrets(findings)
    : { redactedKeys: 0, unredacted: [] as readonly MaskedSecretFinding[] };
  const redactedKeys = redaction.redactedKeys;
  const outcome = routeRemediationOption(option, {
    redact: () => redactedKeys,
    setStandingRedactPosture: () => writeSecretPosture('redact'),
  });

  switch (outcome.kind) {
    case 'redacted':
      // 'redact-only' has no resolved summary, so it prints its own redaction
      // confirmation — partial-aware, naming any key left unredacted rather than
      // claiming a clean strike. 'redact-rotation-checklist' reports the
      // redaction inside the resolved summary below (with the transcript count),
      // so it does not print the standalone confirmation here — reported once.
      if (!outcome.withRotationChecklist) {
        process.stdout.write(
          `${renderRedactionOutcome({
            redactedKeys: outcome.redactedKeys,
            findings,
            unredactedFindings: redaction.unredacted,
          })}\n`,
        );
      }
      // A 'redacted' outcome comes only from a redact route, where
      // requireRedactPosture already produced a validated level; persist it after
      // the strike and before any resolved summary.
      if (postureLevel !== undefined) {
        process.stdout.write(postureConfirmation(writeSecretPosture(postureLevel)));
      }
      if (outcome.withRotationChecklist) {
        const deliverable = resolveRemediationDeliverable({
          findings,
          redactedKeys: outcome.redactedKeys,
          unredactedFindings: redaction.unredacted,
          cwd: process.cwd(),
        });
        process.stdout.write(`${deliverable.summary}\n`);
      }
      break;
    case 'posture-set':
      process.stdout.write(postureConfirmation(outcome.posture));
      break;
    case 'left':
      process.stdout.write('Left the leaked keys as-is — no redaction, no posture change.\n');
      break;
  }
}

// Guard so importing the exported helpers in tests never runs the CLI.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const argv = process.argv.slice(2);
    const optionIndex = argv.indexOf('--option');
    const frameText = readFileSync(0, 'utf8');
    if (optionIndex === -1) {
      present(frameText);
    } else {
      const rawOption = argv[optionIndex + 1];
      if (rawOption === undefined) fail('--option requires a value');
      const postureIndex = argv.indexOf('--posture');
      const rawPosture = postureIndex === -1 ? undefined : argv[postureIndex + 1];
      await route(frameText, rawOption, rawPosture);
    }
  } catch (err) {
    process.stdout.write(
      `Could not run the remediation chain (${err instanceof Error ? err.message : 'unknown error'}).\n`,
    );
  }

  process.exit(0);
}
