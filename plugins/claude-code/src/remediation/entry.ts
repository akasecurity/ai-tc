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
 * session; a malformed `--option` fails loud (a wizard wiring bug, not a
 * session fault), mirroring apply-suppressions.js's malformed `--plan`
 * handling.
 */
import { readFileSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { loadConfig } from '@akasecurity/plugin-sdk';
import { CalibrationFrame, RemediationOption } from '@akasecurity/schema';

import { readRegisteredCommands } from '../command-registry.ts';
import { fenced } from '../present.ts';
import { frameJsonBlock, readFrameJsonBlock } from '../setup-frame-json.ts';
import { presentBatchedRemediation, routeRemediationOption } from './chain.ts';
import { resolveRemediationDeliverable } from './deliverable.ts';
import { loadSecretLeakFindings } from './findings.ts';
import { writeStandingSecretPosture } from './posture.ts';
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

// Route the chosen remediation option: the two redact options strike the leaked keys
// via the hardened production adapter, 'set-secret-redact' persists the
// standing 'secret' posture, and 'leave' does nothing. The
// 'redact-rotation-checklist' path additionally resolves the summary deliverable.
async function route(frameText: string, rawOption: string): Promise<void> {
  const parsedOption = RemediationOption.safeParse(rawOption);
  if (!parsedOption.success) fail(`unknown --option "${rawOption}"`);
  const option = parsedOption.data;

  const findings = loadSecretLeakFindings(() => frameText);
  if (findings === undefined) {
    process.stdout.write(FRAME_READ_NOTE);
    return;
  }
  const needsRedaction = option === 'redact-only' || option === 'redact-rotation-checklist';
  const redaction = needsRedaction
    ? await redactSurfacedSecrets(findings)
    : { redactedKeys: 0, unredacted: [] };

  // Open the local store ONLY on the path that writes to it: the router invokes
  // setStandingRedactPosture solely for 'set-secret-redact', so 'leave' and the
  // redact paths never touch the policies store and a store fault can't affect
  // their outcome. The store is opened and closed within this one call.
  const outcome = routeRemediationOption(option, {
    redact: () => redaction.redactedKeys,
    setStandingRedactPosture: () => {
      let db: ReturnType<typeof openLocalDatabase>;
      try {
        db = openLocalDatabase(loadConfig().dataDir);
      } catch {
        // The store was unavailable before any write landed — report a
        // non-persisted result so the posture branch renders its own
        // store-unavailable note rather than escaping to the generic catch.
        return { persisted: false };
      }
      try {
        return writeStandingSecretPosture('redact', db.policies);
      } finally {
        try {
          db.close();
        } catch {
          // Best-effort teardown: a close fault here must never rewrite the
          // write result already computed above.
        }
      }
    },
  });

  switch (outcome.kind) {
    case 'redacted':
      if (outcome.withRotationChecklist) {
        const deliverable = resolveRemediationDeliverable({
          findings,
          redactedKeys: outcome.redactedKeys,
          unredactedFindings: redaction.unredacted,
          cwd: process.cwd(),
        });
        process.stdout.write(`${deliverable.summary}\n`);
      } else {
        // The 'redact-only' route has no resolved summary, so it prints its own
        // redaction confirmation — partial-aware, naming any key left unredacted
        // rather than claiming a clean strike.
        process.stdout.write(
          `${renderRedactionOutcome({
            redactedKeys: outcome.redactedKeys,
            findings,
            unredactedFindings: redaction.unredacted,
          })}\n`,
        );
      }
      break;
    case 'posture-set':
      process.stdout.write(
        outcome.posture.persisted
          ? `✓ Set 'secret' posture to ${outcome.posture.level}\n`
          : "Could not persist the 'secret' posture — the local store was unavailable.\n",
      );
      break;
    case 'left':
      process.stdout.write('Left the leaked keys as-is — no redaction, no posture change.\n');
      break;
  }
}

try {
  const argv = process.argv.slice(2);
  const optionIndex = argv.indexOf('--option');
  const frameText = readFileSync(0, 'utf8');
  if (optionIndex === -1) {
    present(frameText);
  } else {
    const rawOption = argv[optionIndex + 1];
    if (rawOption === undefined) fail('--option requires a value');
    await route(frameText, rawOption);
  }
} catch (err) {
  process.stdout.write(
    `Could not run the remediation chain (${err instanceof Error ? err.message : 'unknown error'}).\n`,
  );
}

process.exit(0);
