/**
 * The first-run screen's testable core — the dependency-injected orchestration
 * behind the thin firstrun.ts entry (the install-complete screen of the
 * `/aka:setup` wizard).
 *
 * Renders the install-complete card AND emits the handoff-offer payload
 * as a structured JSON block alongside it. All IO (gateway reads, posture read,
 * stdout) is injected so this is unit-testable with a seeded gateway; firstrun.ts
 * wires the real implementations.
 *
 * The handoff payload's 'M worth a look' count is the surfaced/important count
 * from the calibration preview (`counts.important`), threaded in via
 * `--surfaced`. It is NOT the whole-store finding total: a suppressed finding
 * stays in the store (its FP suppression is a temporary exception, not a
 * deletion), so the total over-counts the surfaced items. When no count is
 * supplied (no scan ran), the payload is omitted rather than fabricated.
 *
 * The narrower surfaced live-key secret count arrives via `--live-keys` and gates
 * the remediation chain-entry: it is a subset of `--surfaced`, so a scan that
 * surfaced only non-secret findings carries a positive `--surfaced` with
 * `--live-keys` 0 and offers no remediation. Absent flag ⇒ 0.
 */
import type { DataGateway } from '@akasecurity/plugin-sdk';

import { readRegisteredCommands } from './command-registry.ts';
import { fenced } from './present.ts';
import {
  buildHandoffOffer,
  buildRecommendations,
  healthScore,
  renderFirstRun,
  STORE_UNAVAILABLE_NOTE,
  topFindings,
} from './render.ts';
import { frameJsonBlock } from './setup-frame-json.ts';

// The surfaced/important count for the handoff payload, parsed from
// `--surfaced <n>`. Returns a non-negative integer, or undefined when the flag
// is absent or malformed — the caller then omits the handoff payload instead of
// fabricating a count. This is the same value the calibration preview emitted as
// `counts.important`; the wizard orchestration reads it there and passes it here.
export function parseSurfacedCount(argv: readonly string[]): number | undefined {
  return parseNonNegativeFlag(argv, '--surfaced');
}

// The surfaced live-key secret count for the remediation chain-entry gate, parsed
// from `--live-keys <n>`. A subset of `--surfaced` — the flag is absent (⇒ 0)
// whenever no live-key secret surfaced, so the plain dashboard handoff stands.
export function parseLiveKeyCount(argv: readonly string[]): number {
  return parseNonNegativeFlag(argv, '--live-keys') ?? 0;
}

// Read a `<flag> <n>` non-negative integer from argv, or undefined when the flag
// is absent or its value is malformed.
function parseNonNegativeFlag(argv: readonly string[], flag: string): number | undefined {
  const i = argv.indexOf(flag);
  if (i === -1) return undefined;
  const raw = argv[i + 1];
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

export interface FirstRunDeps {
  argv: readonly string[];
  gateway: DataGateway;
  // Per-category posture block for the card. Injected (rather than opening the
  // store here) so the emission seam is unit-testable; readPostureBlock owns its
  // own catch and degrades to '' so a policies-read fault only hides the Posture
  // section rather than collapsing into the outer fail-open note.
  readPosture: () => Promise<string>;
  stdout: (s: string) => void;
}

// Emit the first-run card and, alongside it, the handoff-offer payload.
// Reads only; never closes the gateway (the caller owns its lifecycle). Throws on
// a store-read failure so the entry's fail-open catch can substitute its note.
export async function runFirstRun(deps: FirstRunDeps): Promise<void> {
  const [summary, findings] = await Promise.all([
    deps.gateway.healthSummary(),
    deps.gateway.recentFindings({ limit: 500 }),
  ]);
  // "Recommendations" mirrors /recommend exactly — the same builder + cap — so
  // the card's count never disagrees with what that screen lists.
  const recommendations = buildRecommendations(findings).length;

  // Per-category posture — the wizard's policy write, read straight from the
  // local store so the card shows what's actually enforced, not the single
  // settings.policy string.
  const postureBlock = await deps.readPosture();

  // The surfaced/important count from the calibration preview (a real preview value) drives
  // both the visible 'N worth a look' handoff line and the structured offer
  // payload below; when no scan supplied one, both are omitted, never fabricated.
  const surfaced = parseSurfacedCount(deps.argv);
  // The narrower live-key secret count gates the remediation chain-entry below,
  // independent of the all-category `surfaced` display count.
  const liveKeys = parseLiveKeyCount(deps.argv);

  // The installed command registry, resolved at this I/O boundary and threaded
  // into the pure renderer so the Try line's curated set is validated against the
  // commands the plugin actually registers.
  const registry = readRegisteredCommands();

  deps.stdout(
    `${fenced(
      renderFirstRun(
        {
          posture: postureBlock,
          health: healthScore(summary),
          // The card's "Findings N" stat is the whole-store total — correct here.
          findings: summary.findings,
          recommendations,
          // Only threaded when a scan supplied a count — never as an explicit
          // undefined (exactOptionalPropertyTypes), so the card omits the handoff
          // line rather than fabricating a zero.
          ...(surfaced !== undefined ? { worthALook: surfaced } : {}),
          topFindings: topFindings(findings),
        },
        registry,
      ),
    )}\n`,
  );

  // The handoff-offer payload, emitted ALONGSIDE the card above so a
  // harness (and the later Claude layer) can read the structured offer without
  // observing the AskUserQuestion the prompt layer issues.
  if (surfaced !== undefined) {
    deps.stdout(frameJsonBlock(buildHandoffOffer(surfaced, liveKeys)));
  }
}

// Fail-open wrapper around runFirstRun: on a store-read failure it degrades to the
// honest store-unavailable note instead of throwing, so no error escapes to break
// the Claude session. The thin firstrun.ts entry delegates its catch here so the
// degradation is unit-tested rather than living in untestable glue.
export async function runFirstRunFailOpen(deps: FirstRunDeps): Promise<void> {
  try {
    await runFirstRun(deps);
  } catch {
    deps.stdout(`${STORE_UNAVAILABLE_NOTE}\n`);
  }
}
