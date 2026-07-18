/**
 * Posture-card emitter for the `/aka:setup` wizard's calibration frames. Two
 * modes, both pure copy (read no store, record no consent, write only the card
 * to stdout):
 *
 *   node scripts/start-light.js
 *     Frame 0.3b — the Not-now branch's start-light card: the full 8×4 default posture
 *     matrix seeded with the conservative severity-floor defaults, a per-pack
 *     rationale, and the re-tune hint. The No-history branch touches no historical
 *     data by construction.
 *
 *   node scripts/start-light.js --adjust-confirm --posture '<json>' [--recommended '<json>']
 *     Frame 0.4b — the Yes-path adjust loop's confirm card: the
 *     'category │ recommended │ yours' table comparing the recommended posture
 *     with the user's adjusted choices (the --posture map, the recommended base
 *     with their overrides overlaid), both validated through parsePosture. The
 *     recommended column is the --recommended map — the calibrated recommended
 *     posture the preview printed — so a pack calibration escalated shows its
 *     calibrated level, not the floor; it falls back to the severity floor when
 *     --recommended is omitted.
 */
import { severityFloorPosture } from '@akasecurity/plugin-sdk';

import { parsePosture } from './onboard-posture.ts';
import { fenced } from './present.ts';
import { renderAdjustConfirm, renderStartLight } from './render.ts';

const argv = process.argv.slice(2);

// Matches the other adapter scripts (onboard.js): a malformed argument prints a
// clean one-line reason and exits non-zero, never a raw uncaught stack.
function fail(message: string): never {
  process.stdout.write(`AKA setup failed: ${message}\n`);
  process.exit(1);
}

function jsonArg(flag: string): string | undefined {
  const i = argv.indexOf(flag);
  return i === -1 ? undefined : argv[i + 1];
}

// The --posture flag carries the user's adjusted posture as JSON — the frame-0.4b
// confirm card needs it; the frame-0.3b start-light card takes no arguments.
function postureArg(): string {
  const value = jsonArg('--posture');
  if (value === undefined) throw new Error('--adjust-confirm requires --posture <json>');
  return value;
}

// The recommended column of the 0.4b confirm table: the calibrated recommended
// posture the preview printed (passed as --recommended), falling back to the
// cold-start severity floor when the caller omits it.
function recommendedPosture() {
  const raw = jsonArg('--recommended');
  return raw === undefined ? severityFloorPosture() : parsePosture(raw);
}

let card: string;
try {
  card = argv.includes('--adjust-confirm')
    ? renderAdjustConfirm(recommendedPosture(), parsePosture(postureArg()))
    : renderStartLight(severityFloorPosture());
} catch (err) {
  fail(err instanceof Error ? err.message : 'could not render the posture card');
}

// One Markdown code fence so the wizard can echo the card verbatim (space-aligned
// monospace collapses without the fence).
process.stdout.write(`${fenced(card)}\n`);

// Match the other adapter scripts (intro.js, firstrun.js) which hard-exit on
// completion so no stray handle can keep the process alive.
process.exit(0);
