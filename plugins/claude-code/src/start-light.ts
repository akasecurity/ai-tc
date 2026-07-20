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
 *   node scripts/start-light.js --adjust-confirm --posture '<json>' [--recommended '<json>'] [--current '<json>']
 *     Frame 0.4b — the Yes-path adjust loop's confirm card: the
 *     'category │ recommended │ yours' table comparing the recommended posture
 *     with the user's adjusted choices (the --posture map, the recommended base
 *     with their overrides overlaid), both validated through parsePosture. The
 *     recommended column is the --recommended map — the calibrated recommended
 *     posture the preview printed — so a pack calibration escalated shows its
 *     calibrated level, not the floor; it falls back to the severity floor when
 *     --recommended is omitted. --current carries the store's existing
 *     per-category action (the plan file's `current` map) so a choice that lowers
 *     enforcement below it prints the downgrade WARNING; omitted, no baseline
 *     exists and nothing can read as a downgrade.
 */
import { severityFloorPosture } from '@akasecurity/plugin-sdk';

import { parseCurrent, parsePosture } from './onboard-posture.ts';
import { fenced } from './present.ts';
import { renderAdjustConfirm, renderStartLight } from './render.ts';

const argv = process.argv.slice(2);

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

// The store's existing per-category action, for the downgrade comparison. This
// script reads no store — the caller passes the snapshot it already holds (the
// plan file's `current` map). Absent, the baseline is empty and nothing can read
// as a downgrade.
function currentPosture() {
  const raw = jsonArg('--current');
  return raw === undefined ? {} : parseCurrent(raw);
}

// Bad input (a missing --posture, malformed JSON, an unknown category or level)
// must read as a plain line inside the user's Claude session, never a raw stack
// trace, so every parse runs inside this guard.
try {
  const card = argv.includes('--adjust-confirm')
    ? renderAdjustConfirm(recommendedPosture(), parsePosture(postureArg()), currentPosture())
    : renderStartLight(severityFloorPosture());

  // One Markdown code fence so the wizard can echo the card verbatim (space-aligned
  // monospace collapses without the fence).
  process.stdout.write(`${fenced(card)}\n`);
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  process.stdout.write(`AKA setup failed: ${message}\n`);
  process.exit(1);
}

// Match the other adapter scripts (intro.js, firstrun.js) which hard-exit on
// completion so no stray handle can keep the process alive.
process.exit(0);
