/**
 * Posture-card emitter for the `/aka:setup` wizard's calibration frames. Two
 * modes:
 *
 *   node scripts/start-light.js
 *     Frame 0.3b — the Not-now branch's start-light card: the full 8×4 default posture
 *     matrix seeded with the conservative severity-floor defaults, a per-pack
 *     rationale, and the re-tune hint. Pure copy — reads no store, records no
 *     consent, writes only the card to stdout. The No-history branch touches no
 *     historical data by construction.
 *
 *   node scripts/start-light.js --adjust-confirm --posture '<json>' [--recommended '<json>']
 *     Frame 0.4b — the Yes-path adjust loop's confirm card: the
 *     'category │ recommended │ yours' table comparing the recommended posture
 *     with the user's adjusted choices (the --posture map, the recommended base
 *     with their overrides overlaid), both validated through parsePosture. The
 *     recommended column is the --recommended map — the calibrated recommended
 *     posture the preview printed — so a pack calibration escalated shows its
 *     calibrated level, not the floor; it falls back to the severity floor when
 *     --recommended is omitted. This mode also does a best-effort READ of the
 *     policies store's current per-category posture, so the confirm card can
 *     warn when a pack would be lowered below its existing stored level — a
 *     pack hardened out of band, even one with no findings this run (see
 *     readExistingPosture below). Fail-open: a missing store, or any read
 *     fault, degrades to no comparison rather than throwing.
 */
import { existsSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { loadConfig, severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { ActionTaken, DetectionCategory } from '@akasecurity/schema';
import { DetectionCategory as DetectionCategorySchema } from '@akasecurity/schema';

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

// Best-effort read of the policies store's current per-category posture, for
// the 0.4b downgrade comparison. Fail-open by construction — this is the setup
// wizard, so a store fault must degrade the card rather than break the
// session: no store on disk yet, or any read error (missing/corrupt/locked
// db), returns an empty map, which renders the confirm card exactly as it did
// before this comparison existed. Never opens (and so never creates) a store
// that doesn't already exist — a read-only confirm card should not have the
// side effect of seeding one.
function readExistingPosture(): Partial<
  Record<DetectionCategory, { action: ActionTaken; enabled: boolean }>
> {
  const existing: Partial<Record<DetectionCategory, { action: ActionTaken; enabled: boolean }>> =
    {};
  try {
    const config = loadConfig();
    if (!existsSync(config.dbPath)) return existing;
    const db = openLocalDatabase(config.dataDir);
    try {
      for (const category of DetectionCategorySchema.options) {
        const action = db.policies.getCategoryAction(category);
        if (action !== undefined) existing[category] = { action, enabled: true };
      }
    } finally {
      db.close();
    }
  } catch {
    return {};
  }
  return existing;
}

let card: string;
try {
  card = argv.includes('--adjust-confirm')
    ? renderAdjustConfirm(recommendedPosture(), parsePosture(postureArg()), readExistingPosture())
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
