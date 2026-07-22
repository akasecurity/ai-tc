import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { CalibrationPreview, MaskedSecretFinding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { frameCalibration } from '../../src/calibration.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';
import { parseSurface } from '../../src/setup-show.ts';

// The empty-findings honest-degrade leg, proven at the declared INTEGRATION
// seam: the shipped, entry-point-agnostic direct-invocation entry — the same
// `scripts/remediate.js` `commands/setup.md` runs — driven directly with a
// SUCCESSFULLY-READ, ZERO-FINDING calibration frame. The frame-0.6 "Review
// leaked keys" offer fires exactly when the calibration scan surfaced live
// keys and never otherwise, so a real frame-0.6 decision can never present an
// empty set; this branch is therefore driven through the entry directly (no
// wizard state), never frame 0.6, matching
// remediation-production-entry.journey.test.ts's frame-0.6 coverage of the
// nonempty leg.
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const REMEDIATE_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'remediate.js');

// A calibration preview that genuinely surfaced something (a pii hit) but no
// secret leak — so the "zero-finding secret-leak set" below is a real absence,
// not a vacuous empty preview.
const preview: CalibrationPreview = {
  categories: [{ category: 'pii', genuineCount: 1, fpCount: 5, egress: false }],
  posture: {
    secret: 'warn',
    pii: 'warn',
    financial: 'warn',
    phi: 'warn',
    code_flaw: 'warn',
    custom: 'warn',
    code_context: 'monitor',
    config: 'monitor',
  },
};

// Spawn the built production entry exactly as the wizard does — piping the
// calibration frame text on stdin, present mode (no `--option`).
function present(frameText: string): string {
  return execFileSync(process.execPath, [REMEDIATE_SCRIPT], {
    input: frameText,
    encoding: 'utf8',
  });
}

// Route mode: the same built entry, spawned with `--option`/`--posture`.
function route(frameText: string, ...args: string[]): string {
  return execFileSync(process.execPath, [REMEDIATE_SCRIPT, ...args], {
    input: frameText,
    encoding: 'utf8',
  });
}

// A backfill + apply-suppressions preview that DID surface a secret leak — the
// counterpart to the empty-findings `preview` above — so the count line, the
// fenced finding table, and the frame block can be proven as SHOW/FRAME regions
// against a real (non-empty) remediation decision. The masked finding mirrors
// findings.test.ts's raw-free MaskedSecretFinding shape — no raw value anywhere.
const secretsPreview: CalibrationPreview = {
  categories: [{ category: 'secret', genuineCount: 2, fpCount: 0, egress: false }],
  posture: {
    secret: 'warn',
    pii: 'warn',
    financial: 'warn',
    phi: 'warn',
    code_flaw: 'warn',
    custom: 'warn',
    code_context: 'monitor',
    config: 'monitor',
  },
};

const stripeFinding: MaskedSecretFinding = {
  provider: 'stripe',
  maskedToken: 'sk_live_****',
  where: { filePath: '~/.claude/transcripts/2026-07-01.jsonl' },
  state: 'still-valid',
};
const awsFinding: MaskedSecretFinding = {
  provider: 'aws',
  maskedToken: 'AKIA****************',
  where: { filePath: '/tmp/agent-dump.txt', span: { start: 12, end: 32 } },
  state: 'still-valid',
};

function secretsFrameText(): string {
  return frameJsonBlock(frameCalibration(secretsPreview, [stripeFinding, awsFinding]).frame);
}

describe('production remediation entry: honest degrade on a successfully-read, zero-finding set', () => {
  it('a frame that read cleanly but carried no secret findings degrades honestly — no fabricated count, no remediation decision', () => {
    // `frameCalibration` is called with no maskedFindings argument, so it
    // defaults to `[]` and the frame omits `maskedFindings` entirely — a REAL
    // clean read through the same frameCalibration -> frameJsonBlock path the
    // wizard writes, not hand-built JSON standing in for one.
    const emptyFrameText = frameJsonBlock(frameCalibration(preview).frame);

    const out = present(emptyFrameText);
    const surface = parseSurface(out);

    // The honest no-op the entry prints when `presentBatchedRemediation` returns
    // `{ kind: 'no-decision' }` over an empty findings set — never a fabricated
    // count and never the remediation-decision copy. It rides inside a SHOW
    // region — the same relay chokepoint every other user-facing note in this
    // entry now uses.
    expect(surface.shows).toEqual(["No exposed keys to deal with — you're clear."]);
    expect(surface.status).not.toContain('exposed secret');
    expect(surface.status).not.toContain('Redact + rotation checklist');
    // No frame JSON block is emitted for a no-decision outcome — nothing for a
    // wizard/harness to mistake for a real remediation-decision payload.
    expect(surface.frames).toHaveLength(0);
  });

  it('is distinct from the read-failure path: a successful empty read never reads like an unreadable frame', () => {
    const emptyFrameText = frameJsonBlock(frameCalibration(preview).frame);
    const unreadableFrameText = 'this is not a calibration frame block';

    const emptyOut = parseSurface(present(emptyFrameText));
    const unreadableOut = parseSurface(present(unreadableFrameText));

    expect(emptyOut.shows).toEqual(["No exposed keys to deal with — you're clear."]);
    // FRAME_READ_NOTE carries its own trailing newline (shared with the
    // route-mode read-failure path), so the SHOW region's content keeps it too.
    expect(unreadableOut.shows).toEqual([
      "I couldn't pull up what I found just now — the details weren't available.\n",
    ]);
    expect(emptyOut.shows).not.toEqual(unreadableOut.shows);
  });
});

describe('production remediation entry: SHOW-relay coverage (present + route)', () => {
  it('present mode emits the count line + fenced finding table as a SHOW region, keeps the decision frame a FRAME, and never leaks the finding into status', () => {
    const out = present(secretsFrameText());
    const surface = parseSurface(out);

    expect(surface.shows).toHaveLength(1);
    const [card] = surface.shows;
    expect(card).toContain('exposed secret keys');
    // The fenced finding table rides inside the same SHOW region as the count line.
    expect(card).toContain('sk_live_****');
    expect(card).toContain('```');

    // The machine-readable decision frame is untouched — still a FRAME, never a SHOW.
    expect(surface.frames).toHaveLength(1);

    // The finding text never leaks into the untagged status remainder.
    expect(surface.status).not.toContain('exposed secret keys');
    expect(surface.status).not.toContain('sk_live_****');
  });

  it('route "leave" emits its note as a SHOW region', () => {
    const out = route(secretsFrameText(), '--option', 'leave');
    const surface = parseSurface(out);

    expect(surface.shows).toEqual(['Left them as they are — nothing redacted, nothing changed.']);
    expect(surface.status).not.toContain('Left them as they are');
  });
});
