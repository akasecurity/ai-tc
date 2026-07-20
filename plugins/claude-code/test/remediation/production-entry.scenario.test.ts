import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { CalibrationPreview } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { frameCalibration } from '../../src/calibration.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';

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

describe('production remediation entry: honest degrade on a successfully-read, zero-finding set', () => {
  it('a frame that read cleanly but carried no secret findings degrades honestly — no fabricated count, no remediation decision', () => {
    // `frameCalibration` is called with no maskedFindings argument, so it
    // defaults to `[]` and the frame omits `maskedFindings` entirely — a REAL
    // clean read through the same frameCalibration -> frameJsonBlock path the
    // wizard writes, not hand-built JSON standing in for one.
    const emptyFrameText = frameJsonBlock(frameCalibration(preview).frame);

    const out = present(emptyFrameText);

    // The honest no-op the entry prints when `presentBatchedRemediation` returns
    // `{ kind: 'no-decision' }` over an empty findings set — never a fabricated
    // count and never the remediation-decision copy.
    expect(out).toBe('No secret-leak findings to review.\n');
    expect(out).not.toContain('exposed secret');
    expect(out).not.toContain('Redact + rotation checklist');
    // No frame JSON block is emitted for a no-decision outcome — nothing for a
    // wizard/harness to mistake for a real remediation-decision payload.
    expect(out).not.toContain('AKA_FRAME_JSON');
  });

  it('is distinct from the read-failure path: a successful empty read never reads like an unreadable frame', () => {
    const emptyFrameText = frameJsonBlock(frameCalibration(preview).frame);
    const unreadableFrameText = 'this is not a calibration frame block';

    const emptyOut = present(emptyFrameText);
    const unreadableOut = present(unreadableFrameText);

    expect(emptyOut).toBe('No secret-leak findings to review.\n');
    expect(unreadableOut).toBe(
      'Could not read the calibration frame — the surfaced findings were unavailable.\n',
    );
    expect(emptyOut).not.toEqual(unreadableOut);
  });
});
