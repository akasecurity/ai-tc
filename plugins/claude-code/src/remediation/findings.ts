/**
 * Loads the secret-leak finding set the remediation chain presents in its
 * decision by reading the persisted calibration frame's optional `maskedFindings` — the
 * raw-free per-secret summaries (provider, masked token, where, state) the finding
 * table renders from. The loader consumes only what the frame carries; it never
 * synthesizes or hardcodes a finding.
 *
 * The load is FAIL-OPEN: reading and validating the persisted frame is wrapped, so
 * a store/read/parse failure returns `undefined` instead of throwing and breaking
 * the Claude session. `undefined` (the load failed) is kept DISTINCT from `[]`
 * (the frame read cleanly and carried no secret summary): the caller presents no
 * remediation decision and fabricates no count on `undefined`, and degrades honestly to
 * the no-decision outcome on `[]`.
 */
import { CalibrationFrame, type MaskedSecretFinding } from '@akasecurity/schema';

import { readFrameJsonBlock } from '../setup-frame-json.ts';

// `readCalibrationFrame` yields the persisted frame's stdout text (the block the
// apply-suppressions preview emitted, captured by the wizard). Injected so the
// read boundary — the seam a store/read failure surfaces at — is exercised
// directly. Returns the surfaced secret summaries, `[]` when the read succeeded
// but none surfaced, or `undefined` when the read/parse failed (fail-open).
export function loadSecretLeakFindings(
  readCalibrationFrame: () => string,
): MaskedSecretFinding[] | undefined {
  try {
    const frame = CalibrationFrame.parse(readFrameJsonBlock(readCalibrationFrame()));
    return frame.maskedFindings ?? [];
  } catch {
    return undefined;
  }
}
