// Wraps the real detection engine into the sanitiser's `Detect` seam. The ONE
// file in src/sanitize/ with an external import, isolated so the walker and
// classifier stay trivially unit-testable with a fake detector.
import { scanText } from '@akasecurity/plugin-sdk/browser';

import type { Detect } from './sanitize-capture.ts';

/** The blanket mask `scanText` returns when it could not scan at all. */
const UNAVAILABLE_MASK = '[REDACTED]';

/** Thrown by the real detector when the engine could not answer. */
export class DetectorUnavailableError extends Error {
  constructor() {
    super('the detection engine could not scan this text');
  }
}

/**
 * The real engine: every rule id the bundled packs find in `text`.
 *
 * `scanText` is fail-SECURE for MASKING, and reading only its findings would
 * turn that into a fail-OPEN seam here. Both of its failure branches — a
 * malformed bundled pack, latched for the life of the process, and a scan
 * that threw — return `{ masked: '[REDACTED]', findings: [] }`, which is
 * indistinguishable from a clean scan to a caller that reads `findings`
 * alone. That answer gates the per-value and per-key approval override AND
 * the sanitiser's final whole-document backstop, so a silently empty findings
 * array preserves an operator-approved live credential verbatim and passes
 * every check on the way out, with no diagnostic anywhere.
 *
 * So both halves are read, and an engine that cannot answer REFUSES rather
 * than reporting clean. A sanitiser whose last backstop can fail silently
 * must fail closed.
 */
export function createDetector(): Detect {
  return (text: string): readonly string[] => {
    const { masked, findings } = scanText(text);
    if (findings.length === 0 && masked === UNAVAILABLE_MASK && text !== UNAVAILABLE_MASK) {
      throw new DetectorUnavailableError();
    }
    return findings.map((f) => f.ruleId);
  };
}
