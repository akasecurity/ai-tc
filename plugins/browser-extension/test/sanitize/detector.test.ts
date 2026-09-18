// The one seam in src/sanitize/ that touches the real engine. What is pinned
// here is that an engine which CANNOT answer is not mistaken for one that
// found nothing — the two are byte-identical in `findings` alone, and the
// sanitiser gates both its approval override and its final backstop on that
// array.
import { describe, expect, it, vi } from 'vitest';

import { createDetector, DetectorUnavailableError } from '../../src/sanitize/detector.ts';

const scanText = vi.hoisted(() => vi.fn());

vi.mock('@akasecurity/plugin-sdk/browser', () => ({ scanText }));

describe('createDetector', () => {
  it('D1: reports the rule ids of a real finding', () => {
    scanText.mockReturnValue({
      masked: 'AKIA[REDACTED]',
      findings: [{ ruleId: 'secrets/aws-access-key' }],
    });
    expect(createDetector()('AKIAIOSFODNN7EXAMPLE')).toEqual(['secrets/aws-access-key']);
  });

  it('D2: reports nothing for clean text', () => {
    scanText.mockReturnValue({ masked: 'just some prose', findings: [] });
    expect(createDetector()('just some prose')).toEqual([]);
  });

  it('D3: THROWS when the engine could not scan, rather than reporting clean', () => {
    // Both of scanText's failure branches — a latched malformed bundled pack,
    // and a scan that threw — return exactly this.
    scanText.mockReturnValue({ masked: '[REDACTED]', findings: [] });
    expect(() => createDetector()('anything at all')).toThrow(DetectorUnavailableError);
  });

  it('D4: text that IS the blanket mask is not mistaken for a failure', () => {
    scanText.mockReturnValue({ masked: '[REDACTED]', findings: [] });
    expect(createDetector()('[REDACTED]')).toEqual([]);
  });

  it('D5: a real finding whose redaction happens to be the blanket mask still reports', () => {
    scanText.mockReturnValue({ masked: '[REDACTED]', findings: [{ ruleId: 'secrets/generic' }] });
    expect(createDetector()('a-real-secret-value')).toEqual(['secrets/generic']);
  });
});
