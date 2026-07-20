import { type CalibrationPreview, type MaskedSecretFinding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { frameCalibration } from '../../src/calibration.ts';
import { loadSecretLeakFindings } from '../../src/remediation/findings.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';

// A backfill + apply-suppressions preview whose calibration recorded BOTH a
// surfaced secret kind AND a non-secret (pii) kind, so "only secret-leak findings
// reach the remediation flow" is an OBSERVABLE exclusion here, not a vacuous one: the
// source frame genuinely carries pii activity in its findingKinds.
const preview: CalibrationPreview = {
  categories: [
    { category: 'secret', genuineCount: 2, fpCount: 0, egress: false },
    { category: 'pii', genuineCount: 1, fpCount: 100, egress: false },
  ],
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

// The surfaced secret-leak summaries the calibration carried into the frame — the
// raw-free MaskedSecretFinding shape the finding table renders from.
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
const maskedSecrets: MaskedSecretFinding[] = [stripeFinding, awsFinding];

// A calibration frame that CARRIES masked secret summaries, serialized through the
// same frameCalibration -> frameJsonBlock path the loader reads back, so the test
// drives the loader's real read boundary (frameJsonBlock/readFrameJsonBlock +
// CalibrationFrame.parse) over frame-shaped input — no hand-built JSON. The masked
// summaries are supplied via frameCalibration's optional argument. Wiring the
// apply-suppressions preview to populate them from real triage hits ships this
// iteration and is exercised at the adapter and journey seams
// (test/triage/adapter.test.ts and the yes-scan journey); this loader test drives
// only the read boundary.
function persistedFrame(masked: readonly MaskedSecretFinding[] = maskedSecrets): string {
  return frameJsonBlock(frameCalibration(preview, [...masked]).frame);
}

describe('loadSecretLeakFindings — reads backfill findings from the calibration frame', () => {
  it('loads the surfaced secret findings from the persisted calibration frame — not synthesized', () => {
    const loaded = loadSecretLeakFindings(() => persistedFrame());
    expect(loaded).toEqual(maskedSecrets);
  });

  it('templates over the real set — a different frame yields a different count (no hardcode)', () => {
    const three = [...maskedSecrets, stripeFinding];
    const loaded = loadSecretLeakFindings(() => persistedFrame(three));
    expect(loaded).toHaveLength(3);

    const one = loadSecretLeakFindings(() => persistedFrame([stripeFinding]));
    expect(one).toHaveLength(1);
  });

  it('excludes non-secret kinds — the pii activity in the frame never enters the loaded set', () => {
    // Guard against vacuity: the source frame genuinely records a non-secret (pii)
    // finding kind, so the exclusion below is a real filter, not an empty set.
    const frame = frameCalibration(preview, maskedSecrets).frame;
    expect(frame.findingKinds.map((k) => k.category)).toContain('pii');

    const surfacedSecretCount = preview.categories
      .filter((c) => c.category === 'secret')
      .reduce((n, c) => n + c.genuineCount, 0);
    const loaded = loadSecretLeakFindings(() => persistedFrame());
    // Only the secret-leak summaries reach the flow — count matches the surfaced
    // secret findings, and every loaded entry is a secret summary (no pii row).
    expect(loaded).toEqual(maskedSecrets);
    expect(loaded).toHaveLength(surfacedSecretCount);
  });

  it('returns an empty set — distinct from a failure — when a scan surfaced no secret', () => {
    // A successfully-read frame that carried no secret masked summaries: the load
    // SUCCEEDED and there is simply nothing to remediate → [], never undefined.
    const cleanFrame = frameJsonBlock(frameCalibration(preview).frame);
    const loaded = loadSecretLeakFindings(() => cleanFrame);
    expect(loaded).toEqual([]);
  });
});

describe('loadSecretLeakFindings — fail-open on a store/read failure', () => {
  it('catches a read throw at the findings-load seam — never propagates it', () => {
    expect(() =>
      loadSecretLeakFindings(() => {
        throw new Error('store read failed (missing / corrupt / locked db)');
      }),
    ).not.toThrow();
  });

  it('claims no false success — returns undefined, fabricating no count and no findings', () => {
    const loaded = loadSecretLeakFindings(() => {
      throw new Error('store read failed');
    });
    // undefined is the "do not present a remediation decision, do not fabricate a count"
    // signal — it carries neither a findings array nor a number.
    expect(loaded).toBeUndefined();
  });

  it('keeps the failure signal DISTINCT from an honest empty read', () => {
    const failed = loadSecretLeakFindings(() => {
      throw new Error('store read failed');
    });
    const empty = loadSecretLeakFindings(() => frameJsonBlock(frameCalibration(preview).frame));
    // A failed load must never be mistaken for "no secret findings surfaced":
    // undefined (read failed) ≠ [] (read succeeded, nothing to remediate).
    expect(failed).toBeUndefined();
    expect(empty).toEqual([]);
    expect(failed).not.toEqual(empty);
  });

  it('fails open on an unreadable / malformed persisted frame too', () => {
    // A read that returns text with no valid frame block cannot yield findings —
    // it degrades to the same "load failed" signal rather than a fabricated set.
    expect(loadSecretLeakFindings(() => 'not a frame block at all')).toBeUndefined();
  });
});
