// Derives the stable, content-addressed key that correlates an AT-REST
// finding across re-scans of the same file, so a later scan that re-detects
// the same underlying issue reconciles onto the same `findings` row (via
// SqliteFindingsRepository's `ON CONFLICT (finding_key)` upsert) instead of
// minting a duplicate. Only at-rest (worktree-scan, kind: 'code_change')
// findings get one — see `createPluginRuntime`'s capture(); in-flight captures
// (prompt/response) are streamed once and never re-scanned, so there is
// nothing to correlate against.
//
// Formula: sha256(ruleId + '\0' + normalizedPath + '\0' + valueFingerprint).
// `valueFingerprint` is the SAME keyed HMAC fingerprint used for detection
// exceptions / blocked_detections (see fingerprint.ts's fingerprintValue) —
// callers fall back to the masked match when no fingerprint key is available
// (no dataDir), so a key is still produced; see runtime.ts.
import { createHash } from 'node:crypto';

export interface FindingKeyInput {
  ruleId: string;
  filePath: string;
  valueFingerprint: string;
}

// A finding key must stay stable across re-scans on the same machine; this
// also keeps it stable if a backslash ever leaks in from a Windows-style path.
function normalizeFilePath(filePath: string): string {
  return filePath.replaceAll('\\', '/');
}

export function computeFindingKey(input: FindingKeyInput): string {
  const normalizedPath = normalizeFilePath(input.filePath);
  return createHash('sha256')
    .update(`${input.ruleId}\0${normalizedPath}\0${input.valueFingerprint}`)
    .digest('hex');
}
