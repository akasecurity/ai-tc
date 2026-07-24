/**
 * Model-judge consent — the distinct opt-in that gates sending findings to the
 * model API (the `/aka:setup` judge's `claude -p` egress). This is separate from
 * the historical-access grant, which only governs READING local transcripts.
 * The judge refuses to run unless the stored consent is present AND matches the
 * current payload-shape version.
 */
import type { WorkspaceSettings } from '@akasecurity/schema';
import { MODEL_JUDGE_PAYLOAD_VERSION } from '@akasecurity/schema';

// The current judge-payload shape version, re-exported from the schema (the
// single source of truth, also read by the web dashboard). Bumped when the
// payload sent to the model changes, so a consent recorded against an older
// shape stops counting as valid and the user is asked again.
export { MODEL_JUDGE_PAYLOAD_VERSION };

// True only when the user has recorded consent AND that consent covers the
// current payload shape. Absent consent or a stale payloadVersion is false.
export function isModelJudgeConsentValid(consent: WorkspaceSettings['modelJudgeConsent']): boolean {
  return consent?.payloadVersion === MODEL_JUDGE_PAYLOAD_VERSION;
}
