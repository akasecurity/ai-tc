/**
 * Model-judge consent — the distinct opt-in that gates sending findings to the
 * model API (the aka-setup judge's `antigravity exec` egress). This is separate from
 * the historical-access grant, which only governs READING local rollouts.
 * The judge refuses to run unless the stored consent is present AND matches the
 * current payload-shape version.
 *
 * Both the version constant and the validity predicate live in
 * `@akasecurity/schema` — the dashboard and CLI read the same definition, so
 * "granted" cannot mean one thing to the judge and another to the settings UI.
 * They are re-exported here so the plugin's triage code has one local import.
 */
export { isModelJudgeConsentValid, MODEL_JUDGE_PAYLOAD_VERSION } from '@akasecurity/schema';
