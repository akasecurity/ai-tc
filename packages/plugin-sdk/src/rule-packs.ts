import { registerPack } from '@aka/detections';
import { Rule } from '@aka/schema';

import coreEmail from '../../../rules/core-pii/email.json';
import coreSsn from '../../../rules/core-pii/ssn.json';
import secretsAwsAccessKey from '../../../rules/secrets/aws-access-key.json';
import secretsGithubPat from '../../../rules/secrets/github-pat.json';

/**
 * Validate raw rule-file JSON (as bundled from `rules/<pack>/`) against the
 * versioned Rule schema and register it with the engine. Throws on invalid
 * rules — callers on the hook path wrap in their fail-open guard.
 */
export function registerRulePack(packId: string, rawRules: unknown[]): void {
  const rules = rawRules.map((raw) => Rule.parse(raw));
  registerPack({ id: packId, rules });
}

/**
 * Register the rule packs shipped with every AKA plugin. The JSON is inlined
 * into the hook scripts at build time (tsup bundles it via noExternal), so
 * detection works with zero network and zero install steps. Owned by the SDK
 * so a new plugin (VSCode, Cursor…) reuses the exact same bundled coverage.
 * TODO: generate these imports from the pack manifests instead of by hand.
 */
export function registerBundledPacks(): void {
  registerRulePack('secrets', [secretsAwsAccessKey, secretsGithubPat]);
  registerRulePack('core-pii', [coreEmail, coreSsn]);
}

// Distinct rule ids across a finding set, joined for a one-line summary in the
// adapter's warn/redact system messages. Generic (no Claude-Code specifics), so
// it lives in the SDK for every adapter to reuse.
export function uniqueRuleIds(findings: { ruleId: string }[]): string {
  return [...new Set(findings.map((f) => f.ruleId))].join(', ');
}
