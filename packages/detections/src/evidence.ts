import type { DetectionCategory, Rule, RuleEvidence } from '@akasecurity/schema';

// Bundled rules whose matched text is a code pattern rather than a sensitive
// value. A finding of one of these shows its matched code readable in the
// dashboard excerpt; every other rule's match is redacted there.
//
// Kept here rather than as `evidence` in the rule files: an older plugin build
// parses installed rules strictly and would drop a rule carrying a key it does
// not know. The three code-flaw rules whose match contains a real secret value
// (`hardcoded-password`, `hardcoded-secret-key`, `dev-placeholder-secret`) are
// deliberately absent.
const BUNDLED_CODE_EVIDENCE: ReadonlySet<string> = new Set([
  'code-flaws/auth-jwt-no-verify',
  'code-flaws/auth-ssl-verify-false',
  'code-flaws/cmd-inject-exec',
  'code-flaws/cmd-inject-node-exec',
  'code-flaws/cmd-inject-shell',
  'code-flaws/crypto-insecure-random',
  'code-flaws/crypto-weak-hash-md5',
  'code-flaws/crypto-weak-hash-sha1',
  'code-flaws/deser-java-ois',
  'code-flaws/deser-pickle',
  'code-flaws/deser-yaml-unsafe',
  'code-flaws/dev-debug-enabled',
  'code-flaws/dev-wildcard-cors',
  'code-flaws/eval-dynamic-exec',
  'code-flaws/path-traversal-join',
  'code-flaws/path-traversal-open',
  'code-flaws/prototype-pollution-merge',
  'code-flaws/regex-redos-backtrack',
  'code-flaws/sql-inject-concat',
  'code-flaws/sql-inject-concat-dot',
  'code-flaws/sql-inject-format',
  'code-flaws/sql-inject-interp',
  'code-flaws/ssrf-user-url',
  'code-flaws/xss-dangerously-set',
  'code-flaws/xss-inner-html',
  'code-flaws/xss-unescaped-render',
]);

// Categories whose matches are values by definition. A rule in one of them is
// never treated as code, whatever it declares: a pulled or custom rule could
// otherwise leave a credential readable in an excerpt.
const VALUE_CATEGORIES: ReadonlySet<DetectionCategory> = new Set([
  'secret',
  'pii',
  'financial',
  'phi',
]);

/**
 * Whether a rule's matched text is a code pattern (`'code'`) or a sensitive
 * value (`'value'`). A rule's own `evidence` field wins, except that a rule in a
 * value category is always `'value'`; otherwise a bundled code-pattern rule is
 * `'code'` and everything else is `'value'`, so a rule nobody classified is
 * masked.
 */
export function ruleEvidence(
  rule: Pick<Rule, 'id' | 'evidence'> & { category?: DetectionCategory | undefined },
): RuleEvidence {
  if (rule.category !== undefined && VALUE_CATEGORIES.has(rule.category)) return 'value';
  if (rule.evidence !== undefined) return rule.evidence;
  return BUNDLED_CODE_EVIDENCE.has(rule.id) ? 'code' : 'value';
}

/** The bundled rule ids classified as code evidence, for the guard that pins them. */
export function bundledCodeEvidenceIds(): readonly string[] {
  return [...BUNDLED_CODE_EVIDENCE];
}
