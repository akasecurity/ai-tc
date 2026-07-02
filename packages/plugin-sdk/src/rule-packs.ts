import { registerPack } from '@akasecurity/detections';
import type { InstalledPackInput } from '@akasecurity/schema';
import { Rule } from '@akasecurity/schema';

import codeFlawsAuthJwtNoVerify from '../../../rules/code-flaws/auth-jwt-no-verify.json';
import codeFlawsAuthSslVerifyFalse from '../../../rules/code-flaws/auth-ssl-verify-false.json';
import codeFlawsCmdInjectExec from '../../../rules/code-flaws/cmd-inject-exec.json';
import codeFlawsCmdInjectNodeExec from '../../../rules/code-flaws/cmd-inject-node-exec.json';
import codeFlawsCmdInjectShell from '../../../rules/code-flaws/cmd-inject-shell.json';
import codeFlawsCryptoInsecureRandom from '../../../rules/code-flaws/crypto-insecure-random.json';
import codeFlawsCryptoWeakHashMd5 from '../../../rules/code-flaws/crypto-weak-hash-md5.json';
import codeFlawsCryptoWeakHashSha1 from '../../../rules/code-flaws/crypto-weak-hash-sha1.json';
import codeFlawsDeserJavaOis from '../../../rules/code-flaws/deser-java-ois.json';
import codeFlawsDeserPickle from '../../../rules/code-flaws/deser-pickle.json';
import codeFlawsDeserYamlUnsafe from '../../../rules/code-flaws/deser-yaml-unsafe.json';
import codeFlawsDevDebugEnabled from '../../../rules/code-flaws/dev-debug-enabled.json';
import codeFlawsDevPlaceholderSecret from '../../../rules/code-flaws/dev-placeholder-secret.json';
import codeFlawsDevWildcardCors from '../../../rules/code-flaws/dev-wildcard-cors.json';
import codeFlawsEvalDynamicExec from '../../../rules/code-flaws/eval-dynamic-exec.json';
import codeFlawsHardcodedPassword from '../../../rules/code-flaws/hardcoded-password.json';
import codeFlawsHardcodedSecretKey from '../../../rules/code-flaws/hardcoded-secret-key.json';
import codeFlawsManifest from '../../../rules/code-flaws/manifest.json';
import codeFlawsPathTraversalJoin from '../../../rules/code-flaws/path-traversal-join.json';
import codeFlawsPathTraversalOpen from '../../../rules/code-flaws/path-traversal-open.json';
import codeFlawsPrototypePollutionMerge from '../../../rules/code-flaws/prototype-pollution-merge.json';
import codeFlawsRegexRedosBacktrack from '../../../rules/code-flaws/regex-redos-backtrack.json';
import codeFlawsSqlInjectConcat from '../../../rules/code-flaws/sql-inject-concat.json';
import codeFlawsSqlInjectConcatDot from '../../../rules/code-flaws/sql-inject-concat-dot.json';
import codeFlawsSqlInjectFormat from '../../../rules/code-flaws/sql-inject-format.json';
import codeFlawsSqlInjectInterp from '../../../rules/code-flaws/sql-inject-interp.json';
import codeFlawsSsrfUserUrl from '../../../rules/code-flaws/ssrf-user-url.json';
import codeFlawsXssDangerouslySet from '../../../rules/code-flaws/xss-dangerously-set.json';
import codeFlawsXssInnerHtml from '../../../rules/code-flaws/xss-inner-html.json';
import codeFlawsXssUnescapedRender from '../../../rules/code-flaws/xss-unescaped-render.json';
import coreEmail from '../../../rules/core-pii/email.json';
import corePiiManifest from '../../../rules/core-pii/manifest.json';
import coreSsn from '../../../rules/core-pii/ssn.json';
import secretsAwsAccessKey from '../../../rules/secrets/aws-access-key.json';
import secretsGithubPat from '../../../rules/secrets/github-pat.json';
import secretsManifest from '../../../rules/secrets/manifest.json';

// Publisher handle the bundled (AKA-shipped) packs are recorded under in the
// local detections inventory — lets the dashboard tell library packs apart from
// user-authored (custom) ones, and pairs with packId as the upsert key.
const BUNDLED_NAMESPACE = 'aka';

// The rule packs shipped with every AKA plugin. The JSON (rules + manifest) is
// inlined into the hook scripts at build time (tsup bundles it via noExternal),
// so detection works with zero network and zero install steps. `packId` is the
// manifest id (also the prefix of every rule id, e.g. `core-pii/email`), so it
// joins back to findings.rule_id. Owned by the SDK so a new plugin (VSCode,
// Cursor…) reuses the exact same bundled coverage.
//
// NOTE: only a subset of each pack's rules is bundled today (the rest of the
// manifest's rules land as coverage grows) — `rawRules` is the truth for what's
// loaded, while `version`/`name` come from the manifest.
// TODO: generate these entries from the pack manifests instead of by hand.
interface BundledPack {
  packId: string;
  name: string;
  version: string;
  rawRules: unknown[];
}

const BUNDLED_PACKS: readonly BundledPack[] = [
  {
    packId: secretsManifest.id,
    name: secretsManifest.name,
    version: secretsManifest.version,
    rawRules: [secretsAwsAccessKey, secretsGithubPat],
  },
  {
    packId: corePiiManifest.id,
    name: corePiiManifest.name,
    version: corePiiManifest.version,
    rawRules: [coreEmail, coreSsn],
  },
  {
    packId: codeFlawsManifest.id,
    name: codeFlawsManifest.name,
    version: codeFlawsManifest.version,
    rawRules: [
      codeFlawsSqlInjectConcat,
      codeFlawsSqlInjectConcatDot,
      codeFlawsSqlInjectFormat,
      codeFlawsSqlInjectInterp,
      codeFlawsCmdInjectShell,
      codeFlawsCmdInjectExec,
      codeFlawsCmdInjectNodeExec,
      codeFlawsXssInnerHtml,
      codeFlawsXssDangerouslySet,
      codeFlawsXssUnescapedRender,
      codeFlawsDeserPickle,
      codeFlawsDeserYamlUnsafe,
      codeFlawsDeserJavaOis,
      codeFlawsHardcodedPassword,
      codeFlawsHardcodedSecretKey,
      codeFlawsDevDebugEnabled,
      codeFlawsDevPlaceholderSecret,
      codeFlawsDevWildcardCors,
      codeFlawsAuthSslVerifyFalse,
      codeFlawsAuthJwtNoVerify,
      codeFlawsPathTraversalOpen,
      codeFlawsPathTraversalJoin,
      codeFlawsCryptoWeakHashMd5,
      codeFlawsCryptoWeakHashSha1,
      codeFlawsCryptoInsecureRandom,
      codeFlawsPrototypePollutionMerge,
      codeFlawsEvalDynamicExec,
      codeFlawsSsrfUserUrl,
      codeFlawsRegexRedosBacktrack,
    ],
  },
];

/**
 * Validate raw rule-file JSON (as bundled from `rules/<pack>/`) against the
 * versioned Rule schema and register it with the engine. Throws on invalid
 * rules — callers on the hook path wrap in their fail-open guard.
 */
export function registerRulePack(packId: string, rawRules: unknown[]): void {
  const rules = rawRules.map((raw) => Rule.parse(raw));
  registerPack({ id: packId, rules });
}

/** Register every bundled pack with the detection engine. */
export function registerBundledPacks(): void {
  for (const pack of BUNDLED_PACKS) registerRulePack(pack.packId, pack.rawRules);
}

// Memoized: the bundled JSON is inlined at build time, so the parsed inventory
// is constant for the process. resolveDataGateway calls bundledDetections() on
// every hook, so parsing once here avoids re-running Zod on the hook path.
// Callers treat the result as immutable (the gateway only reads it).
let cachedDetections: InstalledPackInput[] | undefined;

/**
 * The bundled packs as a detections inventory — the standalone gateway upserts
 * these into the local `installed_packs` table on open, so the Detections
 * dashboard can count detections/rules/active and compare each stored version
 * against the registry to flag updates. Parses the rules so the persisted
 * rules_json is the validated snapshot (the same shape the engine registers).
 */
export function bundledDetections(): InstalledPackInput[] {
  cachedDetections ??= BUNDLED_PACKS.map((pack) => ({
    namespace: BUNDLED_NAMESPACE,
    packId: pack.packId,
    version: pack.version,
    name: pack.name,
    rules: pack.rawRules.map((raw) => Rule.parse(raw)),
  }));
  return cachedDetections;
}

// Distinct rule ids across a finding set, joined for a one-line summary in the
// adapter's warn/redact system messages. Generic (no Claude-Code specifics), so
// it lives in the SDK for every adapter to reuse.
export function uniqueRuleIds(findings: { ruleId: string }[]): string {
  return [...new Set(findings.map((f) => f.ruleId))].join(', ');
}
