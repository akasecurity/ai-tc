import { describe, expect, it } from 'vitest';

import * as barrel from '../src/index.ts';

/**
 * The barrel's exported symbol set is the package's public API and must not
 * change during internal restructuring. It is the workspace's highest-stakes
 * barrel to leave unpinned: `cli`, all three plugin bundles and the browser
 * extension's native host each set `noExternal: [/^@akasecurity\//]`, so this
 * package is inlined into five shipped artifacts, and an export dropped in a
 * refactor reaches Claude Code, Codex and Antigravity in one release. (It is the
 * extension's CONTENT SCRIPT that takes the `./browser` subpath instead; that
 * subpath is out of scope here — see the limits below.)
 *
 * Before this file, nothing in the package saw such a drop. Its own suites each
 * reach their subject through that module's own path (`../src/data-dir.ts`,
 * `../src/mask.ts`, ...), never through the index, so deleting a line from the
 * export block broke none of them. And typecheck binds only what some in-repo
 * file imports, while the SDK publishes plenty that nothing does —
 * `ensureDataDir` is the worked example: deleting it from `src/index.ts` left
 * both `pnpm --filter @akasecurity/plugin-sdk test` and `typecheck` green.
 *
 * That residue is what this file is worth, and it is worth being exact about.
 * Consumers elsewhere in the workspace do import the barrel — suites in `cli`,
 * `local-ops` and `plugin-runtime` among them — so an export THEY use is already
 * covered by typecheck. What is left is the roughly one name in five below that
 * nothing in the tree imports, for which this is the only gate.
 *
 * The list is an EXACT set rather than a floor. A floor would forbid removals
 * while letting an unreviewed addition through, and on a surface that ships
 * inlined the addition is the half that matters more: it is what the package
 * commits to supporting from that release on. Keep the list in
 * `Object.keys().sort()` order — code-unit order, so every uppercase name sorts
 * before every lowercase one — because the comparison below is positional.
 *
 * Three limits, all deliberate: this pins the NAMES on the `.` entry and nothing
 * more.
 *
 * - **Type-only exports are invisible.** `export type { ... }` is erased at
 *   runtime, so `Object.keys` never sees one. `persistence/test/index.test.ts`
 *   records the same limit; the second case below pins it here rather than
 *   leaving it as prose.
 * - **A rebind under an existing name is invisible.** The comparison is over key
 *   sets, so `export { dataDir as settingsDir }` changes nothing it can see —
 *   and nothing else catches that one either: both are `(base?: string) =>
 *   string`, so the whole workspace typechecks clean while `aka init` creates
 *   and chmods the wrong directory under the owner-only contract. How far that
 *   reaches depends on the pair. A rebind between DIFFERENTLY typed exports is
 *   caught, just not here: `export { maskText as scanText }` reds `tsc` at the
 *   three plugins' `src/history/usage.ts`, which destructure `scanText`'s object
 *   result. Do not read a green run here as identity, and do not read it as the
 *   only gate either.
 * - **The subpath entries are out of scope.** `package.json` also publishes
 *   `./scan-worker`, `./bare-command` and `./browser`; this covers `.` alone,
 *   the entry plugin authors import.
 *
 * Scope: `persistence` is the only other barrel pinned this way, and neither is
 * special — every barrel carries exports nothing consumes. `detections`,
 * `local-ops`, `scanner`, `setup-wizard` and `plugin-runtime` are each small
 * enough to take a copy of this file. `schema` is not, at several hundred
 * exports: a list edited on nearly every PR touching the package has stopped
 * being a review gate, and wants a derived check instead.
 *
 * Some names below are re-exported from `@akasecurity/detections` and
 * `@akasecurity/schema` rather than defined here (`maskMatch`, the egress
 * extraction group, the token-cost group), so a symbol can leave this surface
 * because a DIFFERENT package dropped it — a change no edit to `src/index.ts`
 * would show in review.
 */
const PUBLIC_VALUE_EXPORTS = [
  'DATA_DIR_MODE',
  'DATA_FILE_MODE',
  'EGRESS_CODE_EXTENSIONS',
  'EGRESS_VERSION_MATERIAL',
  'ISOLATED_PROBE_BUDGET_MS',
  'ISOLATED_SCAN_BUDGET_MS',
  'ISOLATED_START_BUDGET_MS',
  'LOCKFILE_BASENAMES',
  'POINTER_UNAVAILABLE_TEXT',
  'PROJECT_WALK_BOUNDS',
  'RawEgressError',
  'THIRTY_DAYS_MS',
  'aggregateTokenUsage',
  'antigravityProviderFromModelId',
  'applyCategoryPosture',
  'applyOnboarding',
  'applySetupTriageSuppressions',
  'assertRawFree',
  'buildIngestEvent',
  'buildModelRefusalEvent',
  'buildTokenReports',
  'bundledDetections',
  'childRel',
  'claimOnboardingNudge',
  'claimSessionStart',
  'claudeCodeModelFromRecord',
  'codexModelFromRecord',
  'codexProviderFromModelId',
  'computeFindingKey',
  'configPostureDefinitions',
  'contentHashOf',
  'createGuardedScanner',
  'createIsolatedScanner',
  'createPluginRuntime',
  'createPolicyResolver',
  'createVaultGlue',
  'dataDir',
  'dbPath',
  'decideProhibitedModelTurn',
  'defaultCostModel',
  'defaultDataDir',
  'describePointerSafe',
  'detectPostureChanges',
  'detokenizeText',
  'dropShieldedFindings',
  'ensureDataDir',
  'ensureDataDirSync',
  'evaluateConfigPosture',
  'evaluateIgnore',
  'extractEgress',
  'extractManifestSdks',
  'filterUnsafeRules',
  'fingerprintValue',
  'formatCostTotal',
  'formatUsd',
  'hasLocalStoreMaintenance',
  'hasPointer',
  'isCurrentKeyVersion',
  'isModelProhibited',
  'isVendoredPath',
  'loadConfig',
  'loadOrCreateFingerprintKey',
  'manifestKindOf',
  'maskContextSlice',
  'maskMatch',
  'maskText',
  'matchProhibitedSpawnModel',
  'migrateLegacyLayout',
  'modelFromTranscript',
  'modelFromTranscriptTail',
  'normalizeModelId',
  'offersMaintenance',
  'prohibitedModelMessage',
  'providerFromModelId',
  'quarantineRule',
  'readFingerprintKey',
  'readIgnoreLayer',
  'readSessionModel',
  'recordSessionModel',
  'registerBundledPacks',
  'registerRulePack',
  'resolveAntigravityProvider',
  'resolveCodexProvider',
  'resolveConfigInventory',
  'resolveEgress',
  'resolveGitBranch',
  'resolveHeadRoot',
  'resolveInventoryContext',
  'resolveNonGitProject',
  'resolveProjectFiles',
  'resolveProvider',
  'resolveRepo',
  'resolveRepoIdentity',
  'resolveRepoNwo',
  'resolveWorktreeRoot',
  'rotateFingerprintKey',
  'ruleProbeKey',
  'safeMaskedMatch',
  'scanText',
  'settingsDir',
  'severityFloorPosture',
  'shieldPointers',
  'substituteModelPointers',
  'throttled',
  'toPosix',
  'tokenizeText',
  'tokenizeValue',
  'uniqueRuleIds',
  'withLayer',
];

describe('package barrel', () => {
  it('exports exactly the pinned public symbol set', () => {
    expect(Object.keys(barrel).sort()).toEqual(PUBLIC_VALUE_EXPORTS);
  });

  // Pins the first limit above instead of only stating it. `PluginConfig` is
  // exported as a type, so it must stay absent from the runtime namespace: this
  // goes red if it is ever promoted to a value export, or if a transform starts
  // surfacing type-only exports on the namespace object.
  it('does not surface type-only exports at runtime', () => {
    expect(Object.keys(barrel)).not.toContain('PluginConfig');
  });
});
