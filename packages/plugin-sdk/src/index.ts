export type { PluginConfig } from './config.ts';
export { applyOnboarding, loadConfig } from './config.ts';
export type { ResolveConfigInventoryInput } from './config-inventory.ts';
export { resolveConfigInventory } from './config-inventory.ts';
export {
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  dataDir,
  dbPath,
  defaultDataDir,
  ensureDataDir,
  ensureDataDirSync,
  migrateLegacyLayout,
  settingsDir,
} from './data-dir.ts';
export type {
  CaptureRecord,
  DataGateway,
  ScanLedgerEntry,
  ScanLedgerState,
} from './data-gateway.ts';
export type { BuildEventInput } from './events.ts';
export { buildIngestEvent, contentHashOf } from './events.ts';
export type { FindingKeyInput } from './finding-key.ts';
export { computeFindingKey } from './finding-key.ts';
export type { FingerprintKey } from './fingerprint.ts';
export {
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from './fingerprint.ts';
export type { ResolveInventoryInput } from './inventory-resolver.ts';
export { resolveInventoryContext } from './inventory-resolver.ts';
export type { ScanFinding } from './mask.ts';
export { maskText, scanText } from './mask.ts';
export { claimOnboardingNudge, claimSessionStart } from './nudge.ts';
export type { PostureChange } from './posture.ts';
export { applyCategoryPosture, detectPostureChanges, severityFloorPosture } from './posture.ts';
export { resolveProjectFiles } from './project-files.ts';
export type { Provider, ProviderOrUnknown, ResolvedProvider } from './provider.ts';
export { providerFromModelId, resolveProvider } from './provider.ts';
export type { EgressHit } from './raw-egress.ts';
export { assertRawFree, maskContextSlice, RawEgressError, safeMaskedMatch } from './raw-egress.ts';
export {
  resolveGitBranch,
  resolveHeadRoot,
  resolveRepo,
  resolveRepoIdentity,
  resolveRepoNwo,
  resolveWorktreeRoot,
} from './repo.ts';
export {
  bundledDetections,
  registerBundledPacks,
  registerRulePack,
  uniqueRuleIds,
} from './rule-packs.ts';
export type { CaptureOptions, PluginRuntime } from './runtime.ts';
export { createPluginRuntime } from './runtime.ts';
export { throttled } from './throttle.ts';
export type {
  AkaPluginAdapter,
  BlockedDetectionRef,
  CaptureHooks,
  CaptureInput,
  CaptureResult,
} from './types.ts';
export { maskMatch } from '@akasecurity/detections';
// The read-time token cost/rollup logic moved to `@akasecurity/schema` (pure, no
// Node-API deps) so the OSS Activity surfaces + CLI/TUI can price tokens without
// importing the plugin SDK. Re-exported here so existing plugin/runtime callers
// (standalone-gateway, render.ts) keep their `@akasecurity/plugin-sdk` import.
export type { CostModel, CostUsage, ModelPrice } from '@akasecurity/schema';
export type { LlmCallLeaf } from '@akasecurity/schema';
export { defaultCostModel } from '@akasecurity/schema';
export {
  aggregateTokenUsage,
  buildTokenReports,
  formatCostTotal,
  formatUsd,
} from '@akasecurity/schema';
// Posture evaluation re-exported for @akasecurity/plugin-runtime, which may not
// depend on @akasecurity/detections directly (the SDK is its one detections door).
export { configPostureDefinitions, evaluateConfigPosture } from '@akasecurity/detections';
// Read-projection DTOs now live in @akasecurity/schema; re-exported so the SDK's public
// surface is unchanged for the renderers that consume them.
export type {
  DayActivity,
  FindingView,
  HealthSummary,
  SessionTokenReport,
  SourceTool,
  TokenRollup,
} from '@akasecurity/schema';
