// Attached mode: what a machine does once its settings name a control plane and
// a credential for that plane is on disk.
//
// Everything here is inert on a standalone machine. `resolve.ts` builds the
// decorator only when both halves of an attachment are present and agree, so a
// machine that has never attached — the overwhelming majority — constructs none
// of it and behaves exactly as it did before this existed.
export { hashProjectKey, toEgressIngestRequest } from './egress-wire.ts';
export type { GatewayMeta } from './factory.ts';
// The device identity, and ONLY that: `aka attach` has to tell a deployment
// which machine is asking, and reading it through the same store the posture
// reporter uses is what keeps one laptop from presenting two identities.
export type {
  CommandScan,
  CommandSyncOutcome,
  DiscoverScan,
  RunCommandSyncDeps,
} from './command-sync.ts';
export {
  COMMAND_REQUEST_TIMEOUT_MS,
  COMMAND_SCAN_SCOPE,
  commandScanFor,
  runCommandSync,
} from './command-sync.ts';
export type { ControlPlaneFailure } from './failure.ts';
export { classifyFailure } from './failure.ts';
export type { ForwardDrops } from './forward-drops.ts';
export { FORWARD_DROPS_FILENAME, readForwardDrops, recordForwardDrops } from './forward-drops.ts';
export type { ForwardPolicy, ForwardResult } from './forward-policy.ts';
export {
  createForwardPolicy,
  DECISION_PATH_BUDGET_MS,
  FORWARD_BUDGET_MS,
  FORWARD_STATE_FILENAME,
  readForwardHealth,
} from './forward-policy.ts';
export type { AttachedClient, AttachedDataGatewayDeps } from './gateway.ts';
export { AttachedDataGateway } from './gateway.ts';
export type { HistorySyncOutcome, HistorySyncPhase, HistorySyncState } from './history-state.ts';
export {
  HISTORY_SYNC_STATE_FILENAME,
  historySyncStatePath,
  readHistorySyncState,
  writeHistorySyncState,
} from './history-state.ts';
export type { HistorySyncResult, RunHistorySyncDeps } from './history-sync.ts';
export {
  endpointFingerprint,
  HISTORY_PASS_BUDGET_MS,
  HISTORY_REQUEST_TIMEOUT_MS,
  runHistorySync,
} from './history-sync.ts';
export { runHistorySyncPass } from './history-sync-entry.ts';
export type { HistorySyncTriggerDeps } from './history-sync-trigger.ts';
export {
  HISTORY_SYNC_MARKER_NAME,
  HISTORY_SYNC_SCRIPT_NAME,
  HISTORY_SYNC_THROTTLE_MS,
  triggerHistorySync,
} from './history-sync-trigger.ts';
export type { PluginBuildInfo } from './plugin-block.ts';
export { createPluginBlock, readManifestBuild } from './plugin-block.ts';
export type { PolicyStore, StoredPolicyBundle } from './policy-store.ts';
export { createPolicyStore } from './policy-store.ts';
export type { PolicySyncOutcome, PolicySyncResult } from './policy-sync.ts';
export { pullPolicyBundle, runPolicySync, SYNC_REQUEST_TIMEOUT_MS } from './policy-sync.ts';
export type { PostureReporterDeps } from './posture-reporter.ts';
export { createPostureReporter, POSTURE_REPORT_INTERVAL_MS } from './posture-reporter.ts';
export type { StoreReadout } from './posture-snapshot.ts';
export { readStorePosture } from './posture-snapshot.ts';
export type { PostureState, PostureStore } from './posture-store.ts';
export { readDeviceIdentity } from './posture-store.ts';
export { createPostureStore } from './posture-store.ts';
export type { RenderAttachedStatusDeps } from './status.ts';
export { renderAttachedStatus, renderPolicyLine } from './status.ts';
export { runAttachedSync } from './sync-entry.ts';
export { readSyncState, SYNC_STATE_FILENAME, syncStatePath, writeSyncState } from './sync-state.ts';
export type { SyncTriggerDeps } from './sync-trigger.ts';
export {
  SYNC_MARKER_NAME,
  SYNC_SCRIPT_NAME,
  SYNC_THROTTLE_MS,
  triggerPolicySync,
} from './sync-trigger.ts';
