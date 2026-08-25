// Attached mode: what a machine does once its settings name a control plane and
// a credential for that plane is on disk.
//
// Everything here is inert on a standalone machine. `resolve.ts` builds the
// decorator only when both halves of an attachment are present and agree, so a
// machine that has never attached — the overwhelming majority — constructs none
// of it and behaves exactly as it did before this existed.
export type { ControlPlaneFailure } from './failure.ts';
export { classifyFailure } from './failure.ts';
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
export type { PolicyStore, StoredPolicyBundle } from './policy-store.ts';
export { createPolicyStore } from './policy-store.ts';
export type { PolicySyncOutcome, PolicySyncResult } from './policy-sync.ts';
export { pullPolicyBundle, runPolicySync, SYNC_REQUEST_TIMEOUT_MS } from './policy-sync.ts';
export type { PostureReporterDeps } from './posture-reporter.ts';
export { createPostureReporter, POSTURE_REPORT_INTERVAL_MS } from './posture-reporter.ts';
export type { StoreReadout } from './posture-snapshot.ts';
export { readStorePosture } from './posture-snapshot.ts';
export type { PostureState, PostureStore } from './posture-store.ts';
export { createPostureStore } from './posture-store.ts';
export type { RenderAttachedStatusDeps } from './status.ts';
export { renderAttachedStatus, renderPolicyLine } from './status.ts';
export { runAttachedSync } from './sync-entry.ts';
export { readSyncState, SYNC_STATE_FILENAME, syncStatePath, writeSyncState } from './sync-state.ts';
export type { SyncTriggerDeps } from './sync-trigger.ts';
export {
  SYNC_MARKER_NAME,
  SYNC_THROTTLE_MS,
  triggerPolicySync,
} from './sync-trigger.ts';
