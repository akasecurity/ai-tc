export {
  ATTACHED_DERIVED_FILENAMES,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  ATTACHED_HISTORY_SYNC_STATE_FILENAME,
  ATTACHED_SYNC_STATE_FILENAME,
  clearAttachmentDerivedState,
  POLICY_CACHE_FILENAME,
} from './attached-derived.ts';
export type {
  CredentialFileRead,
  CredentialState,
  CredentialUnusableReason,
} from './control-plane-credential.ts';
export {
  controlPlaneCredentialPath,
  isSafeEndpoint,
  readControlPlaneCredential,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  removeControlPlaneCredential,
  writeControlPlaneCredential,
} from './control-plane-credential.ts';
export type { InventoryContext, LocalDatabase, ResolvedInventory } from './database.ts';
export { openLocalDatabase } from './database.ts';
export type { ExceptionPolicyProvider, RevealDecision } from './exception-policy.ts';
export { UserGrantPolicyProvider } from './exception-policy.ts';
export type { FileLockFailure, FileLockOptions } from './file-lock.ts';
export { FileLockError, withFileLock } from './file-lock.ts';
export type { FindingKeyInput } from './finding-key.ts';
export { computeFindingKey } from './finding-key.ts';
export type { FingerprintKey } from './fingerprint.ts';
export {
  EXCEPTION_KEY_FILENAME,
  fingerprintValue,
  isCurrentKeyVersion,
  keyStateOf,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from './fingerprint.ts';
export type { LocalHistoryPreview } from './history-preview.ts';
export { readLocalHistoryPreview } from './history-preview.ts';
export {
  captureId,
  classifiedDataId,
  inspectionDefinitionId,
  inspectionFindingId,
  inventoryId,
  llmCallId,
  normalizeHost,
  promptId,
  shareCallSiteId,
  shareDestinationId,
  shareEndpointId,
  sourceProjectId,
  toolCallId,
} from './ids.ts';
export {
  dataDir,
  dbPath,
  defaultDataDir,
  ensureDataDir,
  ensureLayoutDirSync,
  keysDir,
  migrateLegacyLayout,
  settingsDir,
} from './local-layout.ts';
export {
  lockedAmong,
  managedContextOf,
  managedSettingsPaths,
  overlayManagedSettings,
  readManagedSettings,
} from './managed-settings.ts';
export {
  createOwnerOnlyFileSync,
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  DB_FILENAME,
  dbSidecars,
  ensureDataDirSync,
  KeyUnclaimableError,
  tightenFile,
  tightenPerms,
  writeOwnerOnlyFileSync,
} from './paths.ts';
export type {
  ActivityReadPort,
  DashboardViews,
  DetectionsReadPort,
  EventsReadPort,
  FindingsReadPort,
  InstalledPacksReadPort,
  InventoryReadPort,
  PoliciesReadPort,
  PolicyCatalogReadPort,
  SecurityViews,
  SharesReadPort,
} from './ports.ts';
export { SqliteActivityRepository } from './repositories/activity.ts';
export { SqliteAuditEventsRepository } from './repositories/audit-events.ts';
export { SqliteClassifiedDataRepository } from './repositories/classified-data.ts';
export { SqliteConfigInventoryRepository } from './repositories/config-inventory.ts';
export { SqliteDetectionsRepository } from './repositories/detections.ts';
export { SqliteEventsRepository } from './repositories/events.ts';
export type {
  BlockedDetection,
  BlockedDetectionInput,
  CreateExceptionInput,
} from './repositories/exceptions.ts';
export {
  AmbiguousExceptionIdError,
  BLOCKED_DETECTIONS_RETENTION_MS,
  BLOCKED_DETECTIONS_TTL_MS,
  DuplicateActiveExceptionError,
  SqliteExceptionsRepository,
} from './repositories/exceptions.ts';
export { SqliteFindingsRepository } from './repositories/findings.ts';
export type {
  HistorySyncCounts,
  HistorySyncInspectionRow,
  HistorySyncLease,
} from './repositories/history-sync.ts';
export {
  SqliteHistorySyncRepository,
  STRUCTURAL_EVENT_TYPES,
} from './repositories/history-sync.ts';
export { SqliteInspectionDefinitionsRepository } from './repositories/inspection-definitions.ts';
export { SqliteInspectionFindingsRepository } from './repositories/inspection-findings.ts';
export type {
  InstalledPackCounts,
  InstalledRuleset,
  RejectedRule,
} from './repositories/installed-packs.ts';
export { SqliteInstalledPacksRepository } from './repositories/installed-packs.ts';
export { SqliteInventoryRepository } from './repositories/inventory.ts';
export { SqliteInventoryAssetsRepository } from './repositories/inventory-assets.ts';
export { SqlitePoliciesRepository } from './repositories/policies.ts';
export { SqlitePolicyCatalogRepository } from './repositories/policy-catalog.ts';
export type { Resolution, ResolutionInput } from './repositories/resolutions.ts';
export { SqliteResolutionsRepository } from './repositories/resolutions.ts';
export type { RuleProbeCacheEntry } from './repositories/rule-probe-cache.ts';
export { SqliteRuleProbeCacheRepository } from './repositories/rule-probe-cache.ts';
export type { ScanLedgerEntry, ScanLedgerState } from './repositories/scan-ledger.ts';
export { SqliteScanLedgerRepository } from './repositories/scan-ledger.ts';
export type { VaultDerefInsert, VaultRow, VaultRowInsert } from './repositories/secret-vault.ts';
export { SqliteSecretVaultRepository } from './repositories/secret-vault.ts';
export { SqliteSecurityRepository } from './repositories/security.ts';
export {
  MAX_EGRESS_CALL_SITES_PER_PROJECT,
  SqliteSharesRepository,
} from './repositories/shares.ts';
export { SqliteSourceProjectRepository } from './repositories/source-project.ts';
export { compareBinaryVersions } from './semver.ts';
export type { OnboardingAnswers } from './settings.ts';
export type { EffectiveSettings } from './settings.ts';
export {
  applyOnboarding,
  ManagedFieldError,
  readEffectiveSettings,
  readWorkspaceSettings,
  SETTINGS_FILENAME,
} from './settings.ts';
export type { SymlinkedStorePath } from './store-symlinks.ts';
export { linkTarget, storeTargets, symlinkedStorePaths } from './store-symlinks.ts';
export {
  base32Decode,
  base32Encode,
  bindingInput,
  deriveSubkeys,
  formatPointer,
  signPointer,
  verifyPointerTag,
} from './vault/crypto.ts';
export type { KeyProvider, VaultKeyMaterial } from './vault/key-provider.ts';
export {
  createKeyProvider,
  FileKeyProvider,
  KeychainKeyProvider,
  VAULT_KEY_FILENAME,
  VaultKeyEpochMissingError,
} from './vault/key-provider.ts';
export type {
  DetokenizeOptions,
  DetokenizeResult,
  SecretVaultDeps,
  TokenizeMeta,
  TokenizeResult,
} from './vault/vault.ts';
export { CONSENT_ABSENT, SecretVault, UNAVAILABLE } from './vault/vault.ts';
export { capWarnEraEnforcementOnce } from './warn-era-cap.ts';
