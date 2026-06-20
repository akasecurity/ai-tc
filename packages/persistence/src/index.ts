export type { InventoryContext, LocalDatabase, ResolvedInventory } from './database.ts';
export { openLocalDatabase } from './database.ts';
export type { FingerprintKey } from './fingerprint.ts';
export {
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from './fingerprint.ts';
export {
  classifiedDataId,
  inspectionDefinitionId,
  inspectionFindingId,
  inventoryId,
  llmCallId,
  normalizeHost,
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
  migrateLegacyLayout,
  settingsDir,
} from './local-layout.ts';
export {
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  DB_FILENAME,
  ensureDataDirSync,
  tightenPerms,
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
export { SqliteInspectionDefinitionsRepository } from './repositories/inspection-definitions.ts';
export { SqliteInspectionFindingsRepository } from './repositories/inspection-findings.ts';
export type { InstalledPackCounts } from './repositories/installed-packs.ts';
export { SqliteInstalledPacksRepository } from './repositories/installed-packs.ts';
export { SqliteInventoryRepository } from './repositories/inventory.ts';
export { SqliteInventoryAssetsRepository } from './repositories/inventory-assets.ts';
export { SqlitePoliciesRepository } from './repositories/policies.ts';
export { SqlitePolicyCatalogRepository } from './repositories/policy-catalog.ts';
export type { Resolution, ResolutionInput } from './repositories/resolutions.ts';
export { SqliteResolutionsRepository } from './repositories/resolutions.ts';
export type { ScanLedgerEntry, ScanLedgerState } from './repositories/scan-ledger.ts';
export { SqliteScanLedgerRepository } from './repositories/scan-ledger.ts';
export { SqliteSecurityRepository } from './repositories/security.ts';
export { SqliteSharesRepository } from './repositories/shares.ts';
export { SqliteSourceProjectRepository } from './repositories/source-project.ts';
export { compareBinaryVersions } from './semver.ts';
export { applyOnboarding, readWorkspaceSettings } from './settings.ts';
