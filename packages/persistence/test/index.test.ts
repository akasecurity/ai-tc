import { describe, expect, it } from 'vitest';

import * as barrel from '../src/index.ts';

// The barrel's exported symbol set is the package's public API and must not
// change during internal restructuring. Type-only exports are invisible at
// runtime; this snapshot pins the value exports.
const PUBLIC_VALUE_EXPORTS = [
  'AmbiguousExceptionIdError',
  'BLOCKED_DETECTIONS_RETENTION_MS',
  'BLOCKED_DETECTIONS_TTL_MS',
  'DATA_DIR_MODE',
  'DATA_FILE_MODE',
  'DB_FILENAME',
  'DuplicateActiveExceptionError',
  'SqliteActivityRepository',
  'SqliteAuditEventsRepository',
  'SqliteClassifiedDataRepository',
  'SqliteConfigInventoryRepository',
  'SqliteDetectionsRepository',
  'SqliteEventsRepository',
  'SqliteExceptionsRepository',
  'SqliteFindingsRepository',
  'SqliteInspectionDefinitionsRepository',
  'SqliteInspectionFindingsRepository',
  'SqliteInstalledPacksRepository',
  'SqliteInventoryAssetsRepository',
  'SqliteInventoryRepository',
  'SqlitePoliciesRepository',
  'SqlitePolicyCatalogRepository',
  'SqliteResolutionsRepository',
  'SqliteRuleProbeCacheRepository',
  'SqliteScanLedgerRepository',
  'SqliteSecurityRepository',
  'SqliteSharesRepository',
  'SqliteSourceProjectRepository',
  'applyOnboarding',
  'capWarnEraEnforcementOnce',
  'classifiedDataId',
  'compareBinaryVersions',
  'dataDir',
  'dbPath',
  'defaultDataDir',
  'ensureDataDir',
  'ensureDataDirSync',
  'ensureLayoutDirSync',
  'fingerprintValue',
  'inspectionDefinitionId',
  'inspectionFindingId',
  'inventoryId',
  'llmCallId',
  'loadOrCreateFingerprintKey',
  'migrateLegacyLayout',
  'normalizeHost',
  'openLocalDatabase',
  'readFingerprintKey',
  'readWorkspaceSettings',
  'rotateFingerprintKey',
  'settingsDir',
  'shareCallSiteId',
  'shareDestinationId',
  'shareEndpointId',
  'sourceProjectId',
  'tightenPerms',
  'toolCallId',
];

describe('package barrel', () => {
  it('exports exactly the pinned public symbol set', () => {
    expect(Object.keys(barrel).sort()).toEqual(PUBLIC_VALUE_EXPORTS);
  });
});
