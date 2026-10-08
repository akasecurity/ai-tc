// The `./sqlite-free` entry: the slice of this package that never loads
// `node:sqlite`, for code that is bundled without the store layer.
//
// `@akasecurity/plugin-sdk` re-exports these on the paths its runtime reaches,
// and an SDK built on it ships those paths into processes that never open the
// store. Importing the root entry instead keeps every module it re-exports,
// `database.ts` among them, because this package is not side-effect-free.
//
// Everything here is also exported from the root entry. Only add a module
// whose own imports, followed all the way down, load no `node:sqlite`; the
// plugin-sdk suite `sdk-import-graph.test.ts` fails if one does.
export type { FindingKeyInput } from './finding-key.ts';
export { computeFindingKey } from './finding-key.ts';
export type { FingerprintKey } from './fingerprint.ts';
export {
  fingerprintValue,
  isCurrentKeyVersion,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from './fingerprint.ts';
export { captureWireId } from './ids.ts';
export {
  dataDir,
  dbPath,
  defaultDataDir,
  ensureDataDir,
  ensureLayoutDirSync,
  migrateLegacyLayout,
  settingsDir,
} from './local-layout.ts';
export { DATA_DIR_MODE, DATA_FILE_MODE } from './paths.ts';
