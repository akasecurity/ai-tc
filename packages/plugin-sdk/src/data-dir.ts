// The ~/.aka layout + permission modes now live in @akasecurity/persistence (the
// lowest layer that touches the store), shared with the CLI and the OSS web-ui.
// This module is a re-export shim so existing SDK consumers keep importing them
// from here.
// Imported through the `./sqlite-free` entry, never the root: a bundle that
// ships without the store layer reaches this module, and the root carries it all.
export {
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  dataDir,
  dbPath,
  defaultDataDir,
  ensureDataDir,
  ensureLayoutDirSync as ensureDataDirSync,
  migrateLegacyLayout,
  settingsDir,
} from '@akasecurity/persistence/sqlite-free';
