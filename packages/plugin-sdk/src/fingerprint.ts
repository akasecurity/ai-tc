// The exception fingerprint key machinery now lives in @akasecurity/persistence,
// shared with the CLI and the OSS web-ui (which may not import the plugin SDK).
// This module is a re-export shim so existing SDK consumers keep importing it
// from here. Semantics are load-bearing and unchanged: absence mints a key,
// corruption throws (fail-secure), rotation is invalidation.
// Imported through the `./sqlite-free` entry, never the root: a bundle that
// ships without the store layer reaches this module, and the root carries it all.
export type { FingerprintKey } from '@akasecurity/persistence/sqlite-free';
export {
  fingerprintValue,
  isCurrentKeyVersion,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from '@akasecurity/persistence/sqlite-free';
