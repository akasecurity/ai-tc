// The exception fingerprint key machinery now lives in @akasecurity/persistence,
// shared with the CLI and the OSS web-ui (which may not import the plugin SDK).
// This module is a re-export shim so existing SDK consumers keep importing it
// from here. Semantics are load-bearing and unchanged: absence mints a key,
// corruption throws (fail-secure), rotation is invalidation.
export type { FingerprintKey } from '@akasecurity/persistence';
export {
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from '@akasecurity/persistence';
