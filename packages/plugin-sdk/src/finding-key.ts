// The finding-key derivation now lives in @akasecurity/persistence, shared with
// the CLI / web-ui / local-ops (which must not import the plugin SDK) so an
// `aka scan` finding reconciles onto the same row as the plugin's worktree-scan
// capture. This module is a re-export shim so existing SDK consumers keep
// importing it from here (mirrors fingerprint.ts). The formula is load-bearing
// and unchanged.
export type { FindingKeyInput } from '@akasecurity/persistence';
export { computeFindingKey } from '@akasecurity/persistence';
