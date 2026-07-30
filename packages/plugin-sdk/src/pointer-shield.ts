// The pointer shield now lives in @akasecurity/detections, shared with every
// scan surface (the plugin's live hooks here, and local-ops' fs-scan pipeline
// behind `aka scan` and the dashboard folder scan) — the "no rule ever sees a
// pointer" guarantee must hold wherever the engine runs, not only in the
// plugin. This module is a re-export shim so existing SDK consumers keep
// importing it from here. Semantics are load-bearing and unchanged: pointer
// spans are blanked with same-length filler before the engine runs, and any
// finding touching a blanked span is dropped.
export type { ShieldedSpan, ShieldedText } from '@akasecurity/detections';
export { dropShieldedFindings, shieldPointers } from '@akasecurity/detections';
