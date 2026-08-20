// Zod contracts for the local store and everything that reads it.
//
// SHAPE IDS — the convention every file here follows. A shape that something
// else refers to BY NAME carries `.meta({ id })`, so a consumer walking these
// schemas emits it once and points at it thereafter. Query and path shapes
// deliberately do NOT carry one: a consumer expands their properties into
// individual parameters, and a parameter cannot be a reference to a named
// shape, so they stay inline. Adding an id to a query shape is the mistake this
// note exists to prevent — it produces a named component nothing can reference.

export * from './activity.ts';
export * from './config-inventory.ts';
export * from './detection.ts';
export * from './detection-build.ts';
export * from './egress-extraction.ts';
export * from './event.ts';
export * from './exception.ts';
export * from './exception-action.ts';
export * from './finding.ts';
export * from './findings-flat-build.ts';
export * from './findings-group-build.ts';
export * from './harness-map.ts';
export * from './installed-pack.ts';
export * from './inventory.ts';
export * from './local.ts';
export * from './managed.ts';
export * from './meta.ts';
export * from './policy.ts';
export * from './project-files.ts';
export * from './ranges.ts';
export * from './registry.ts';
export * from './remediation.ts';
export * from './rule.ts';
export * from './security.ts';
export * from './settings-action.ts';
export * from './setup-frame.ts';
export * from './shares.ts';
export * from './shares-access.ts';
export * from './triage.ts';
export * from './updates.ts';
export * from './vault.ts';
