// Namespaced ids for the removable sample dataset, shared across the seed domains
// so cross-domain references line up. In particular a Data Shares sample call
// site's `projectId` must equal the Inventory sample project's `source_project`
// id, so a future call-site → Inventory-project drill-down resolves instead of
// missing. The `sample:` prefix keeps these clear of real content-addressed ids.

export const sampleProjectId = (slug: string): string => `sample:project:${slug}`;
export const sampleAssetId = (slug: string): string => `sample:asset:${slug}`;
export const sampleHarnessId = (slug: string): string => `sample:harness:${slug}`;
// Activity audit-events sample rows: the session root is `sample:activity:<slug>`,
// its timeline events `sample:activity:<slug>:<n>`. The shared `sample:activity:`
// prefix is what `clearSampleAuditEvents` deletes on.
export const sampleActivityId = (slug: string): string => `sample:activity:${slug}`;
