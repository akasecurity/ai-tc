import { describe, expectTypeOf, it } from 'vitest';

import type {
  BaseAuditEventRow,
  BaseClassifiedDataRow,
  BaseEventRow,
  BaseFindingRow,
  BaseInspectionDefinitionRow,
  BaseInspectionFindingRow,
  BaseInstalledPackRow,
  BaseInventoryRow,
  BasePolicyRow,
  BaseSourceProjectRow,
} from '../../src/drizzle/base-rows.ts';
import type * as local from '../../src/drizzle/local/sqlite.ts';

// The OSS local SQLite store must equal the tenant-free base row contracts. Time
// columns are epoch-millis `number` here — the base interfaces default `TTime` to
// `number`, so no explicit dialect arg is needed. `toEqualTypeOf` is invariant, so
// ANY drift — a column added, removed, renamed, or retyped on either the table or
// the base interface — fails `tsc --noEmit` (the package typecheck) AND
// `vitest run`, so the store and the base row contracts can never silently
// diverge.
describe('OSS local store adheres to the base row contracts', () => {
  it('events ≡ BaseEventRow', () => {
    expectTypeOf<typeof local.events.$inferSelect>().toEqualTypeOf<BaseEventRow>();
  });

  it('findings ≡ BaseFindingRow', () => {
    expectTypeOf<typeof local.findings.$inferSelect>().toEqualTypeOf<BaseFindingRow>();
  });

  it('policies ≡ BasePolicyRow', () => {
    expectTypeOf<typeof local.policies.$inferSelect>().toEqualTypeOf<BasePolicyRow>();
  });

  it('installed_packs ≡ BaseInstalledPackRow', () => {
    expectTypeOf<typeof local.installedPacks.$inferSelect>().toEqualTypeOf<BaseInstalledPackRow>();
  });

  it('inventory ≡ BaseInventoryRow', () => {
    expectTypeOf<typeof local.inventory.$inferSelect>().toEqualTypeOf<BaseInventoryRow>();
  });

  it('source_project ≡ BaseSourceProjectRow', () => {
    expectTypeOf<typeof local.sourceProject.$inferSelect>().toEqualTypeOf<BaseSourceProjectRow>();
  });

  it('audit_events ≡ BaseAuditEventRow', () => {
    expectTypeOf<typeof local.auditEvents.$inferSelect>().toEqualTypeOf<BaseAuditEventRow>();
  });

  it('classified_data ≡ BaseClassifiedDataRow', () => {
    expectTypeOf<typeof local.classifiedData.$inferSelect>().toEqualTypeOf<BaseClassifiedDataRow>();
  });

  it('inspection_definitions ≡ BaseInspectionDefinitionRow', () => {
    expectTypeOf<
      typeof local.inspectionDefinitions.$inferSelect
    >().toEqualTypeOf<BaseInspectionDefinitionRow>();
  });

  it('inspection_findings ≡ BaseInspectionFindingRow', () => {
    expectTypeOf<
      typeof local.inspectionFindings.$inferSelect
    >().toEqualTypeOf<BaseInspectionFindingRow>();
  });
});
