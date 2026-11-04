import { describe, expect, it } from 'vitest';

import {
  ListFindingInstancesQuery,
  ListFindingLocationsQuery,
  ListFindingTypesQuery,
} from '../../src/zod/finding.ts';
import {
  ListVaultDerefsQuery,
  ListVaultInventoryQuery,
  ListVaultReuseQuery,
} from '../../src/zod/vault.ts';

// `offset` crosses a Server Action boundary the browser can post anything to.
describe.each([
  { name: 'ListFindingTypesQuery', schema: ListFindingTypesQuery },
  { name: 'ListFindingInstancesQuery', schema: ListFindingInstancesQuery },
  { name: 'ListFindingLocationsQuery', schema: ListFindingLocationsQuery },
  { name: 'ListVaultInventoryQuery', schema: ListVaultInventoryQuery },
  { name: 'ListVaultReuseQuery', schema: ListVaultReuseQuery },
  { name: 'ListVaultDerefsQuery', schema: ListVaultDerefsQuery },
])('$name offset', ({ schema }) => {
  it('keeps a row position', () => {
    expect(schema.parse({ offset: 300 }).offset).toBe(300);
    expect(schema.parse({ offset: 0 }).offset).toBe(0);
  });

  it('leaves it absent when not given', () => {
    expect(schema.parse({}).offset).toBeUndefined();
  });

  it('refuses a position that is negative or not a whole number', () => {
    expect(() => schema.parse({ offset: -1 })).toThrow();
    expect(() => schema.parse({ offset: 1.5 })).toThrow();
    expect(() => schema.parse({ offset: 'x' })).toThrow();
  });
});
