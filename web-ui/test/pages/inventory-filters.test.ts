import { DEFAULT_INVENTORY_SELECTION } from '@akasecurity/dashboard-ui';
import { describe, expect, it } from 'vitest';

import { buildInventoryParams, parseSelection } from '../../app/(app)/inventory/filters';

describe('inventory URL ⇄ selection', () => {
  it('reads an empty URL as the default selection', () => {
    expect(parseSelection({})).toEqual(DEFAULT_INVENTORY_SELECTION);
  });

  it('round-trips a by-type selection with an opened row', () => {
    const sel = {
      view: 'type',
      harness: 'cursor',
      type: 'mcp',
      item: { type: 'mcp', id: 'mcp-1' },
    } as const;
    const params = buildInventoryParams(sel);
    expect(params.toString()).toBe('v=type&h=cursor&t=mcp&st=mcp&si=mcp-1');
    expect(parseSelection(Object.fromEntries(params))).toEqual(sel);
  });

  it('leaves the defaults out of the URL', () => {
    expect(buildInventoryParams(DEFAULT_INVENTORY_SELECTION).toString()).toBe('');
  });

  it('falls back to the default for any unrecognised value', () => {
    expect(
      parseSelection({ v: 'grid', h: 'not-a-harness', t: 'widget', st: 'widget', si: 'x' }),
    ).toEqual(DEFAULT_INVENTORY_SELECTION);
    expect(parseSelection({ st: 'skill', si: '' }).item).toBeNull();
  });
});
