import {
  DEFAULT_INVENTORY_SELECTION,
  type InventorySelection as Selection,
} from '@akasecurity/dashboard-ui';
import { AssetType, HarnessId } from '@akasecurity/schema';

// Pure URL ⇄ selection helpers for the Inventory page. The selection — which
// list the left panel shows (v), the harness (h) and type (t) picked in each,
// and the row opened from the table (st/si) — lives in the URL so the Server
// Component re-reads the local store on each change. A table's own search,
// filters, sort and page are client state and stay out of the URL.

export interface InventorySearchParams {
  v?: string;
  h?: string;
  t?: string;
  st?: string;
  si?: string;
}

/** The selection a URL describes; anything missing or unrecognised takes the default. */
export function parseSelection(sp: InventorySearchParams): Selection {
  const harness = HarnessId.safeParse(sp.h);
  const type = AssetType.safeParse(sp.t);
  const itemType = AssetType.safeParse(sp.st);
  return {
    view: sp.v === 'type' ? 'type' : 'harness',
    harness: harness.success ? harness.data : DEFAULT_INVENTORY_SELECTION.harness,
    type: type.success ? type.data : DEFAULT_INVENTORY_SELECTION.type,
    item:
      itemType.success && typeof sp.si === 'string' && sp.si !== ''
        ? { type: itemType.data, id: sp.si }
        : null,
  };
}

/** The URLSearchParams for an Inventory navigation. */
export function buildInventoryParams(sel: Selection): URLSearchParams {
  const params = new URLSearchParams();
  if (sel.view === 'type') params.set('v', 'type');
  if (sel.harness !== null) params.set('h', sel.harness);
  if (sel.type !== DEFAULT_INVENTORY_SELECTION.type) params.set('t', sel.type);
  if (sel.item) {
    params.set('st', sel.item.type);
    params.set('si', sel.item.id);
  }
  return params;
}
