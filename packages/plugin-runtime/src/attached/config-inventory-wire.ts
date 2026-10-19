import type {
  ConfigInventoryRequest,
  ConfigInventoryRequestItem,
  ConfigScanRecord,
} from '@akasecurity/schema';
import {
  CONFIG_INVENTORY_BATCH_MAX,
  ConfigInventoryRequestItem as RequestItem,
  isProjectScopedConfigItem,
} from '@akasecurity/schema';

/**
 * The requests that report one config scan's items to the control plane, or
 * none when the record names no harness.
 *
 * Each request carries the record's harness and project key. An item the route
 * does not take (another object type, or one over the size cap) is left out,
 * and so is a project scoped item when the record has no project key. A scan
 * over `CONFIG_INVENTORY_BATCH_MAX` items is split into several requests. The
 * requests are marked `complete` only when the record is complete, nothing was
 * left out, and one request carries every item: a complete request removes what
 * the machine reported before and that request does not carry.
 *
 * A complete scan that found nothing still produces one request, so it removes
 * what the machine no longer has. An incomplete one with nothing to carry
 * produces none.
 */
export function configInventoryRequests(record: ConfigScanRecord): ConfigInventoryRequest[] {
  const { harness, projectKey } = record;
  if (harness?.objectType !== 'harness') return [];

  const items: ConfigInventoryRequestItem[] = [];
  let leftOut = false;
  for (const candidate of record.items) {
    const item = RequestItem.safeParse(candidate);
    if (!item.success || (projectKey === undefined && isProjectScopedConfigItem(item.data))) {
      leftOut = true;
      continue;
    }
    items.push(item.data);
  }

  const complete =
    record.complete === true && !leftOut && items.length <= CONFIG_INVENTORY_BATCH_MAX;
  if (items.length === 0 && !complete) return [];
  const requests: ConfigInventoryRequest[] = [];
  for (let at = 0; at === 0 || at < items.length; at += CONFIG_INVENTORY_BATCH_MAX) {
    requests.push({
      harness: { ...harness, objectType: 'harness' },
      items: items.slice(at, at + CONFIG_INVENTORY_BATCH_MAX),
      ...(projectKey === undefined ? {} : { projectKey }),
      ...(complete ? { complete: true } : {}),
    });
  }
  return requests;
}
