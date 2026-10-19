import type {
  ConfigInventoryRequest,
  ConfigInventoryRequestItem,
  ConfigScanRecord,
} from '@akasecurity/schema';
import {
  CONFIG_INVENTORY_BATCH_MAX,
  CONFIG_INVENTORY_BATCH_MAX_BYTES,
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
 * over `CONFIG_INVENTORY_BATCH_MAX` items or `CONFIG_INVENTORY_BATCH_MAX_BYTES`
 * of JSON is split into several requests. The requests are marked `complete`
 * only when the record is complete, nothing was left out, and one request
 * carries every item: a complete request removes what the machine reported
 * before and that request does not carry.
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

  const parts = splitItems(items);
  const complete = record.complete === true && !leftOut && parts.length === 1;
  if (items.length === 0 && !complete) return [];
  return parts.map((part) => ({
    harness: { ...harness, objectType: 'harness' },
    items: part,
    ...(projectKey === undefined ? {} : { projectKey }),
    ...(complete ? { complete: true } : {}),
  }));
}

// The items in order, in parts of at most CONFIG_INVENTORY_BATCH_MAX items and
// CONFIG_INVENTORY_BATCH_MAX_BYTES of JSON. Always at least one part.
function splitItems(items: readonly ConfigInventoryRequestItem[]): ConfigInventoryRequestItem[][] {
  const parts: ConfigInventoryRequestItem[][] = [];
  let part: ConfigInventoryRequestItem[] = [];
  let bytes = 0;
  for (const item of items) {
    const size = Buffer.byteLength(JSON.stringify(item), 'utf8') + 1;
    if (
      part.length > 0 &&
      (part.length === CONFIG_INVENTORY_BATCH_MAX ||
        bytes + size > CONFIG_INVENTORY_BATCH_MAX_BYTES)
    ) {
      parts.push(part);
      part = [];
      bytes = 0;
    }
    part.push(item);
    bytes += size;
  }
  parts.push(part);
  return parts;
}
