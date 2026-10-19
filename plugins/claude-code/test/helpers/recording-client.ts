// A transport for the attached gateway that records what it is handed and sends
// nothing. Its imports are types only, so a suite's `vi.mock` factory can load it.
import type { AttachedClient } from '@akasecurity/plugin-runtime';
import type { AuditEventInput, IngestBatch, InventoryContext } from '@akasecurity/schema';

/** What the recording client was handed, in order. */
export interface Sent {
  readonly captures: IngestBatch[];
  readonly audit: AuditEventInput[];
  readonly inventory: InventoryContext[];
}

/** A client that records every request on `sent` and answers as a deployment that accepts it. */
export function recordingClient(sent: Sent): AttachedClient {
  return {
    ingestEvents: (batch) => {
      sent.captures.push(batch);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    },
    ingestInventory: (context) => {
      sent.inventory.push(context);
      return Promise.resolve({});
    },
    recordAuditEvent: (event) => {
      sent.audit.push(event);
      return Promise.resolve();
    },
    recordAuditEvents: (events) => {
      sent.audit.push(...events);
      return Promise.resolve({ accepted: events.length });
    },
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: () => Promise.resolve({}),
    recordConfigInventory: (request) => Promise.resolve({ accepted: request.items.length }),
  };
}
