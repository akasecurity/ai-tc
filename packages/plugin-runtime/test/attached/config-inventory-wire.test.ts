import type { ConfigScanRecord, InventoryInput } from '@akasecurity/schema';
import {
  CONFIG_INVENTORY_BATCH_MAX,
  CONFIG_INVENTORY_BATCH_MAX_BYTES,
  CONFIG_INVENTORY_ITEM_MAX_CHARS,
  ConfigInventoryRequest,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { configInventoryRequests } from '../../src/attached/config-inventory-wire.ts';

const HARNESS: InventoryInput = {
  objectType: 'harness',
  identityKey: 'claude-code',
  title: 'claude-code',
  attributes: { harness_version: '2.1.0' },
};
const PROJECT_KEY = 'https://github.com/acme/widgets.git';

const skill: InventoryInput = {
  objectType: 'skill',
  identityKey: 'local|pdf',
  title: 'pdf',
  attributes: { source: 'local', scope: 'user' },
};
const projectHook: InventoryInput = {
  objectType: 'hook',
  identityKey: 'PreToolUse|Bash|guard.sh|project',
  title: 'PreToolUse: guard.sh',
  attributes: { event: 'PreToolUse', command: 'guard.sh', scope: 'project' },
};
const localServer: InventoryInput = {
  objectType: 'mcp_server',
  identityKey: `github|local:${PROJECT_KEY}`,
  title: 'github',
  attributes: { scope: `local:${PROJECT_KEY}`, transport: 'stdio', command: 'mcp-github' },
};

function record(overrides: Partial<ConfigScanRecord> = {}): ConfigScanRecord {
  return {
    items: [skill, projectHook, localServer],
    scanEvent: {
      id: 'scan-1',
      eventType: 'config_scan',
      startedAt: '2026-10-19T09:00:00.000Z',
    },
    harness: HARNESS,
    projectKey: PROJECT_KEY,
    complete: true,
    ...overrides,
  };
}

describe('configInventoryRequests', () => {
  it('builds one complete request carrying every item, the harness and the project key', () => {
    const requests = configInventoryRequests(record());

    expect(requests).toEqual([
      {
        harness: HARNESS,
        items: [skill, projectHook, localServer],
        projectKey: PROJECT_KEY,
        complete: true,
      },
    ]);
    expect(ConfigInventoryRequest.safeParse(requests[0]).success).toBe(true);
  });

  it('builds nothing for a record that names no harness', () => {
    const withoutHarness = record();
    delete withoutHarness.harness;
    expect(configInventoryRequests(withoutHarness)).toEqual([]);
  });

  it('builds nothing for a harness that is not one', () => {
    expect(configInventoryRequests(record({ harness: { ...skill } }))).toEqual([]);
  });

  it('leaves complete off when the scan was not complete', () => {
    const [request] = configInventoryRequests(record({ complete: false }));
    expect(request?.items).toHaveLength(3);
    expect(request).not.toHaveProperty('complete');
  });

  it('leaves out an item the route does not take, and is then not complete', () => {
    const host: InventoryInput = { objectType: 'host', identityKey: 'laptop', attributes: {} };
    const oversized: InventoryInput = {
      ...skill,
      identityKey: 'local|big',
      attributes: { ...skill.attributes, description: 'x'.repeat(CONFIG_INVENTORY_ITEM_MAX_CHARS) },
    };

    const [request] = configInventoryRequests(record({ items: [skill, host, oversized] }));

    expect(request?.items).toEqual([skill]);
    expect(request).not.toHaveProperty('complete');
  });

  it('leaves out project scoped items when there is no project key, and is then not complete', () => {
    const withoutKey = record();
    delete withoutKey.projectKey;

    const requests = configInventoryRequests(withoutKey);

    expect(requests).toEqual([{ harness: HARNESS, items: [skill] }]);
    expect(ConfigInventoryRequest.safeParse(requests[0]).success).toBe(true);
  });

  it('splits a scan over the batch cap, and marks none of the parts complete', () => {
    const items = Array.from({ length: CONFIG_INVENTORY_BATCH_MAX + 1 }, (_, i) => ({
      ...skill,
      identityKey: `local|skill-${String(i)}`,
    }));

    const requests = configInventoryRequests(record({ items }));

    expect(requests.map((request) => request.items.length)).toEqual([
      CONFIG_INVENTORY_BATCH_MAX,
      1,
    ]);
    expect(requests.flatMap((request) => request.items)).toEqual(items);
    for (const request of requests) {
      expect(request).not.toHaveProperty('complete');
      expect(request.projectKey).toBe(PROJECT_KEY);
      expect(ConfigInventoryRequest.safeParse(request).success).toBe(true);
    }
  });

  it('splits a scan over the byte cap, and marks none of the parts complete', () => {
    const description = 'd'.repeat(CONFIG_INVENTORY_ITEM_MAX_CHARS - 200);
    const items = Array.from({ length: 300 }, (_, i) => ({
      ...skill,
      identityKey: `local|big-${String(i)}`,
      attributes: { ...skill.attributes, description },
    }));

    const requests = configInventoryRequests(record({ items }));

    expect(requests.length).toBeGreaterThan(1);
    expect(requests.flatMap((request) => request.items)).toEqual(items);
    for (const request of requests) {
      expect(Buffer.byteLength(JSON.stringify(request.items), 'utf8')).toBeLessThanOrEqual(
        CONFIG_INVENTORY_BATCH_MAX_BYTES,
      );
      expect(request).not.toHaveProperty('complete');
    }
  });

  it('sends one empty complete request for a complete scan that found nothing', () => {
    expect(configInventoryRequests(record({ items: [] }))).toEqual([
      { harness: HARNESS, items: [], projectKey: PROJECT_KEY, complete: true },
    ]);
  });

  it('sends nothing for an incomplete scan that found nothing', () => {
    expect(configInventoryRequests(record({ items: [], complete: false }))).toEqual([]);
  });
});
