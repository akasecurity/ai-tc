import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { InventoryContext, ResolvedAttachmentScope } from '@akasecurity/schema';
import { agentKey, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// The one widening of the inventory gate: a session whose root is stamped with
// a coding-agent key in scope sends its inventory, though its repository is not
// enrolled. A repository key passed beside the context never widens it, and the
// local store is handed the context alone either way.

const TAG = '0123456789abcdef';
const WORK_URL = 'https://github.com/acme/payments-api.git';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_URL = 'https://github.com/someone/side-project.git';
const AGENT = agentKeyOf(TAG, `claude:${randomUUID()}`);
const OTHER_AGENT = agentKeyOf(TAG, `claude:${randomUUID()}`);

/** The agent key the schema's builder makes for `account` under `scopeTag`, failing the suite if none. */
function agentKeyOf(scopeTag: string, account: string): string {
  const key = agentKey(scopeTag, account);
  if (key === undefined) throw new Error(`no agent key for ${account}`);
  return key;
}

const SCOPED: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set([WORK_REPO, AGENT]) };
const MACHINE: ResolvedAttachmentScope = { mode: 'machine', keys: new Set<string>() };

/** Runs every forward: the healthy-plane case. */
const passthrough: ForwardPolicy = {
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
};

/** The device's own store, real, with the arguments of every inventory call it was handed. */
class LocalStore extends StandaloneDataGateway {
  readonly inventoryCalls: unknown[][] = [];

  override ensureInventory(...args: Parameters<StandaloneDataGateway['ensureInventory']>) {
    this.inventoryCalls.push(args);
    return super.ensureInventory(...args);
  }
}

let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'aka-inventory-gate-'));
  migratedStore.seed(dataDir);
});

afterEach(() => {
  removeTree(dataDir);
});

function context(tool: string, url: string): InventoryContext {
  return {
    harness: { objectType: 'harness', identityKey: tool, attributes: {} },
    project: {
      url,
      name:
        url
          .replace(/\.git$/, '')
          .split('/')
          .pop() ?? 'project',
      attributes: {},
    },
  };
}

function build(attachment: ResolvedAttachmentScope) {
  const local = new LocalStore(dataDir);
  const sent: InventoryContext[] = [];
  const client: AttachedClient = {
    ingestEvents: (batch) => Promise.resolve({ accepted: batch.events.length, duplicates: 0 }),
    ingestInventory: (ctx) => {
      sent.push(ctx);
      return Promise.resolve({});
    },
    recordAuditEvent: () => Promise.resolve(),
    recordAuditEvents: (events) => Promise.resolve({ accepted: events.length }),
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: () => Promise.resolve({}),
    recordConfigInventory: () => Promise.resolve({ accepted: 0 }),
  };
  const gateway = new AttachedDataGateway({
    local,
    client,
    dataDir,
    readCachedBundle: () => Promise.resolve(null),
    forward: passthrough,
    attachment,
  });
  return { gateway, local, sent };
}

describe('ensureInventory — the gate on a scoped attachment', () => {
  it('sends the inventory of a session in an enrolled repository', async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, WORK_URL));
    expect(sent).toHaveLength(1);
  });

  it('keeps the inventory of a personal session local when no key is passed beside it', async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL));
    expect(sent).toEqual([]);
  });

  it("sends a personal session's inventory when its root is stamped with an agent key in scope", async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL), {
      scopeKey: AGENT,
    });
    expect(sent).toHaveLength(1);
    // The context crosses as it was handed: the key rides beside it, never in it.
    expect(JSON.stringify(sent)).not.toContain('agent:');
  });

  it('never widens for a repository key passed beside the context', async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL), {
      scopeKey: WORK_REPO,
    });
    expect(sent).toEqual([]);
  });

  it('never widens for an agent key out of scope', async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL), {
      scopeKey: OTHER_AGENT,
    });
    expect(sent).toEqual([]);
  });

  it('never widens for a web chat session', async () => {
    const { gateway, sent } = build(SCOPED);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeAi, PERSONAL_URL), {
      scopeKey: AGENT,
    });
    expect(sent).toEqual([]);
  });

  it('hands the local store the context alone, so the local write is the same either way', async () => {
    const { gateway, local } = build(SCOPED);
    const ctx = context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL);
    await gateway.ensureInventory(ctx, { scopeKey: AGENT });
    await gateway.ensureInventory(ctx);
    expect(local.inventoryCalls).toEqual([[ctx], [ctx]]);
  });
});

describe('ensureInventory — the gate on a machine-wide attachment', () => {
  it('sends every inventory, with or without a key beside it', async () => {
    const { gateway, sent } = build(MACHINE);
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL));
    await gateway.ensureInventory(context(SOURCE_TOOL.ClaudeCode, PERSONAL_URL), {
      scopeKey: WORK_REPO,
    });
    expect(sent).toHaveLength(2);
  });
});
