import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { hashProjectKey, llmCallId, toolCallId } from '@akasecurity/persistence';
import type {
  AuditEventInput,
  AuditEventRow,
  IngestEvent,
  InventoryContext,
  LlmCallInput,
  RecordProjectEgressInput,
  ToolCallInput,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { rebuildCapture } from '../../src/attached/capture-rebuild.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { rebuildAuditEvent } from '../../src/attached/history-rebuild.ts';

/**
 * Machine-mode byte identity, judged at the `AttachedClient` boundary.
 *
 * Producers stamp a local `scope_key` on what they record, in every attachment
 * mode. A machine attachment must still send exactly the bytes it sent before
 * that stamping existed. So each case below feeds the gateway a STAMPED input
 * and compares what reaches the client, serialised, against a frozen string:
 * the body the unstamped input produced before stamping existed. The comparison
 * is on `JSON.stringify` of the argument the client received, not on a parsed
 * copy, because key order and a leftover `attributes: {}` are exactly what a
 * deep-equal forgives and a receiver's idempotency does not.
 *
 * The boundary is the client and not the socket. The real client re-parses
 * audit bodies on the way out (it adds `inspections: []`), which would mask a
 * difference made here.
 *
 * Unstamped inputs would pass vacuously. That is why every audit-shaped input
 * below is the stamped twin of a frozen expectation.
 */

const KEY = 'github.com/org/api';
const REMOTE = 'https://github.com/org/api.git';

/** What each client route received, serialised, in arrival order. */
interface Wire {
  ingestEvents: string[];
  ingestInventory: string[];
  recordAuditEvent: string[];
  recordAuditEvents: string[];
  recordProjectEgress: string[];
}

const emptyWire = (): Wire => ({
  ingestEvents: [],
  ingestInventory: [],
  recordAuditEvent: [],
  recordAuditEvents: [],
  recordProjectEgress: [],
});

function recordingClient(wire: Wire, overrides: Partial<AttachedClient> = {}): AttachedClient {
  return {
    ingestEvents: (batch) => {
      wire.ingestEvents.push(JSON.stringify(batch));
      return Promise.resolve({ accepted: 1, duplicates: 0 });
    },
    ingestInventory: (context) => {
      wire.ingestInventory.push(JSON.stringify(context));
      // A PARTIAL resolution, so the re-key branch both drops and substitutes.
      return Promise.resolve({ hostId: 'tenant-host', sourceProjectId: 'tenant-project' });
    },
    recordAuditEvent: (body) => {
      wire.recordAuditEvent.push(JSON.stringify(body));
      return Promise.resolve();
    },
    recordAuditEvents: (bodies) => {
      wire.recordAuditEvents.push(JSON.stringify(bodies));
      return Promise.resolve({ accepted: bodies.length });
    },
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: (request) => {
      wire.recordProjectEgress.push(JSON.stringify(request));
      return Promise.resolve({});
    },
    ...overrides,
  };
}

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

/**
 * A deployment that predates the batch route. The batch call fails as
 * `route-absent`, so the gateway re-sends each event singly. That is the
 * per-item fallback, whose bodies must match too.
 */
const routeAbsent: ForwardPolicy = {
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'route-absent' };
    }
  },
};

/** The inner local gateway, reduced to what the forwarding methods touch. */
function quietLocal(): AttachedDataGatewayDeps['local'] {
  const resolved = (): Promise<void> => Promise.resolve();
  return {
    recordCapture: resolved,
    ensureInventory: () => Promise.resolve({}),
    recordAuditEvent: resolved,
    recordLlmCall: resolved,
    recordLlmCalls: resolved,
    recordToolCalls: resolved,
    recordProjectEgress: () =>
      Promise.resolve({
        destinations: 0,
        endpoints: 0,
        callSites: 0,
        truncated: false,
        droppedFiles: [],
      }),
    markCaptureDelivered: () => undefined,
    markCaptureOwed: () => undefined,
    markAuditEventsDelivered: () => undefined,
  } as unknown as AttachedDataGatewayDeps['local'];
}

let dataDir: string;
beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'aka-byte-identity-'));
});
afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

function build(wire: Wire, opts: { forward?: ForwardPolicy; client?: AttachedClient } = {}) {
  return new AttachedDataGateway({
    dataDir,
    local: quietLocal(),
    client: opts.client ?? recordingClient(wire),
    readCachedBundle: () => Promise.resolve(null),
    forward: opts.forward ?? passthrough,
    // MACHINE mode: what this whole suite is about.
    attachment: { mode: 'machine', keys: new Set<string>() },
  });
}

// ── inputs: each audit-shaped one beside its stamped twin ──────────────────

/** A session root as the session-start path builds it, local inventory ids included. */
const ROOT: AuditEventInput = {
  id: 'session-1',
  eventType: 'session',
  startedAt: '2026-08-19T10:00:00.000Z',
  hostId: 'local-host',
  harnessId: 'local-harness',
  sourceProjectId: 'local-project',
  attributes: { provider: 'anthropic', harness: 'claude-code', cwd: '/work/api', repo: 'org/api' },
};
const ROOT_STAMPED: AuditEventInput = {
  ...ROOT,
  attributes: { ...ROOT.attributes, scope_key: KEY },
};

/** An attribute-less session stub, which stamping turns into a one-member bag. */
const STUB: AuditEventInput = {
  id: 'session-2',
  eventType: 'session',
  startedAt: '2026-08-19T10:00:00.000Z',
};
const STUB_STAMPED: AuditEventInput = { ...STUB, attributes: { scope_key: KEY } };

const LLM: LlmCallInput = {
  sessionId: 'session-1',
  messageId: 'msg-1',
  parentId: 'session-1',
  rootSessionId: 'session-1',
  startedAt: '2026-08-19T10:00:01.000Z',
  attributes: { model: 'claude-opus-5', input_tokens: 10, output_tokens: 20 },
};
const LLM_STAMPED: LlmCallInput = { ...LLM, attributes: { ...LLM.attributes, scope_key: KEY } };

const TOOL: ToolCallInput = {
  sessionId: 'session-1',
  toolUseId: 'toolu-1',
  parentId: 'session-1',
  rootSessionId: 'session-1',
  startedAt: '2026-08-19T10:00:02.000Z',
  attributes: { tool_name: 'Bash', tool_use_id: 'toolu-1', target: 'ls' },
  inspections: [],
};
const TOOL_STAMPED: ToolCallInput = { ...TOOL, attributes: { ...TOOL.attributes, scope_key: KEY } };

const CAPTURE: IngestEvent = {
  id: 'capture-1',
  sourceTool: 'claude-code',
  kind: 'prompt',
  occurredAt: '2026-08-19T10:00:00.000Z',
  contentHash: 'hash-capture-1',
  content: 'content of capture-1',
  metadata: { sessionId: 'session-1', repo: 'org/api' },
};

/** Egress and inventory inputs carry no key; their bodies are pinned as they are. */
const EGRESS: RecordProjectEgressInput = {
  projectKey: `git:${REMOTE}`,
  project: 'api',
  projectId: 'local-project',
  reconcile: { mode: 'walk', walkedPrefix: '/work/api' },
  hits: [],
};

const INVENTORY: InventoryContext = {
  project: { url: REMOTE, name: 'api', attributes: {} },
};

// ── frozen bodies: what each UNSTAMPED input put on the wire ───────────────

/** The root before any inventory resolved: every local id dropped. */
const ROOT_WIRE_UNRESOLVED =
  '{"id":"session-1","eventType":"session","startedAt":"2026-08-19T10:00:00.000Z",' +
  '"attributes":{"provider":"anthropic","harness":"claude-code","cwd":"/work/api","repo":"org/api"}}';

/** The root after a partial resolution: local ids dropped, the resolved two appended. */
const ROOT_WIRE_RESOLVED =
  '{"id":"session-1","eventType":"session","startedAt":"2026-08-19T10:00:00.000Z",' +
  '"attributes":{"provider":"anthropic","harness":"claude-code","cwd":"/work/api","repo":"org/api"},' +
  '"hostId":"tenant-host","sourceProjectId":"tenant-project"}';

const STUB_WIRE = '{"id":"session-2","eventType":"session","startedAt":"2026-08-19T10:00:00.000Z"}';

const LLM_WIRE =
  `{"id":"${llmCallId('session-1', 'msg-1')}","eventType":"llm_call",` +
  '"startedAt":"2026-08-19T10:00:01.000Z","parentId":"session-1","rootSessionId":"session-1",' +
  '"attributes":{"model":"claude-opus-5","input_tokens":10,"output_tokens":20}}';

const TOOL_WIRE =
  `{"id":"${toolCallId('session-1', 'toolu-1')}","eventType":"tool_call",` +
  '"startedAt":"2026-08-19T10:00:02.000Z","parentId":"session-1","rootSessionId":"session-1",' +
  '"attributes":{"tool_name":"Bash","tool_use_id":"toolu-1","target":"ls"},"inspections":[]}';

const CAPTURE_WIRE =
  '{"events":[{"id":"capture-1","sourceTool":"claude-code","kind":"prompt",' +
  '"occurredAt":"2026-08-19T10:00:00.000Z","contentHash":"hash-capture-1",' +
  '"content":"content of capture-1","metadata":{"sessionId":"session-1","repo":"org/api"}}]}';

const EGRESS_WIRE =
  `{"projectKey":"${hashProjectKey(`git:${REMOTE}`)}","project":"api",` +
  '"reconcile":{"mode":"walk","walkedPrefix":"/work/api"},"hits":[]}';

const INVENTORY_WIRE = `{"project":{"url":"${REMOTE}","name":"api","attributes":{}}}`;

describe('machine-mode byte identity at the AttachedClient boundary', () => {
  it('ingestEvents: a capture carries its key beside the event, so the body is unchanged', async () => {
    const wire = emptyWire();
    await build(wire).recordCapture({ event: CAPTURE, findings: [], scopeKey: KEY });
    expect(wire.ingestEvents).toEqual([CAPTURE_WIRE]);
  });

  it('ingestEvents: the dedupe hint still rides beside the events', async () => {
    const wire = emptyWire();
    await build(wire).recordCapture({
      event: CAPTURE,
      findings: [],
      dedupe: 'content-hash',
      scopeKey: KEY,
    });
    expect(wire.ingestEvents).toEqual([`${CAPTURE_WIRE.slice(0, -1)},"dedupe":"content-hash"}`]);
  });

  it('recordAuditEvent: a stamped root sends the unstamped bytes before inventory resolves', async () => {
    const wire = emptyWire();
    await build(wire).recordAuditEvent(ROOT_STAMPED);
    expect(wire.recordAuditEvent).toEqual([ROOT_WIRE_UNRESOLVED]);
  });

  it('recordAuditEvent: and after it resolves, on the substitution branch', async () => {
    const wire = emptyWire();
    const gateway = build(wire);
    await gateway.ensureInventory(INVENTORY);
    await gateway.recordAuditEvent(ROOT_STAMPED);
    expect(wire.recordAuditEvent).toEqual([ROOT_WIRE_RESOLVED]);
  });

  it('recordAuditEvent: a stub whose only attribute was the key sends no attributes at all', async () => {
    const wire = emptyWire();
    await build(wire).recordAuditEvent(STUB_STAMPED);
    expect(wire.recordAuditEvent).toEqual([STUB_WIRE]);
  });

  it('recordAuditEvent (single llm_call): the stamped leaf sends the unstamped bytes', async () => {
    const wire = emptyWire();
    await build(wire).recordLlmCall(LLM_STAMPED);
    expect(wire.recordAuditEvent).toEqual([LLM_WIRE]);
  });

  it('recordAuditEvents: a stamped batch sends the unstamped bytes', async () => {
    const wire = emptyWire();
    const gateway = build(wire);
    await gateway.recordLlmCalls([LLM_STAMPED]);
    await gateway.recordToolCalls([TOOL_STAMPED]);
    expect(wire.recordAuditEvents).toEqual([`[${LLM_WIRE}]`, `[${TOOL_WIRE}]`]);
  });

  it('recordAuditEvents per-item fallback: each single sends the unstamped bytes', async () => {
    const wire = emptyWire();
    const client = recordingClient(wire, {
      recordAuditEvents: () => Promise.reject(new Error('no batch route')),
    });
    const gateway = build(wire, { forward: routeAbsent, client });
    await gateway.recordLlmCalls([LLM_STAMPED]);
    await gateway.recordToolCalls([TOOL_STAMPED]);
    // The batch route never recorded: the override replaced it, so these are the singles.
    expect(wire.recordAuditEvents).toEqual([]);
    expect(wire.recordAuditEvent).toEqual([LLM_WIRE, TOOL_WIRE]);
  });

  it('recordProjectEgress: the projected request is unchanged', async () => {
    const wire = emptyWire();
    await build(wire).recordProjectEgress(EGRESS);
    expect(wire.recordProjectEgress).toEqual([EGRESS_WIRE]);
  });

  it('ingestInventory: the context crosses verbatim', async () => {
    const wire = emptyWire();
    await build(wire).ensureInventory(INVENTORY);
    expect(wire.ingestInventory).toEqual([INVENTORY_WIRE]);
  });
});

describe('the history drain sends the unstamped bytes too', () => {
  const leafRow = (attributes: Record<string, unknown> | null): AuditEventRow => ({
    id: 'llm-row-1',
    parentId: 'session-1',
    rootSessionId: 'session-1',
    eventType: 'llm_call',
    hostId: 'local-host',
    harnessId: null,
    sourceProjectId: null,
    startedAt: Date.parse('2026-08-19T10:00:01.000Z'),
    endedAt: null,
    severity: null,
    priority: null,
    content: null,
    contentHash: null,
    attributes: attributes === null ? null : JSON.stringify(attributes),
  });

  it('structural lane: a stamped row rebuilds to the unstamped request, byte for byte', () => {
    const unstamped = rebuildAuditEvent(leafRow({ model: 'claude-opus-5', input_tokens: 10 }));
    const stamped = rebuildAuditEvent(
      leafRow({ model: 'claude-opus-5', scope_key: KEY, input_tokens: 10 }),
    );
    // The frozen value, so the byte comparison below cannot pass by both sides drifting together.
    expect(unstamped).toEqual({
      id: 'llm-row-1',
      eventType: 'llm_call',
      startedAt: '2026-08-19T10:00:01.000Z',
      parentId: 'session-1',
      rootSessionId: 'session-1',
      attributes: { model: 'claude-opus-5', input_tokens: 10 },
      inspections: [],
    });
    expect(JSON.stringify(stamped)).toBe(JSON.stringify(unstamped));
  });

  it('structural lane: a row whose bag held only the key rebuilds with no bag', () => {
    const bare = rebuildAuditEvent(leafRow(null));
    const stamped = rebuildAuditEvent(leafRow({ scope_key: KEY }));
    expect(bare).toBeDefined();
    expect(JSON.stringify(stamped)).toBe(JSON.stringify(bare));
  });

  // The capture lane picks wire fields by name, so a stored key cannot ride it.
  // Pinned so a later widening of that pick is a visible decision.
  it('capture lane: a stamped capture row rebuilds to the unstamped event', () => {
    const captureRow = (attributes: Record<string, unknown>): AuditEventRow => ({
      id: 'capture-row-1',
      eventType: 'prompt',
      startedAt: Date.parse('2026-08-19T10:00:00.000Z'),
      rootSessionId: 'session-1',
      parentId: 'session-1',
      content: 'content of capture-1',
      contentHash: 'a'.repeat(64),
      attributes: JSON.stringify(attributes),
    });
    const unstamped = rebuildCapture(captureRow({ source_tool: 'claude-code', repo: 'org/api' }));
    const stamped = rebuildCapture(
      captureRow({ source_tool: 'claude-code', repo: 'org/api', scope_key: KEY }),
    );
    expect(unstamped).toBeDefined();
    expect(JSON.stringify(stamped)).toBe(JSON.stringify(unstamped));
    expect(JSON.stringify(stamped)).not.toContain('scope_key');
    expect(JSON.stringify(stamped)).not.toContain(KEY);
  });
});
