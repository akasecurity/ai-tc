import { randomUUID } from 'node:crypto';

import type { WebCaptureStatus, WebSourceTool } from '@akasecurity/schema';
import { toCaptureStatusAttributes } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import { SqliteAuditEventsRepository } from '../../src/repositories/audit-events.ts';
import { SqliteCaptureStatusRepository } from '../../src/repositories/capture-status.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-capture-status-', { migrated: true });

const STATUS: WebCaptureStatus = {
  patched: true,
  live: true,
  blind: false,
  sendsSeenDom: 2,
  exchangesSeenNet: 2,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
  conversationEndpoints: 1,
};

// `parentId`/`rootSessionId` are left unset: they are nullable FK columns, and
// what is under test here is the capture-status read, not the session-root
// FK-planting the gateway layer (recordAuditEvent) is responsible for.
function writeStatus(opts: {
  id?: string;
  startedAt: string;
  tool: string;
  status?: WebCaptureStatus;
}): void {
  const audit = new SqliteAuditEventsRepository(store.openRaw());
  audit.insertAuditEvent({
    id: opts.id ?? randomUUID(),
    eventType: 'capture_status',
    startedAt: opts.startedAt,
    attributes:
      opts.status === undefined
        ? { source_tool: opts.tool }
        : toCaptureStatusAttributes(opts.status, opts.tool as WebSourceTool),
  });
}

let repo: SqliteCaptureStatusRepository;

beforeEach(() => {
  repo = new SqliteCaptureStatusRepository(store.openRaw());
});

describe('SqliteCaptureStatusRepository.latest', () => {
  it('returns the newest row per site', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-ai', status: STATUS });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'claude-ai',
      status: { ...STATUS, exchangesSeenNet: 5 },
    });
    writeStatus({
      startedAt: '2026-01-01T00:10:00.000Z',
      tool: 'claude-ai',
      status: { ...STATUS, exchangesSeenNet: 9 },
    });
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: STATUS });

    const records = repo.latest();
    expect(records).toHaveLength(2);
    const claudeAi = records.find((r) => r.tool === 'claude-ai');
    expect(claudeAi?.status.exchangesSeenNet).toBe(9);
  });

  it('breaks a tie on started_at by the higher id, whichever landed first', () => {
    // Seeded in DESCENDING id order, so insertion order and id order disagree:
    // asserting the winner against rows written in ascending order passes
    // whether the tiebreaker is `a.id DESC` or nothing at all.
    writeStatus({
      id: 'b-row',
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: { ...STATUS, exchangesSeenNet: 42 },
    });
    writeStatus({
      id: 'a-row',
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: { ...STATUS, exchangesSeenNet: 7 },
    });

    const chatgpt = repo.latest().find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.exchangesSeenNet).toBe(42);
  });

  it('skips a row whose bag is not a status, keeping the other site', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt' }); // no status fields at all
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-ai', status: STATUS });

    const records = repo.latest();
    expect(records.map((r) => r.tool)).toEqual(['claude-ai']);
  });

  it('skips a row whose source_tool is not a web chat id', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-code', status: STATUS });

    expect(repo.latest()).toEqual([]);
  });

  it('answers an empty store with no records', () => {
    expect(repo.latest()).toEqual([]);
  });
});

// A page relays a fresh nothing-seen-yet report the moment its tap patches, so
// the newest row for a site is very often a report that observed nothing. The
// read has to see past those, or reloading the tab — which is what the `blind`
// remediation tells the user to do — replaces the report that told them to.
describe('SqliteCaptureStatusRepository.latest — a watching-only report', () => {
  // Patched, endpoints to watch, nothing observed: what a page reports on load.
  const WATCHING: WebCaptureStatus = {
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 1,
  };
  const BLIND: WebCaptureStatus = { ...WATCHING, blind: true, sendsSeenDom: 3 };

  it('does not replace a report that observed the turn path', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({ startedAt: '2026-01-01T00:05:00.000Z', tool: 'chatgpt', status: WATCHING });

    const chatgpt = repo.latest().find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.blind).toBe(true);
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('is replaced by a later report that did observe the turn path', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({ startedAt: '2026-01-01T00:05:00.000Z', tool: 'chatgpt', status: WATCHING });
    writeStatus({ startedAt: '2026-01-01T00:10:00.000Z', tool: 'chatgpt', status: STATUS });

    const chatgpt = repo.latest().find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.blind).toBe(false);
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:10:00.000Z');
  });

  it('is what a site with nothing else to report shows', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: WATCHING });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: { ...WATCHING, sendsSeenDom: 1 },
    });

    const chatgpt = repo.latest().find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:05:00.000Z');
    expect(chatgpt?.status.sendsSeenDom).toBe(1);
  });

  it('buries an older verdict once enough of them have piled up on top', () => {
    // The lookback is bounded because this read walks the capture_status
    // range; past it the older verdict is stale and the newest row is shown.
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    for (let i = 1; i <= 40; i += 1) {
      writeStatus({
        startedAt: `2026-01-01T01:${String(i).padStart(2, '0')}:00.000Z`,
        tool: 'chatgpt',
        status: WATCHING,
      });
    }

    expect(repo.latest().find((r) => r.tool === 'chatgpt')?.status.blind).toBe(false);
  });

  it('does not hide a build that stopped declaring endpoints', () => {
    // conversationEndpoints === 0 is a statement about this build, not an
    // absence of evidence, so it supersedes like any observation would.
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: { ...WATCHING, conversationEndpoints: 0 },
    });

    const chatgpt = repo.latest().find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.conversationEndpoints).toBe(0);
    expect(chatgpt?.status.blind).toBe(false);
  });
});
