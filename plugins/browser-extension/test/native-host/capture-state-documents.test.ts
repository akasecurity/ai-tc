import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type { WebCaptureStatus, WebChatCapture, WebChatResponseCapture } from '@akasecurity/schema';
import { toCaptureStatusAttributes, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import type { ConfigForTool } from '../../src/native-host/host.ts';
import { handleRequest } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

// `capture_state` answers a site by folding every DOCUMENT that reported for
// it — the stored rows and this process's own in-memory copies together — and
// takes the worst of those still voting. So these cases are about which
// documents exist, and each one has to describe a whole browser.
//
// A SEPARATE file for the reason capture-state-empty.test.ts gives: host.ts's
// `captureStatuses` map is module-global for the life of the process (by
// design — one host serves one browser), and a file boundary is what vitest
// reloads it fresh for. Inside the file the same thing applies between cases,
// which is why every case unloads its own tabs afterwards: a document nobody
// closed is a live document, and a live document votes. That teardown is not a
// test-only escape hatch — it is the report a real tab sends on `pagehide`.
const roots: string[] = [];

function scratch(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return join(root, 'aka');
}

interface OpenDocument {
  sessionId: string;
  tool: WebSourceTool;
  status: WebCaptureStatus;
}

const open: OpenDocument[] = [];
let teardownDir: string;

beforeEach(() => {
  teardownDir = scratch('aka-capture-state-teardown-');
});

afterEach(async () => {
  for (const document of open.splice(0)) {
    await handleRequest(
      {
        type: 'capture_status',
        requestId: `teardown-${document.sessionId}`,
        sessionId: document.sessionId,
        tool: document.tool,
        status: { ...document.status, closed: true },
      },
      configIn(teardownDir),
    );
  }
  removeTrees(roots.splice(0));
});

function configIn(dataDir: string, webChat: WebChatCapture = webChatSettings()): ConfigForTool {
  return (tool: WebSourceTool | undefined): PluginConfig => ({
    settings: {
      specVersion: 3,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
      webChatCapture: webChat,
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  });
}

function webChatSettings(responses: WebChatResponseCapture = 'with-findings'): WebChatCapture {
  return {
    responses,
    account: false,
    consent: {
      acknowledgedAt: '2026-01-01T00:00:00.000Z',
      version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
    },
  };
}

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
  closed: false,
};
const ACTIVE: WebCaptureStatus = { ...WATCHING, live: true, exchangesSeenNet: 1 };
const BLIND: WebCaptureStatus = { ...WATCHING, blind: true, sendsSeenDom: 3 };

/** Report a status for one document, and register the tab so it unloads after. */
async function report(
  cfg: ConfigForTool,
  sessionId: string,
  tool: WebSourceTool,
  status: WebCaptureStatus,
): Promise<void> {
  open.push({ sessionId, tool, status });
  const response = await handleRequest(
    { type: 'capture_status', requestId: `report-${sessionId}`, sessionId, tool, status },
    cfg,
  );
  // The report has to have been ACCEPTED, or every state assertion below holds
  // over a browser that reported nothing.
  expect(response).toMatchObject({ type: 'capture_status', ok: true, accepted: true });
}

/**
 * A `capture_status` row already in the store, as a previous host process left
 * it — under `rootSessionId`, which is what the host stamps and therefore what
 * groups a site's rows into documents.
 *
 * Stamped a minute ago rather than at a fixed date: the store read is bounded
 * to CAPTURE_STATUS_RECENCY_MS, so a literal calendar date ages out of the
 * window and the row stops being read at all.
 */
function storeRow(
  dataDir: string,
  rootSessionId: string,
  tool: WebSourceTool,
  status: WebCaptureStatus,
  startedAt: string = new Date(Date.now() - 60_000).toISOString(),
): void {
  const db = openLocalDatabase(dataDir);
  try {
    // `root_session_id` is a self-FK, so the root row has to exist first. A
    // `session` row carries no attributes and so no `source_tool`, which is
    // why planting one is invisible to the capture-status read.
    db.auditEvents.ensureSessionRoot(rootSessionId, startedAt);
    db.auditEvents.insertAuditEvent({
      id: `${rootSessionId}-row-${startedAt}`,
      eventType: 'capture_status',
      startedAt,
      rootSessionId,
      attributes: toCaptureStatusAttributes(status, tool),
    });
  } finally {
    db.close();
  }
}

async function stateOf(cfg: ConfigForTool, tool: WebSourceTool): Promise<string | undefined> {
  const response = await handleRequest({ type: 'capture_state', requestId: 'state' }, cfg);
  if (response.type !== 'capture_state') throw new Error('expected capture_state');
  return response.sites.find((s) => s.tool === tool)?.state;
}

describe('capture_state over several documents', () => {
  it('derives standby from a stored zero-endpoint status', async () => {
    const dataDir = scratch('aka-capture-state-standby-');
    const cfg = configIn(dataDir);
    await report(cfg, 'state-standby-session', 'chatgpt', {
      ...WATCHING,
      conversationEndpoints: 0,
    });
    expect(await stateOf(cfg, 'chatgpt')).toBe('standby');
  });

  it('falls back to this process own map when the store answers nothing', async () => {
    const reportDir = scratch('aka-capture-state-fallback-1-');
    // `live` only becomes true when an exchange parses, so the count goes with
    // it — a status carrying one without the other is a shape the bridge
    // cannot produce.
    await report(configIn(reportDir), 'state-fallback-session', 'claude-ai', ACTIVE);

    // A DIFFERENT (empty) dataDir for the read — the store answers nothing for
    // this site, so the in-memory map is what is left.
    const readDir = scratch('aka-capture-state-fallback-2-');
    expect(await stateOf(configIn(readDir), 'claude-ai')).toBe('active');
  });

  it('prefers this process own newer report over an older row of the same document', async () => {
    // The durable write is fail-open, so a store that still READS while
    // refusing WRITES loses every later report — and a stored row preferred
    // for being stored then reports a state this process has been told is out
    // of date. Stood in for by writing the newer report into a different
    // dataDir, which is what a refused write leaves behind.
    //
    // Both halves carry the SAME root, which is what makes them one document
    // and the choice between them the within-document pick. Two different
    // roots would both vote instead, and the worse would win — the case below
    // is that one.
    const readDir = scratch('aka-capture-state-stale-read-');
    const lostDir = scratch('aka-capture-state-stale-lost-');
    storeRow(readDir, 'state-stale-session', 'chatgpt', BLIND);
    await report(configIn(lostDir), 'state-stale-session', 'chatgpt', ACTIVE);

    expect(await stateOf(configIn(readDir), 'chatgpt')).toBe('active');
  });

  it('does not let a healthy document mask another document drift', async () => {
    // The popup is the first surface a user checks, and it used to answer with
    // the newest report for the site whichever tab wrote it — so a second tab
    // that was capturing fine reported the site healthy while this one was
    // swallowing the user's messages.
    const dataDir = scratch('aka-capture-state-mask-');
    const cfg = configIn(dataDir);
    storeRow(dataDir, 'doc-blind', 'chatgpt', BLIND);
    await report(cfg, 'doc-healthy', 'chatgpt', ACTIVE);

    expect(await stateOf(cfg, 'chatgpt')).toBe('blind');
  });

  it('stops counting a document that said it was going away', async () => {
    // The same two tabs, except the drifting one has unloaded — which is what
    // the `blind` remediation asks the user to do. Its verdict stops voting,
    // so the reload clears the state instead of being shown it for another
    // thirty days.
    const dataDir = scratch('aka-capture-state-closed-');
    const cfg = configIn(dataDir);
    storeRow(dataDir, 'doc-gone', 'chatgpt', { ...BLIND, closed: true });
    await report(cfg, 'doc-healthy', 'chatgpt', ACTIVE);

    expect(await stateOf(cfg, 'chatgpt')).toBe('active');
  });

  it('answers from this process own map when the store read throws', async () => {
    // The inner catch is the only thing keeping a contended store from turning
    // the popup's whole reply into runHost's generic error, and the popup is
    // the first surface a user checks. It lives HERE rather than in
    // host.test.ts for this file's own reason: the answer depends on which
    // documents exist, and only a fresh module gives this case the one-tab
    // browser it describes.
    //
    // Two homes: the report lands in one, and the read is pointed at a regular
    // FILE so opening the store throws while resolving.
    const reportDir = scratch('aka-capture-state-readfail-');
    await report(configIn(reportDir), 'doc-readfail', 'chatgpt', ACTIVE);

    const blocker = join(scratch('aka-capture-state-blocked-'), 'blocker');
    mkdirSync(dirname(blocker), { recursive: true });
    writeFileSync(blocker, 'x');

    // Not an error, and not empty: this process's own report answers.
    expect(await stateOf(configIn(blocker), 'chatgpt')).toBe('active');
  });

  it('keeps one site documents out of another site answer', async () => {
    const dataDir = scratch('aka-capture-state-sites-');
    const cfg = configIn(dataDir);
    storeRow(dataDir, 'doc-blind-chatgpt', 'chatgpt', BLIND);
    await report(cfg, 'doc-healthy-claude', 'claude-ai', ACTIVE);

    expect(await stateOf(cfg, 'chatgpt')).toBe('blind');
    expect(await stateOf(cfg, 'claude-ai')).toBe('active');
  });
});
