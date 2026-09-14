import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { WebCaptureCardView, type WebCaptureCardViewProps } from '@akasecurity/dashboard-ui';
import {
  applyOnboarding,
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
} from '@akasecurity/persistence';
import type { WebCaptureStatus, WebSourceTool } from '@akasecurity/schema';
import {
  CAPTURE_STATUS_RECENCY_MS,
  toCaptureStatusAttributes,
  WEB_CHAT_CAPTURE_CONSENT_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { emptyStore } from '../helpers/store-templates.ts';

// The store-backed half of the web-capture-drift read-time derivation: a row
// inserted into SQLite -> SqliteCaptureStatusRepository.latest() ->
// webCaptureReport -> the page's props. A direct call to webCaptureReport (the
// detections-package suite) would not exercise the store read at all.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

let home: string;
let dir: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

const BASE_STATUS: WebCaptureStatus = {
  patched: true,
  live: false,
  blind: false,
  sendsSeenDom: 0,
  exchangesSeenNet: 0,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
  conversationEndpoints: 0,
  enforcement: 'watching',
};

let seedCounter = 0;

/**
 * Every seed is stamped relative to NOW rather than at a fixed calendar date:
 * the store read is bounded to the last `CAPTURE_STATUS_RECENCY_MS`, so a
 * literal 2026-01-01 would silently age out of the window as the wall clock
 * moved past it and every case below would then pass for the wrong reason.
 */
function seedStatus(tool: WebSourceTool, status: WebCaptureStatus, agoMs = 0): void {
  seedCounter += 1;
  const db = openLocalDatabase(dir);
  try {
    db.auditEvents.insertAuditEvent({
      id: `${tool}-status-${String(seedCounter)}`,
      eventType: 'capture_status',
      startedAt: new Date(Date.now() - agoMs).toISOString(),
      attributes: toCaptureStatusAttributes(status, tool),
    });
  } finally {
    db.close();
  }
  // The page opens its own memoised handle through db(); drop it so the next
  // read reopens and sees this write.
  resetSingleton();
}

/**
 * Record a web-chat capture consent, which every case but the consent ones
 * needs: the page reads the same `isWebChatCaptureConsentValid` predicate
 * `aka extension status` does, and an unonboarded home has no grant at all.
 */
function grantConsent(version: number = WEB_CHAT_CAPTURE_CONSENT_VERSION): void {
  applyOnboarding(
    {
      webChatCapture: {
        responses: 'with-findings',
        account: false,
        consent: { acknowledgedAt: new Date().toISOString(), version },
      } as never,
    },
    join(home, '.aka'),
  );
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-capture-'));
  osHome.dir = home;
  dir = dataDir();
  // The security page reads no installed-pack surface here — only the
  // security repositories and capture-status, so the schema alone is enough.
  emptyStore.seed(dir);
  resetSingleton();
  seedCounter = 0;
});

afterEach(() => {
  resetSingleton();
  removeTree(home);
});

/** Walk the element tree the page returns for a `WebCaptureCardView` node. */
function captureCard(node: unknown): { props: WebCaptureCardViewProps } | undefined {
  if (node === null || typeof node !== 'object') return undefined;
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = captureCard(child);
      if (found !== undefined) return found;
    }
    return undefined;
  }
  if ((node as { type?: unknown }).type === WebCaptureCardView) {
    return node as { props: WebCaptureCardViewProps };
  }
  const props: unknown = (node as { props?: unknown }).props;
  if (props !== null && typeof props === 'object') {
    return captureCard((props as { children?: unknown }).children);
  }
  return undefined;
}

async function renderSecurityPage(): Promise<{ props: { children: unknown[] } }> {
  const mod = await import('../../app/(app)/security/page.tsx');
  const element = (await (mod.default as (props: { searchParams: Promise<object> }) => unknown)({
    searchParams: Promise.resolve({}),
  })) as { props: { children: unknown[] } };
  return element;
}

/** A status that drifts: endpoints declared, and messages the network never saw. */
const DRIFTING: WebCaptureStatus = {
  ...BASE_STATUS,
  conversationEndpoints: 1,
  blind: true,
  sendsSeenDom: 3,
};

describe('the security page derives web-capture posture at read time', () => {
  it('is quiet when the store holds no capture_status row', async () => {
    grantConsent();
    const element = await renderSecurityPage();
    expect(captureCard(element)).toBeUndefined();

    // The guard renders `false` in place of the card block, so every OTHER
    // top-level child of the page is unaffected by its presence or absence.
    // The card sits outside <WidgetNavigation>, so the root's rendered children
    // are the page head and that wrapper, with the guard's `false` last.
    const topLevel = element.props.children;
    expect(topLevel.filter(Boolean)).toHaveLength(2);
    expect(topLevel.at(-1)).toBe(false);
  });

  it("is quiet on today's state — a build declaring no endpoints reports standby, not drift", async () => {
    grantConsent();
    // Every drift signal at once, under `conversationEndpoints: 0`. That is
    // the whole state of the product today, on every machine that installs the
    // extension, so a card here would be a permanent fixture on the default
    // security surface saying nothing anyone can act on.
    seedStatus('chatgpt', {
      ...BASE_STATUS,
      conversationEndpoints: 0,
      patched: true,
      blind: true,
      parseFailures: 7,
      shapeMisses: ['a', 'b'],
      sendsSeenDom: 9,
    });

    expect(captureCard(await renderSecurityPage())).toBeUndefined();
  });

  it('fires on drift and reaches the page through the real store read', async () => {
    grantConsent();
    seedStatus('claude-ai', DRIFTING);

    const card = captureCard(await renderSecurityPage());
    expect(card).toBeDefined();

    const claudeAi = card?.props.sites.find((s) => s.tool === 'claude-ai');
    expect(claudeAi?.drift).toBe(true);
    expect(claudeAi?.stateLabel).toBe('blind');
    expect(claudeAi?.headline).toContain('the network capture never saw');
    expect(claudeAi?.remediation).toContain('reload the tab');

    expect(card?.props.ruleId).toBe('web-capture-drift');
    expect(card?.props.severity).toBe('medium');
  });

  it('carries only the drifting site, deriving each site independently', async () => {
    grantConsent();
    seedStatus('chatgpt', DRIFTING);
    seedStatus('claude-ai', { ...BASE_STATUS, conversationEndpoints: 1, live: true });

    const card = captureCard(await renderSecurityPage());
    expect(card?.props.sites.map((s) => s.tool)).toEqual(['chatgpt']);
    expect(card?.props.sites.every((s) => s.drift)).toBe(true);
  });

  it('the newest report that observed the turn path wins over a later watching-only one', async () => {
    grantConsent();
    // Older: blind — a real verdict. Newer: watching-only (declares
    // endpoints, patched, nothing else) — says nothing about the turn path.
    seedStatus('chatgpt', DRIFTING, 60_000);
    seedStatus('chatgpt', { ...BASE_STATUS, conversationEndpoints: 1 }, 0);

    const card = captureCard(await renderSecurityPage());
    const chatgpt = card?.props.sites.find((s) => s.tool === 'chatgpt');
    expect(chatgpt?.stateLabel).toBe('blind');
    expect(chatgpt?.drift).toBe(true);
  });
});

// Two ways a stored drift verdict stops being something to say. Both are
// asserted against the SAME seeded row as the positive control above, so a
// case that goes quiet for some unrelated reason cannot pass here.
describe('the security page will not recite a drift verdict nothing can supersede', () => {
  it('says nothing when no web-chat capture consent is recorded', async () => {
    seedStatus('claude-ai', DRIFTING);

    // No grantConsent(): an unonboarded home records none, which is exactly
    // what a machine that has never enabled web-chat capture looks like.
    expect(captureCard(await renderSecurityPage())).toBeUndefined();

    // The control: the identical store, read with a valid grant in place, does
    // render the card. Without this the absence above proves nothing.
    grantConsent();
    resetSingleton();
    expect(captureCard(await renderSecurityPage())).toBeDefined();
  });

  it('says nothing when the recorded consent names a different version', async () => {
    // The fleet-wide case: `isWebChatCaptureConsentValid` is an EQUALITY on
    // the version, so a consent-version bump retires every installed machine's
    // grant at once and the native host then records no further status — the
    // stored verdict below can never be superseded. Driven from the other side
    // of that equality because the schema requires a positive version, so the
    // "one behind the current" grant is not expressible while the current
    // version is 1; the predicate does not distinguish the two directions.
    grantConsent(WEB_CHAT_CAPTURE_CONSENT_VERSION + 1);
    seedStatus('claude-ai', DRIFTING);

    expect(captureCard(await renderSecurityPage())).toBeUndefined();
  });

  it('says nothing when the verdict has aged out of the read window', async () => {
    grantConsent();
    seedStatus('claude-ai', DRIFTING, CAPTURE_STATUS_RECENCY_MS + 60_000);

    expect(captureCard(await renderSecurityPage())).toBeUndefined();

    // The control: the same status, inside the window, does render — so the
    // absence above is the window's doing and not the seed's.
    seedStatus('claude-ai', DRIFTING, 60_000);
    expect(captureCard(await renderSecurityPage())).toBeDefined();
  });
});
