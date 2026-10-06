// @vitest-environment jsdom
//
// The property the explicit `locale` prop exists for: a client component
// renders once on the server and again when the browser hydrates it, and the
// two renders must produce the same text. A count or a time formatted in the
// RENDERER's own locale does not — a Node host on en-US emits `1,234` where a
// de-DE browser hydrates `1.234` — and React resolves that by throwing the
// server's markup away and rebuilding the subtree in the browser.
//
// One process stands in for both renderers. The server render runs under a
// runtime whose default locale is en-US and the hydration under one whose
// default is de-DE (test/helpers/runtime-locale.ts moves the default), while the
// route hands both the de-DE locale a de-DE reader's Accept-Language resolves
// to. A view that formats through the prop renders `1.234` both times and
// hydrates cleanly; one that reaches for the runtime renders `1,234` and then
// `1.234`, and React reports it.
//
// The CONTROL is what makes the clean cases mean anything. A harness that
// failed to move the default, or that missed the hydration error React raises,
// would pass every case below; the first case drives a component formatted
// with a bare toLocaleString() through the same harness and requires the
// mismatch to be reported.
import { HarnessOverview, PolicyStatsView, SyncPanelView } from '@akasecurity/dashboard-ui';
import type {
  ActivitySession,
  ActivitySessionSummary,
  FindingInstanceDetail,
  FindingLocationSummary,
  FindingsOverview,
} from '@akasecurity/schema';
import type React from 'react';
import { act, createElement, type ReactElement } from 'react';
import { hydrateRoot, type Root } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { withRuntimeLocale } from '../../../test/helpers/runtime-locale.ts';

vi.mock('next/navigation', () => ({
  usePathname: () => '/',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn(), refresh: vi.fn() }),
}));

const { ActivityClient } = await import('../../app/(app)/activity/ActivityClient.tsx');
const { FindingsClient } = await import('../../app/(app)/findings/FindingsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

/** What a de-DE reader's request resolves to. */
const READER = 'de-DE';
/** The two renderers' own defaults, deliberately unlike each other. */
const SERVER_DEFAULT = 'en-US';
const BROWSER_DEFAULT = 'de-DE';

const RENDERED_AT = new Date(2026, 6, 5, 21, 0).getTime();

interface Hydrated {
  /** Every hydration error React raised, through either of its two channels. */
  errors: string[];
  serverHtml: string;
  text: string;
}

let roots: Root[] = [];

/**
 * Server-renders `tree` under the server's default locale, then hydrates the
 * markup under the browser's, collecting what React reports.
 *
 * React raises a text mismatch through `onRecoverableError` and an attribute
 * mismatch — a `title` — through `console.error` only, so both are read. Only
 * the HYDRATION messages on the console channel count: anything else a view
 * logs (a missing key, say) is passed through to stderr, so this
 * suite cannot go red for a defect it does not test and name the locale.
 */
function hydrate(tree: () => ReactElement): Hydrated {
  const serverHtml = withRuntimeLocale(SERVER_DEFAULT, () => renderToString(tree()));
  const container = document.createElement('div');
  container.innerHTML = serverHtml;
  document.body.append(container);
  const errors: string[] = [];
  const consoleError = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    const message = args.map(String).join(' ');
    if (/hydrat/i.test(message)) errors.push(message);
    else process.stderr.write(`${message}\n`);
  });
  try {
    withRuntimeLocale(BROWSER_DEFAULT, () => {
      act(() => {
        roots.push(
          hydrateRoot(container, tree(), {
            onRecoverableError: (error) => {
              errors.push(String(error));
            },
          }),
        );
      });
    });
  } finally {
    consoleError.mockRestore();
  }
  return { errors, serverHtml, text: container.textContent };
}

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
  vi.setSystemTime(RENDERED_AT);
});

afterEach(() => {
  act(() => {
    for (const root of roots) root.unmount();
  });
  roots = [];
  document.body.innerHTML = '';
  vi.useRealTimers();
});

describe('the harness', () => {
  it('reports a count formatted in the renderer’s own locale', () => {
    function Unpinned({ title }: { title: boolean }) {
      const n = (1234).toLocaleString();
      return title ? createElement('span', { title: n }, 'x') : createElement('span', null, n);
    }
    const text = hydrate(() => createElement(Unpinned, { title: false }));
    expect(text.serverHtml).toContain('1,234');
    expect(text.errors.join('\n')).toMatch(/hydrat/i);
    // And through the attribute channel, which React reports differently.
    const attr = hydrate(() => createElement(Unpinned, { title: true }));
    expect(attr.serverHtml).toContain('title="1,234"');
    expect(attr.errors.join('\n')).toMatch(/hydrat/i);
  });

  it('reports a relative time formatted in the renderer’s own locale', () => {
    // The stand-in moves every Intl formatter's default, not only the number
    // and date ones — the lint ban names RelativeTimeFormat too.
    function Unpinned() {
      return createElement('span', null, new Intl.RelativeTimeFormat().format(-1, 'day'));
    }
    const result = hydrate(() => createElement(Unpinned));
    expect(result.serverHtml).toContain('1 day ago');
    expect(result.errors.join('\n')).toMatch(/hydrat/i);
  });
});

// ─── Findings: the page-head tally, the summary strip, the location list ─────

const OVERVIEW: FindingsOverview = {
  findings: 1234,
  open: 1001,
  handled: 2002,
  resolved: 3003,
  dismissed: 4004,
};

function findingsRoute(view: 'grouped' | 'files'): ReactElement {
  const facets = { severity: [], subtype: [], provider: [], action: [], status: [] };
  const location: FindingLocationSummary = {
    id: 'loc-1',
    repo: 'acme/api',
    file: 'cfg/.env',
    instanceCount: 5678,
    maxSeverity: 'critical',
    latestDetectedAt: new Date(RENDERED_AT - 3_600_000).toISOString(),
    status: 'open',
    ruleIds: ['secrets/aws-access-key'],
  };
  const noInstances = {
    totals: { findings: 0 },
    facets,
    items: [] as FindingInstanceDetail[],
    nextCursor: null,
  };
  const arm =
    view === 'grouped'
      ? {
          view,
          types: { totals: { findings: 6456, types: 0 }, facets, items: [], nextCursor: null },
          instances: null,
          selectedRule: '',
          deepLinkedInstance: null,
        }
      : {
          view,
          locations: {
            totals: { findings: 6456, locations: 1 },
            facets,
            items: [location],
            nextCursor: null,
          },
          instances: noInstances,
          selectedLocation: location,
          deepLinkedInstance: null,
        };
  return createElement(
    NavigationTransitionProvider,
    null,
    createElement(FindingsClient as unknown as React.FC<Record<string, unknown>>, {
      filters: { severity: [], type: [], provider: [], action: [], status: [], deployment: [] },
      query: '',
      session: '',
      range: null,
      from: null,
      tools: [],
      repo: '',
      file: '',
      renderedAt: RENDERED_AT,
      locale: READER,
      deployment: null,
      overview: OVERVIEW,
      ...arm,
    }),
  );
}

describe('a de-DE reader on an en-US server', () => {
  it('hydrates the findings tally and summary strip without a mismatch', () => {
    const result = hydrate(() => findingsRoute('grouped'));
    expect(result.errors).toEqual([]);
    expect(result.serverHtml).toContain('6.456');
    expect(result.serverHtml).toContain('1.234');
    expect(result.text).toContain('6.456');
    expect(result.text).not.toContain('6,456');
  });

  it('hydrates the location list’s exact counts without a mismatch', () => {
    const result = hydrate(() => findingsRoute('files'));
    expect(result.errors).toEqual([]);
    expect(result.serverHtml).toContain('title="5.678 findings"');
  });

  it('hydrates the activity list and detail times without a mismatch', () => {
    const startedAt = new Date(2026, 6, 5, 20, 5, 9).toISOString();
    const summary: ActivitySessionSummary = {
      id: 'sess-1',
      harness: 'claudecode',
      title: 'Refactor auth',
      project: 'api',
      repo: 'acme/api',
      branches: ['main'],
      startedAt,
      endedAt: null,
      status: 'active',
      turns: 4,
      findings: 0,
      shares: 0,
    };
    const detail: ActivitySession = {
      ...summary,
      host: 'dev-box',
      cwd: '/Users/dev/api',
      models: [],
      version: '1.0.0',
      tokens: {
        sessionId: 'sess-1',
        model: 'm',
        provider: 'anthropic',
        inputTokens: 0,
        outputTokens: 0,
        cacheCreation: 0,
        cacheRead: 0,
        totalTokens: 0,
        estimatedCostUsd: null,
      },
      tools: {},
      files: [],
      commits: 0,
      events: [
        {
          id: 'e1',
          occurredAt: startedAt,
          kind: 'tool',
          title: 'ls',
          detail: 'ls -la',
          tool: 'Bash',
          severity: null,
          link: null,
          targetId: null,
          internal: false,
          flagged: false,
          bodyExpired: false,
        },
      ],
    };
    const result = hydrate(() =>
      createElement(
        NavigationTransitionProvider,
        null,
        createElement(ActivityClient, {
          sessions: [summary],
          detail,
          tokenReport: null,
          liveFindings: null,
          q: '',
          harness: [],
          harnessOptions: [],
          range: '30d',
          selectedId: 'sess-1',
          hasMore: false,
          emptyCount: 0,
          showEmpty: false,
          expanded: false,
          renderedAt: RENDERED_AT,
          locale: READER,
        }),
      ),
    );
    expect(result.errors).toEqual([]);
    // de-DE's 24-hour clock in the detail's start line, where en-US would read
    // `8:05 PM`, and its day-first date in the row's tooltip.
    expect(result.serverHtml).toContain('20:05');
    expect(result.serverHtml).toContain('title="5.7.2026, 20:05:09"');
    expect(result.serverHtml).not.toMatch(/8:05\sPM/);
  });

  it('hydrates the inventory event times without a mismatch', () => {
    const result = hydrate(() =>
      createElement(HarnessOverview, {
        harness: {
          id: 'claudecode',
          label: 'Claude Code',
          kind: 'cli',
          version: '1.0.0',
          sessions: 1,
          assetCount: 0,
          flagCount: 0,
          projects: [],
          categories: [],
        },
        events: {
          counts: { block: 1, redact: 0, warn: 0 },
          items: [
            {
              kind: 'block',
              title: 'aws-access-key',
              detail: 'blocked',
              occurredAt: new Date(2026, 6, 5, 20, 5).toISOString(),
            },
          ],
        },
        onSelect: () => undefined,
        onSelectProject: () => undefined,
        renderedAt: RENDERED_AT,
        locale: READER,
      }),
    );
    expect(result.errors).toEqual([]);
    expect(result.serverHtml).toContain('20:05');
  });

  it('hydrates the policy and sync-panel counts without a mismatch', () => {
    const policies = hydrate(() =>
      createElement(PolicyStatsView, {
        stats: { policies: 1234, builtin: 1, custom: 2, detectionsGoverned: 3 },
        locale: READER,
      }),
    );
    expect(policies.errors).toEqual([]);
    expect(policies.serverHtml).toContain('1.234');

    const sync = hydrate(() =>
      createElement(SyncPanelView, {
        state: {
          status: 'ready',
          kinds: [
            {
              kind: 'llm_call',
              label: 'Model calls',
              synced: 1234,
              queued: 0,
              notSent: 0,
              total: 5678,
            },
          ],
        },
        deployment: 'plane.example',
        renderedAt: RENDERED_AT,
        locale: READER,
        running: false,
      }),
    );
    expect(sync.errors).toEqual([]);
    expect(sync.serverHtml).toContain('1.234 of 5.678');
  });
});
