import type { ActivitySession } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { SessionDetailView } from '../../src/activity/SessionDetailView.tsx';

// SessionDetailView's "Started"/"Duration" meta lines read `dayLabel` and
// `durationLabel` the same way SessionListView's row does — but this view had
// no `renderedAt` prop at all before this PR, so both calls fell straight
// through to format.ts's ambient-clock defaults. Confirmed live: the app-level
// host (ActivityClient) builds a `detailProps` object shared by the docked
// pane and the full-width inspector and never included `renderedAt` in it,
// so opening either for an in-progress or midnight-adjacent session rendered
// one string on the server and another at hydration.
function session(over: Partial<ActivitySession> = {}): ActivitySession {
  return {
    id: 'sess-1',
    harness: 'claudecode',
    title: 'Refactor auth',
    project: 'api',
    repo: 'acme/api',
    branches: ['main'],
    startedAt: '2026-07-05T08:00:00.000Z',
    endedAt: null,
    status: 'active',
    turns: 4,
    findings: 0,
    shares: 0,
    host: 'dev-box',
    cwd: '/Users/dev/api',
    models: ['claude-opus-5'],
    version: '1.0.0',
    tokens: {
      sessionId: 'sess-1',
      model: 'claude-opus-5',
      provider: 'anthropic',
      inputTokens: 100,
      outputTokens: 200,
      cacheCreation: 0,
      cacheRead: 0,
      totalTokens: 300,
      estimatedCostUsd: null,
    },
    tools: {},
    files: [],
    commits: 0,
    events: [],
    ...over,
  };
}

function render(props: Partial<Parameters<typeof SessionDetailView>[0]> = {}) {
  return renderToStaticMarkup(
    <SessionDetailView
      session={session()}
      isLoading={false}
      error={null}
      renderedAt={Date.parse('2026-07-05T09:00:00.000Z')}
      {...props}
    />,
  );
}

describe('SessionDetailView measures its Duration meta line against the instant it is handed', () => {
  it('renders an active session duration against renderedAt, not the ambient clock', () => {
    const html = render();

    expect(html).toContain('1h 0m · live');
  });

  it('is a fixture the ambient clock could not produce', () => {
    const ambientMs = Date.now() - Date.parse('2026-07-05T08:00:00.000Z');
    expect(Math.abs(ambientMs)).toBeGreaterThan(30 * 24 * 60 * 60 * 1000);
  });
});

describe('SessionDetailView measures its Started day label against the instant it is handed', () => {
  // Local-part construction, matching SessionListView's suite — the boundary
  // is local midnight, so a UTC literal buckets differently by the runner's
  // own time zone.
  function at(day: number, hour: number): string {
    return new Date(2026, 6, day, hour, 30).toISOString();
  }

  it('labels Today when renderedAt is the same local day as startedAt', () => {
    const html = render({
      session: session({ startedAt: at(5, 20) }),
      renderedAt: new Date(2026, 6, 5, 22, 0).getTime(),
    });

    expect(html).toContain('Today');
  });

  it('relabels the SAME session Yesterday once renderedAt crosses local midnight', () => {
    const html = render({
      session: session({ startedAt: at(5, 23) }),
      renderedAt: new Date(2026, 6, 6, 1, 0).getTime(),
    });

    expect(html).toContain('Yesterday');
  });
});
