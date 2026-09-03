import type { ActivitySessionSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { SessionListView } from '../../src/activity/SessionListView.tsx';

// SessionListView reads the ambient clock through two paths beside the
// `relativeTime` call this class of bug was first fixed for in the same
// element: `durationLabel` for an in-progress session's "46m · live" chip, and
// `groupSessionsByDay` for the Today/Yesterday day headings. Both default their
// `now` parameter in format.ts, so a call site that forgot to pass `renderedAt`
// still compiled — the required-argument guard only reaches a call that
// SUPPLIES nothing, and TypeScript is silent about a caller relying on a
// default it can still see.
//
// The day-heading case is the more severe of the two: `day` becomes the React
// key groupSessionsByDay assigns each section, so getting it from the wrong
// clock does not just relabel a heading, it hands React a different key set —
// the SUBTREE gets discarded and remounted rather than patched, which is the
// exact "structural, not textual" failure this PR's own exceptionState fix
// exists to prevent.
const noop = (): void => undefined;

function session(over: Partial<ActivitySessionSummary> = {}): ActivitySessionSummary {
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
    ...over,
  };
}

function render(props: Partial<Parameters<typeof SessionListView>[0]> = {}) {
  return renderToStaticMarkup(
    <SessionListView
      sessions={[session()]}
      selectedId=""
      onSelect={noop}
      query=""
      onQuery={noop}
      harness={[]}
      onHarness={noop}
      isLoading={false}
      error={null}
      renderedAt={Date.parse('2026-07-05T09:00:00.000Z')}
      {...props}
    />,
  );
}

describe('SessionListView measures its duration chip against the instant it is handed', () => {
  it('renders an active session duration against renderedAt, not the ambient clock', () => {
    // One hour after the fixture's startedAt: the "· live" chip on an active
    // session measures against `now`, so this pins that `now` is `renderedAt`.
    const html = render();

    expect(html).toContain('1h 0m · live');
  });

  it('is a fixture the ambient clock could not produce', () => {
    // The control: a duration read against `Date.now()` would print a duration
    // in the years, not "1h 0m" — pin that renderedAt sits far from now.
    const ambientMs = Date.now() - Date.parse('2026-07-05T08:00:00.000Z');
    expect(Math.abs(ambientMs)).toBeGreaterThan(30 * 24 * 60 * 60 * 1000);
  });
});

// Local-part construction throughout, never a UTC literal — the boundary is
// LOCAL midnight, so a fixture built from a UTC instant buckets differently
// depending on the runner's own time zone (verified: the two cases below flip
// their answer under Pacific/Kiritimati and Asia/Kolkata when built that way).
function at(day: number, hour: number): string {
  return new Date(2026, 6, day, hour, 30).toISOString();
}

describe('SessionListView day-groups sessions against the instant it is handed', () => {
  it('buckets a session under Today when renderedAt is the same local day', () => {
    const html = render({
      sessions: [session({ startedAt: at(5, 20) })],
      renderedAt: new Date(2026, 6, 5, 22, 0).getTime(),
    });

    expect(html).toContain('Today');
  });

  it('buckets the SAME session under Yesterday when renderedAt crosses local midnight', () => {
    // Same session fixture as above, only the clock this render was handed
    // moves — which is exactly what a server render and a late hydration are.
    const html = render({
      sessions: [session({ startedAt: at(5, 23) })],
      renderedAt: new Date(2026, 6, 6, 1, 0).getTime(),
    });

    expect(html).toContain('Yesterday');
    expect(html).not.toContain('>Today<');
  });
});
