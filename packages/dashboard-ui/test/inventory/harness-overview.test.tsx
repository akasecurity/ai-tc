import type { HarnessEventsResponse, HarnessSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { HarnessOverview } from '../../src/inventory/HarnessOverview.tsx';

// The enforcement-event rows bucket each event as "Today" / "Yesterday" / a
// date, and that bucket is relative to an instant. It is the same hydration
// defect the relative-time labels have, in a shape a search for `relativeTime`
// does not find: the derivation lives in a module-level helper, so it is also
// invisible to `react-hooks/purity`, which reports a clock read inside a
// component. The `use client`-scoped clock ban is what found it, and this is
// what keeps it found.
//
// The boundary here is local midnight rather than a rounding tier, so the
// fixtures are built from local parts — a UTC literal would bucket differently
// depending on the runner's time zone and make this test's own answer a
// property of the machine.
const noop = (): void => undefined;

function at(day: number, hour: number): string {
  return new Date(2026, 6, day, hour, 30).toISOString();
}

function harness(): HarnessSummary {
  return {
    id: 'claudecode',
    label: 'Claude Code',
    kind: 'cli',
    version: '1.0.0',
    sessions: 1,
    assetCount: 0,
    flagCount: 0,
    projects: [],
    categories: [],
  };
}

function events(occurredAt: string): HarnessEventsResponse {
  return {
    counts: { block: 1, redact: 0, warn: 0 },
    items: [{ kind: 'block', title: 'aws-access-key', detail: 'blocked', occurredAt }],
  };
}

describe('HarnessOverview buckets its event rows against the instant it is given', () => {
  // A clock a long way from either fixture instant, so a helper that reached for
  // it would bucket every row as a bare date and fail both cases below.
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2027, 11, 25, 12, 0));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function render(occurredAt: string, renderedAt: number): string {
    return renderToStaticMarkup(
      <HarnessOverview
        harness={harness()}
        events={events(occurredAt)}
        onSelect={noop}
        onSelectProject={noop}
        renderedAt={renderedAt}
      />,
    );
  }

  it('labels one event two different ways on either side of local midnight', () => {
    // The same event, rendered at 23:00 on the 5th and again at 01:00 on the
    // 6th. Two renders of one input across a boundary — which is exactly what a
    // server render and a late hydration are.
    const event = at(5, 22);
    const before = render(event, new Date(2026, 6, 5, 23, 0).getTime());
    const after = render(event, new Date(2026, 6, 6, 1, 0).getTime());

    expect(before).toContain('Today');
    expect(before).not.toContain('Yesterday');
    expect(after).toContain('Yesterday');
  });

  it('falls back to a dated bucket beyond yesterday', () => {
    const html = render(at(1, 12), new Date(2026, 6, 5, 12, 0).getTime());
    expect(html).not.toContain('Today');
    expect(html).not.toContain('Yesterday');
    expect(html).toContain('Jul');
  });
});
