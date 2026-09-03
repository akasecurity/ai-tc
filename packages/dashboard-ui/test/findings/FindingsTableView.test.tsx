import type { FindingGroup, FindingInstance } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { FindingsTableView } from '../../src/findings/FindingsTableView.tsx';
import { FINDINGS_COLUMNS } from '../../src/findings/meta.ts';

// The grouped table renders its `latest` column twice over — once from
// GROUP_CELL for the group row, once from INSTANCE_CELL for each expanded
// instance row — and each reaches `relativeTime` with an instant of its own.
// The sibling flat view's suite cannot see either: it renders a different
// component.
//
// Both cells are pinned here against a fixed instant far from the fixtures, so
// a cell that fell back to the ambient clock reads a five-figure age rather
// than the hours the assertions name.
const RENDERED_AT = Date.parse('2026-07-05T12:00:00.000Z');

// Three hours and two days before RENDERED_AT. The two differ so a cell that
// rendered the wrong row's timestamp is caught as well as one that read the
// wrong clock.
const GROUP_LATEST = '2026-07-05T09:00:00.000Z';
const INSTANCE_DETECTED = '2026-07-03T12:00:00.000Z';

function instance(over: Partial<FindingInstance> = {}): FindingInstance {
  return {
    id: 'fnd-1',
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/db.ts',
    action: 'blocked',
    detectedAt: INSTANCE_DETECTED,
    confidence: 0.9,
    status: 'handled',
    ...over,
  };
}

function group(over: Partial<FindingGroup> = {}): FindingGroup {
  return {
    id: 'aws-key',
    category: 'secret',
    subtype: 'aws-key',
    severity: 'critical',
    match: { maskedValue: 'AKIA****', contextPrefix: '' },
    detection: { id: 'aws-key', name: null },
    policy: { id: 'category:secret', name: 'secret' },
    instanceCount: 1,
    providers: ['claudecode'],
    aggregateAction: 'blocked',
    latestDetectedAt: GROUP_LATEST,
    instances: [instance()],
    status: 'handled',
    ...over,
  };
}

function render(props: Partial<Parameters<typeof FindingsTableView>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingsTableView
      renderedAt={RENDERED_AT}
      groups={[group()]}
      columns={FINDINGS_COLUMNS}
      selection={null}
      expandedIds={new Set<string>()}
      onToggleExpand={vi.fn()}
      onSelectGroup={vi.fn()}
      onSelectInstance={vi.fn()}
      {...props}
    />,
  );
}

describe('FindingsTableView measures both latest columns against the instant it is handed', () => {
  it('renders the group row age against renderedAt, not the ambient clock', () => {
    const html = render();

    expect(html).toContain('3 hours ago');
  });

  it('renders an expanded instance row age against the same instant', () => {
    const html = render({ expandedIds: new Set(['aws-key']) });

    // The group's own cell is still there; the instance's is the second.
    expect(html).toContain('3 hours ago');
    expect(html).toContain('2 days ago');
  });

  it('is a fixture the ambient clock could not produce', () => {
    // The control for the two cases above. Both assert a SHORT age, which is
    // exactly what a view reading `Date.now()` would stop producing the moment
    // the fixtures aged — so pin that the fixtures really are far from now.
    // Without this, a regression to the ambient clock reads "3h ago" on any
    // machine whose date happens to sit near the fixture, and both cases pass.
    const ageFromRealClock = Date.now() - Date.parse(GROUP_LATEST);
    expect(Math.abs(ageFromRealClock)).toBeGreaterThan(30 * 24 * 60 * 60 * 1000);
  });
});
