// The detections route's own wiring of the enable/disable toggle to the floor.
//
// dashboard-ui pins that the pane withholds a switch-off for a detection under
// a floor, and the page suite pins that the server computes the floor record and
// hands it down. Neither can see the line that joins them, which lives here in a
// client component: `policyFloor={floors[detail.id] ?? null}`. It is a lookup,
// and getting it wrong is quiet — key the record by the wrong id and every
// toggle comes back live, offering a switch-off the store will refuse.
//
// So this renders the component for real and reads the control.
import type { DetectionPolicyFloor } from '@akasecurity/dashboard-ui';
import type { DetectionDetail, ListDetectionsResponse } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// DetectionsClient reaches the router through the shared navigation hook, which
// throws outside a real Next app. Renders here are static — renderToStaticMarkup
// runs no effects — so a no-op router is enough: nothing calls it.
vi.mock('next/navigation', () => ({
  usePathname: () => '/detections',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { DetectionsClient } = await import('../../app/(app)/detections/DetectionsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const DETECTION_ID = 'aka/secrets';

const DETAIL: DetectionDetail = {
  id: DETECTION_ID,
  name: 'Secrets',
  version: '1.0.0',
  enabled: true,
  origin: 'library',
  ruleCount: 1,
  namespace: 'aka',
  packId: 'secrets',
  editedAt: '2026-01-01T00:00:00.000Z',
  findingsLast30d: 0,
  update: null,
  modified: false,
  policyId: 'monitor',
  rules: [
    {
      id: 'secrets/example',
      name: 'Example',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'keyword', keywords: ['example'], caseSensitive: false },
    },
  ],
};

const LIST: ListDetectionsResponse = {
  items: [
    {
      id: DETECTION_ID,
      name: 'Secrets',
      version: '1.0.0',
      enabled: true,
      origin: 'library',
      ruleCount: 1,
      namespace: 'aka',
      packId: 'secrets',
      policyId: 'monitor',
    },
  ],
  counts: { all: 1, library: 1, custom: 0, customized: 0, updates: 0 },
};

function render(floors: Record<string, DetectionPolicyFloor>): string {
  return renderToStaticMarkup(
    createElement(
      NavigationTransitionProvider,
      null,
      createElement(DetectionsClient, {
        list: LIST,
        detail: DETAIL,
        filter: 'all',
        query: '',
        selectedId: DETECTION_ID,
        floors,
      }),
    ),
  );
}

/** The opening tag of the enable/disable Switch, which renders as a <button>. */
function switchTag(markup: string): string {
  const tag = markup
    .split('<button')
    .slice(1)
    .map((chunk) => chunk.slice(0, chunk.indexOf('>')))
    .find((t) => t.includes('data-slot="switch"'));
  expect(tag, 'the page rendered no enable/disable switch at all').toBeDefined();
  return tag ?? '';
}

describe('the detections client hands the pane the floor for the selected detection', () => {
  it('withholds the switch-off for a governed detection', () => {
    const markup = render({ [DETECTION_ID]: { floor: 'warn', locked: false } });
    expect(switchTag(markup)).toContain('aria-disabled="true"');
    expect(markup).toContain('data-slot="enabled-locked-reason"');
  });

  it('leaves it live on a machine nothing manages', () => {
    // The positive control the assertion above needs: an empty record is what
    // every install that has not attached sends, and it must reach the pane as
    // no constraint rather than as one nobody imposed.
    const markup = render({});
    expect(switchTag(markup)).not.toContain('aria-disabled');
    expect(markup).not.toContain('data-slot="enabled-locked-reason"');
  });

  it("does not borrow another detection's floor", () => {
    // The lookup is by detection id. Keyed on anything else — the pack id, the
    // list position — this record would still be non-empty and the toggle would
    // come out withheld for a detection nobody governs.
    const markup = render({ 'aka/something-else': { floor: 'block', locked: true } });
    expect(switchTag(markup)).not.toContain('aria-disabled');
  });
});
