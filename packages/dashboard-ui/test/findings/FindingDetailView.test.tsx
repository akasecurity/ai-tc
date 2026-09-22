// @vitest-environment jsdom
//
// The drawer renders ONE instance, and this suite exists because the grouped
// rendering it used to carry was deleted with no test on either side of it.
// `Selection.instance` is required now, so the unreachable branch cannot come
// back by accident — what the type cannot state is what the remaining branch
// puts on screen, which is what these cases pin.
//
// The title is the sharp one: it doubles as the dialog's accessible name via
// Radix's `aria-labelledby`, so a change that left it blank or non-identifying
// would cost a screen-reader user the only thing distinguishing one drawer from
// another, and would break no other assertion in either repo.
//
// jsdom rather than `renderToStaticMarkup`, and the reason is structural, not a
// preference: `SheetContent` portals through `Dialog.Portal`, and a portal
// server-renders to the empty string — a `toContain` against that passes for
// every input and fails for none. Queries go through `document`, never the host
// div, for the same reason: the content is portalled out of it.
import type { FindingGroup, FindingInstance } from '@akasecurity/schema';
import { HARNESS } from '@akasecurity/schema';
import { Sheet, SheetContent } from '@akasecurity/ui-kit';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FindingDetailView } from '../../src/findings/FindingDetailView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const instance = {
  id: 'inst-0f3a',
  groupId: 'grp-1',
  category: 'secret',
  subtype: 'aws-access-key',
  severity: 'critical',
  provider: HARNESS.ClaudeCode,
  repo: 'acme/api',
  file: 'src/config.ts',
  action: 'blocked',
  detectedAt: 1_700_000_000_000,
  confidence: 0.94,
  match: { contextPrefix: 'const key = ', maskedValue: 'AKIA****KEY' },
} as unknown as FindingInstance;

const finding = {
  id: 'grp-1',
  category: 'secret',
  subtype: 'aws-access-key',
  severity: 'critical',
  match: { contextPrefix: 'const key = ', maskedValue: 'AKIA****KEY' },
  instanceCount: 1,
  providers: [HARNESS.ClaudeCode],
  instances: [instance],
  aggregateAction: 'blocked',
  latestDetectedAt: 1_700_000_000_000,
} as unknown as FindingGroup;

// An instant AFTER the fixture's detectedAt, passed explicitly: the view takes
// `renderedAt` precisely so it never reads the ambient clock.
const RENDERED_AT = 1_700_000_060_000;

let mounted: MountedRoot;

beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

function render(): void {
  renderRoot(
    mounted.root,
    <Sheet open>
      <SheetContent>
        <FindingDetailView selection={{ finding, instance }} renderedAt={RENDERED_AT} />
      </SheetContent>
    </Sheet>,
  );
}

describe('FindingDetailView', () => {
  it('titles the drawer with the instance id, and names the dialog by it', () => {
    render();
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();

    const labelledBy = dialog?.getAttribute('aria-labelledby');
    expect(labelledBy).toBeTruthy();

    // The accessible name is resolved rather than assumed: asserting the title's
    // text alone would pass even if `aria-labelledby` pointed somewhere else.
    const named = document.getElementById(String(labelledBy));
    expect(named?.textContent).toBe('inst-0f3a');
  });

  it('renders the single-instance detail, not a locations list', () => {
    render();
    const text = document.body.textContent;
    expect(text).toContain('AKIA****KEY');

    // The META ROWS by label, not by their values: `src/config.ts` also appears
    // in MatchedContent's file line, so a `toContain` on the value alone passes
    // with the Location row deleted — verified by mutation, which is why this
    // reads the labels the grid actually rendered.
    const metaLabels = [...document.querySelectorAll('div.text-label')].map((el) =>
      el.textContent.trim(),
    );
    expect(metaLabels).toEqual([
      'Source tool',
      'Repository',
      'Location',
      'Action taken',
      'Detected',
      'Confidence',
    ]);
    // The control for the two assertions below: the drawer really did render.
    expect(text).toContain('Matched content');

    // Both belonged to the deleted grouped branch and to nothing else. The
    // first is checked per ELEMENT, not as a substring of the body: the
    // single-instance grid carries a "Location" label immediately followed by
    // its value, so the concatenated textContent spells "Locationsrc/config.ts"
    // — which contains "Locations" and fails a body-level `not.toContain` for a
    // reason that has nothing to do with the grouped list.
    const exactly = (s: string): boolean =>
      [...document.querySelectorAll('*')].some((el) => el.textContent.trim() === s);
    expect(exactly('Locations')).toBe(false);
    // The control for that predicate: a label the drawer really does render.
    expect(exactly('Matched content')).toBe(true);
    expect(exactly('Back to finding')).toBe(false);
  });

  it('offers exactly one dismissal control — the sheet close', () => {
    render();
    const dialog = document.querySelector('[role="dialog"]');
    const buttons = [...(dialog?.querySelectorAll('button') ?? [])];
    expect(buttons).toHaveLength(1);
    expect(buttons[0]?.textContent).toContain('Close');
  });
});
