import { Tabs } from '@akasecurity/ui-kit';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DataSharesKindTabsView } from '../../src/data-shares/DataSharesKindTabsView.tsx';
import { group } from './fixtures.ts';

// TabsList/TabsTrigger need a ui-kit Tabs ancestor for Radix context — the app
// owns that Tabs root in the real page, so the test supplies one directly.
function renderTabs(groups: Parameters<typeof DataSharesKindTabsView>[0]['groups']): string {
  const firstKind = groups[0]?.kind;
  return renderToStaticMarkup(
    <Tabs {...(firstKind ? { value: firstKind } : {})}>
      <DataSharesKindTabsView groups={groups} />
    </Tabs>,
  );
}

describe('DataSharesKindTabsView', () => {
  it('renders one tab per group with its label and count', () => {
    const html = renderTabs([
      group({ kind: 'provider', total: 18 }),
      group({ kind: 'internal', total: 1 }),
    ]);
    expect(html).toContain('Providers');
    expect(html).toContain('18');
    expect(html).toContain('Internal &amp; corporate domains');
    expect(html).toContain('1');
  });

  it('renders no tabs for an empty group list', () => {
    const html = renderTabs([]);
    expect(html).not.toContain('role="tab"');
  });

  it('flags external and ip groups with a warning icon, not provider or internal', () => {
    const withoutFlag = renderTabs([group({ kind: 'provider' }), group({ kind: 'internal' })]);
    expect(withoutFlag).not.toContain('<svg');

    const withFlag = renderTabs([group({ kind: 'external' }), group({ kind: 'ip' })]);
    // One AlertIcon svg per flagged tab.
    expect(withFlag.split('<svg').length - 1).toBe(2);
  });

  it('gives the warning icon accessible text, since the icon itself is aria-hidden', () => {
    // The icon replaced a visible "review recommended" label; without this a
    // screen reader hears only the tab name and count.
    const withFlag = renderTabs([group({ kind: 'ip' })]);
    expect(withFlag).toContain('review recommended');
    expect(withFlag).toContain('sr-only');

    const withoutFlag = renderTabs([group({ kind: 'provider' })]);
    expect(withoutFlag).not.toContain('review recommended');
  });
});
