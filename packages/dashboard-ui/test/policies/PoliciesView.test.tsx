import type { PolicyDetail, PolicyListItem } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PolicyDetailView, PolicyListView } from '../../src/policies/PoliciesView.tsx';

// Static-render coverage for the Policies list and detail copy. What the counts
// mean is the host's: one that counts only explicit assignments gets copy that
// says "assigned" (the default), and one whose counts also hold the detections
// with no policy of their own, under the policy they run at, passes
// `countsUnassigned` and gets copy that does not. The local store is the second
// kind; web-ui's policies-page suite renders this copy over it.

const ITEM: PolicyListItem = {
  id: 'block',
  kind: 'builtin',
  name: 'Block',
  enabled: true,
  usedByCount: 3,
};

const DETAIL: PolicyDetail = {
  specVersion: 1,
  id: 'block',
  kind: 'builtin',
  name: 'Block',
  enabled: true,
  description: 'Blocks the request.',
  usedBy: [{ id: 'secrets', name: 'Secrets', ruleCount: 4, enabled: true }],
};

describe('PolicyListView', () => {
  it('labels each row with its count of assigned detections', () => {
    const html = renderToStaticMarkup(
      <PolicyListView
        items={[ITEM, { ...ITEM, id: 'warn', name: 'Warn', usedByCount: 1 }]}
        onSelect={() => undefined}
      />,
    );

    expect(html).toContain('>3 assigned<');
    expect(html).toContain('>1 assigned<');
    expect(html).not.toContain('detection');
  });

  it('counts detections rather than assignments when the host counts unassigned ones', () => {
    const html = renderToStaticMarkup(
      <PolicyListView
        items={[ITEM, { ...ITEM, id: 'warn', name: 'Warn', usedByCount: 1 }]}
        onSelect={() => undefined}
        countsUnassigned
      />,
    );

    expect(html).toContain('>3 detections<');
    expect(html).toContain('>1 detection<');
    expect(html).not.toContain('assigned');
  });
});

describe('PolicyDetailView', () => {
  it('heads the detection list as the detections the policy is assigned to', () => {
    const html = renderToStaticMarkup(<PolicyDetailView policy={DETAIL} />);

    expect(html).toContain('>Assigned to<');
    expect(html).toContain('>Secrets<');
    expect(html).not.toContain('Applied by');
  });

  it('counts one rule in the singular and several in the plural', () => {
    const html = renderToStaticMarkup(
      <PolicyDetailView
        policy={{
          ...DETAIL,
          usedBy: [
            { id: 'secrets', name: 'Secrets', ruleCount: 4, enabled: true },
            { id: 'pii', name: 'PII', ruleCount: 1, enabled: true },
          ],
        }}
      />,
    );

    expect(html).toContain('>4 rules<');
    expect(html).toContain('>1 rule<');
  });

  it('says no detection is assigned the policy when none is', () => {
    const html = renderToStaticMarkup(<PolicyDetailView policy={{ ...DETAIL, usedBy: [] }} />);

    expect(html).toContain('>No detections are assigned this policy yet.<');
  });

  it('speaks of the detections using the policy when the host counts unassigned ones', () => {
    const html = renderToStaticMarkup(<PolicyDetailView policy={DETAIL} countsUnassigned />);
    const empty = renderToStaticMarkup(
      <PolicyDetailView policy={{ ...DETAIL, usedBy: [] }} countsUnassigned />,
    );

    expect(html).toContain('>Applied by<');
    expect(html).toContain('>Secrets<');
    expect(empty).toContain('>No detections use this policy yet.<');
    for (const markup of [html, empty]) expect(markup).not.toContain('assigned');
  });
});
