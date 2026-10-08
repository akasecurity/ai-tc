import type { PolicyDetail, PolicyListItem } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PolicyDetailView, PolicyListView } from '../../src/policies/PoliciesView.tsx';

// Static-render coverage for the Policies list and detail copy. A detection with
// no policy of its own follows its category's policy, so the counts on this page
// are of detections EXPLICITLY assigned a policy, and the copy says so.

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
});
