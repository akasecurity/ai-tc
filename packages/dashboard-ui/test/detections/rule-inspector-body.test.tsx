import type { DetectionRule, RuleFixture } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { RuleInspectorBody } from '../../src/detections/MatcherModal.tsx';

// The inspector used to show a rule's MATCHER and nothing else, which describes a
// rule that fires far more often than the real one: `postValidators` is its
// false-positive guard, `appliesTo` scopes it to a file type, and
// `requiresNearby` demands corroboration. Half the bundled catalog carries at
// least one of the three.
//
// Asserted against `RuleInspectorBody` rather than `MatcherModal`, deliberately.
// The modal renders through a Radix portal, which produces NO markup under
// `renderToStaticMarkup` — verified, not assumed — so every assertion here would
// pass against an empty string and this file would report green while rendering
// nothing. That is also why the body is a separate export.

function rule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: 'secrets/openai-api-key',
    name: 'OpenAI API key',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'regex', pattern: 'sk-[A-Za-z0-9]{20,}', flags: 'g' },
    ...overrides,
  };
}

function render(props: Parameters<typeof RuleInspectorBody>[0]): string {
  return renderToStaticMarkup(createElement(RuleInspectorBody, props));
}

describe('RuleInspectorBody', () => {
  // The control. Without it every absence assertion below is satisfied by a
  // component that renders nothing at all — which is exactly the failure mode
  // that put this suite on the body instead of the modal.
  it('renders the matcher a rule always has', () => {
    const html = render({ rule: rule() });

    expect(html).toContain('sk-[A-Za-z0-9]{20,}');
    expect(html.length).toBeGreaterThan(0);
  });

  it('shows the file scoping that decides where a rule runs at all', () => {
    const html = render({ rule: rule({ appliesTo: { extensions: ['.py', '.pyi'] } }) });

    expect(html).toContain('Only in files');
    expect(html).toContain('.py');
    expect(html).toContain('.pyi');
  });

  it('shows the false-positive guards a match still has to clear', () => {
    const html = render({ rule: rule({ postValidators: ['entropy'] }) });

    expect(html).toContain('Must also pass');
    expect(html).toContain('entropy');
  });

  // PostValidatorRef is a union: a bare name, or { name, config } for per-rule
  // tuning. Both spell the same name, and a renderer reading only the string arm
  // would print nothing for the object one — an absent guard, which reads exactly
  // like a rule that has none.
  it('names a post-validator given in its object form', () => {
    const html = render({
      rule: rule({ postValidators: [{ name: 'entropy', config: { min: 3.5 } }] }),
    });

    expect(html).toContain('entropy');
  });

  it('spells out a corroboration gate, including its window', () => {
    const html = render({
      rule: rule({
        requiresNearby: { labels: ['api_key'], categories: ['secret'], windowChars: 160 },
      }),
    });

    expect(html).toContain('160');
    expect(html).toContain('api_key');
    expect(html).toContain('secret');
  });

  // Every one of the 101 bundled rules ships examples, and they were projected
  // away by the API until DetectionRule was widened. This is the cheapest honest
  // answer to "what does this rule catch".
  it('shows the examples the rule author shipped', () => {
    const html = render({ rule: rule({ examples: ['sk-abcdefghij0123456789'] }) });

    expect(html).toContain('Catches values like');
    expect(html).toContain('sk-abcdefghij0123456789');
  });

  it('renders a rule that sets none of the optional fields without empty headings', () => {
    const html = render({ rule: rule() });

    for (const heading of [
      'Only in files',
      'Must also pass',
      'Catches values like',
      'Test cases',
    ]) {
      expect(html).not.toContain(heading);
    }
  });

  describe('fixtures', () => {
    const fixtures: RuleFixture[] = [
      { label: 'project key', text: 'sk-proj-AAAA1111BBBB2222', shouldMatch: true },
      { label: 'bad prefix', text: 'sb-test-key', shouldMatch: false },
    ];

    it('shows both what a rule must catch and what it must not', () => {
      const html = render({ rule: rule(), fixtures });

      expect(html).toContain('Test cases (2)');
      expect(html).toContain('project key');
      expect(html).toContain('sk-proj-AAAA1111BBBB2222');
      // The negative half is the interesting one: it is how an author records
      // that a near-miss was considered and deliberately excluded.
      expect(html).toContain('bad prefix');
      expect(html).toContain('sb-test-key');
      expect(html).toContain('does not match');
    });

    it('shows a fixture filePath, which is what makes appliesTo assertable', () => {
      const html = render({
        rule: rule({ appliesTo: { extensions: ['.py'] } }),
        fixtures: [{ label: 'gated out', text: 'eval(x)', shouldMatch: false, filePath: 'a.ts' }],
      });

      expect(html).toContain('a.ts');
    });

    // Absent and empty are different claims. An app with no registry configured
    // cannot fetch fixtures at all, and "not loaded here" is true where "this
    // rule ships no tests" would be false for every bundled rule.
    it('renders no section when fixtures were not supplied', () => {
      expect(render({ rule: rule() })).not.toContain('Test cases');
      expect(render({ rule: rule(), fixtures: [] })).not.toContain('Test cases');
    });

    // Fixtures are the strings a rule exists to catch, authored by whoever
    // published the pack — so they are attacker-influenced text rendered into a
    // tenant's dashboard. React escapes children; this pins that nothing here
    // reaches for an escape hatch.
    it('escapes fixture text rather than emitting it as markup', () => {
      const html = render({
        rule: rule(),
        fixtures: [
          { label: '<img src=x onerror=alert(1)>', text: '<script>x</script>', shouldMatch: true },
        ],
      });

      // The property is that no TAG is produced — not that the payload's words
      // are absent. `onerror=` survives as inert text inside a span, and asserting
      // its absence tests the fixture I happened to write rather than the
      // escaping: any payload spelled without that substring would pass it while
      // an unescaped renderer went right on emitting markup.
      expect(html).not.toContain('<script>');
      expect(html).not.toContain('<img');
      expect(html).toContain('&lt;script&gt;');
      expect(html).toContain('&lt;img');
    });
  });
});
