import type { DetectionRule, RuleFixture } from '@akasecurity/schema';
import { createElement, isValidElement, type ReactElement, type ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { CATEGORY_LABEL } from '../../src/detections/meta.ts';
import {
  MatcherModal,
  type RuleFixtures,
  RuleInspectorBody,
} from '../../src/detections/RuleInspector.tsx';

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
//
// The one thing that reasoning leaves unproven is the seam between the two, which
// is the only path a real caller takes. That is covered without a renderer at the
// bottom of this file, by reading the element tree the modal returns.

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

type BodyProps = Parameters<typeof RuleInspectorBody>[0];

function render(props: BodyProps): string {
  return renderToStaticMarkup(createElement(RuleInspectorBody, props));
}

/** The rule's own fixtures, keyed to it — the shape the section renders. */
function forRule(cases: readonly RuleFixture[], ruleId = rule().id): RuleFixtures {
  return { ruleId, cases };
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

  // Two extensions where neither is a prefix of the other. With '.py' and '.pyi'
  // the first assertion cannot fail on its own — it matches inside the rendered
  // '.pyi' — so a renderer dropping all but the last extension stays green.
  it('shows the file scoping that decides where a rule runs at all', () => {
    const html = render({ rule: rule({ appliesTo: { extensions: ['.py', '.rb'] } }) });

    expect(html).toContain('Only in files');
    expect(html).toContain('.py');
    expect(html).toContain('.rb');
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
      rule: rule({ postValidators: [{ name: 'entropy', config: { threshold: 3.5 } }] }),
    });

    expect(html).toContain('entropy');
  });

  // Naming it is not enough. `entropy` alone reads as the engine's defaults (20
  // chars, 3.5 bits), and a rule carrying a config is precisely one that does not
  // use them — a short-secret rule tuned to 8/3.0 would render identically to one
  // running at the defaults, and someone tuning the noisy rule would be wrong on
  // both numbers.
  it('shows the config a tuned post-validator carries, not just its name', () => {
    const html = render({
      rule: rule({ postValidators: [{ name: 'entropy', config: { minLength: 8, threshold: 3 } }] }),
    });

    expect(html).toContain('minLength 8');
    expect(html).toContain('threshold 3');
  });

  // A config value may be any JSON, and an object flattened onto a chip is noise.
  // The chip must still name the validator.
  it('keeps a non-primitive config value off the chip', () => {
    const html = render({
      rule: rule({ postValidators: [{ name: 'entropy', config: { nested: { a: 1 } } }] }),
    });

    expect(html).toContain('entropy');
    expect(html).not.toContain('object Object');
    expect(html).not.toContain('nested');
  });

  // ['entropy', { name: 'entropy', config }] is schema-valid and is the natural
  // way to say "the default one plus a tuned one". Keyed on the name alone the
  // two children collide; both must survive to the output.
  it('renders both arms when one validator name appears twice', () => {
    const html = render({
      rule: rule({ postValidators: ['entropy', { name: 'entropy', config: { minLength: 8 } }] }),
    });

    expect(html.match(/entropy/g)?.length).toBe(2);
    expect(html).toContain('minLength 8');
  });

  it('spells out a corroboration gate, including its window', () => {
    const html = render({
      rule: rule({
        requiresNearby: { labels: ['api_key'], categories: ['secret'], windowChars: 160 },
      }),
    });

    expect(html).toContain('160');
    expect(html).toContain('api_key');
    expect(html).toContain('Secret');
  });

  // The gate is satisfied by ONE criterion. A bare separator between a category
  // and a label reads equally as "needs both", which over-describes the gate —
  // the mirror image of the under-description this section exists to fix.
  it('says the corroboration criteria are alternatives', () => {
    const html = render({
      rule: rule({
        requiresNearby: { labels: ['api_key'], categories: ['secret'], windowChars: 160 },
      }),
    });

    expect(html).toContain('Any of:');
  });

  // The rule's own category renders through CATEGORY_LABEL, so a raw enum in the
  // criteria prints "Code context" and "category code_context" in one dialog.
  it('labels a corroboration category the way it labels the rule’s own', () => {
    const html = render({
      rule: rule({
        category: 'code_context',
        requiresNearby: { categories: ['code_context'], windowChars: 160 },
      }),
    });

    expect(html).toContain(`category ${CATEGORY_LABEL.code_context}`);
    expect(html).not.toContain('category code_context');
  });

  // confidenceBoost does not decide whether the rule fires, but it moves the
  // confidence stamped on every corroborated finding — one of the numbers a
  // reader of this panel is trying to account for.
  it('reports the confidence a corroborated match gains', () => {
    const html = render({
      rule: rule({
        requiresNearby: { labels: ['api_key'], windowChars: 160, confidenceBoost: 0.2 },
      }),
    });

    expect(html).toContain('0.2');
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
      // The dynamic one: rendered unconditionally it would read "Needs
      // corroboration within undefined chars" above an empty criteria line, on
      // every rule that sets no requiresNearby.
      'Needs corroboration',
      'Catches values like',
      'Test cases',
    ]) {
      expect(html).not.toContain(heading);
    }
  });

  // The corroboration heading is the dynamic one, and the all-empty rule above
  // cannot reach it: GatingDetail returns null before rendering anything when a
  // rule sets none of the three gates. A rule carrying one OTHER gate is what
  // proves the heading is guarded rather than merely unreached — rendered
  // unconditionally it reads "Needs corroboration within undefined chars" above
  // an empty criteria line.
  it('omits the corroboration heading on a gated rule that needs no corroboration', () => {
    const html = render({ rule: rule({ appliesTo: { extensions: ['.py'] } }) });

    expect(html).toContain('Only in files');
    expect(html).not.toContain('Needs corroboration');
    expect(html).not.toContain('undefined');
  });

  // MATCHER_META is keyed on the matcher union, so a missing entry is a compile
  // error for anything this repo builds — but this component is exported from the
  // package barrel, and a host that builds a rule from an API response without
  // putting it through the DetectionRule parse can hand it a matcher kind this
  // build has no entry for. Degrading beats taking the page down on `mm.icon`.
  it('renders nothing for a matcher kind it has no metadata for', () => {
    const foreign = { type: 'semantic', pattern: 'x' } as unknown as DetectionRule['matcher'];

    expect(render({ rule: rule({ matcher: foreign }) })).toBe('');
  });

  describe('author-supplied volume', () => {
    // Examples and fixtures arrive from whoever published the pack, and neither
    // the arrays nor the number of 50,000-character fixture bodies is bounded by
    // the schema. The escaping half of this surface is handled; this is the
    // volume half.
    it('bounds how many examples it renders, and says what it left out', () => {
      const examples = Array.from({ length: 100 }, (_, i) => `example-${String(i)}`);
      const html = render({ rule: rule({ examples }) });

      expect(html).toContain('example-19');
      expect(html).not.toContain('example-20');
      expect(html).toContain('+80 more not shown');
    });

    it('bounds how many fixtures it renders, and says what it left out', () => {
      const cases = Array.from({ length: 30 }, (_, i) => ({
        label: `case-${String(i)}`,
        text: 'sk-proj-AAAA1111BBBB2222',
        shouldMatch: true,
      }));
      const html = render({ rule: rule(), fixtures: forRule(cases) });

      expect(html).toContain('case-19');
      expect(html).not.toContain('case-20');
      expect(html).toContain('+10 more not shown');
    });

    it('truncates a single oversized body rather than emitting all of it', () => {
      const long = 'A'.repeat(50_000);
      const html = render({
        rule: rule(),
        fixtures: forRule([{ label: 'big', text: long, shouldMatch: true }]),
      });

      expect(html).toContain('…');
      expect(html).not.toContain(long);
      expect(html.length).toBeLessThan(10_000);
    });
  });

  describe('fixtures', () => {
    const cases: RuleFixture[] = [
      { label: 'project key', text: 'sk-proj-AAAA1111BBBB2222', shouldMatch: true },
      { label: 'bad prefix', text: 'sb-test-key', shouldMatch: false },
    ];

    it('shows both what a rule must catch and what it must not', () => {
      const html = render({ rule: rule(), fixtures: forRule(cases) });

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
        fixtures: forRule([
          { label: 'gated out', text: 'eval(x)', shouldMatch: false, filePath: 'a.ts' },
        ]),
      });

      expect(html).toContain('a.ts');
    });

    // A fixture is an assertion about ONE rule, so a set rendered under a
    // different rule is not stale — it is false. A host fetching fixtures when a
    // rule is opened otherwise shows the previous rule's set for the duration of
    // the fetch, and permanently if two fetches resolve out of order.
    it('renders no section for fixtures belonging to another rule', () => {
      const html = render({ rule: rule(), fixtures: forRule(cases, 'secrets/aws-access-key') });

      expect(html).not.toContain('Test cases');
      expect(html).not.toContain('sk-proj-AAAA1111BBBB2222');
    });

    // Absent and empty are different claims. An app with no registry configured
    // cannot fetch fixtures at all, and "not loaded here" is true where "this
    // rule ships no tests" would be false for every bundled rule.
    it('renders no section when fixtures were not supplied', () => {
      expect(render({ rule: rule() })).not.toContain('Test cases');
      expect(render({ rule: rule(), fixtures: forRule([]) })).not.toContain('Test cases');
    });

    // Fixtures are the strings a rule exists to catch, authored by whoever
    // published the pack — so they are attacker-influenced text rendered into a
    // tenant's dashboard. React escapes children; this pins that nothing here
    // reaches for an escape hatch.
    it('escapes fixture text rather than emitting it as markup', () => {
      const html = render({
        rule: rule(),
        fixtures: forRule([
          { label: '<img src=x onerror=alert(1)>', text: '<script>x</script>', shouldMatch: true },
        ]),
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

// ---------------------------------------------------------------------------
// The modal → body seam
// ---------------------------------------------------------------------------

/**
 * The first `RuleInspectorBody` element in a returned tree.
 *
 * A component that uses no hooks is a plain function returning an element tree,
 * so the tree can be READ without a renderer or a DOM — which is what makes the
 * one path every real caller takes assertable in a package whose suite runs on
 * Node, and whose dialog renders through a portal that emits nothing.
 */
function findBody(node: ReactNode): ReactElement<BodyProps> | null {
  if (Array.isArray(node)) {
    for (const child of node as ReactNode[]) {
      const hit = findBody(child);
      if (hit) return hit;
    }
    return null;
  }
  if (!isValidElement(node)) return null;
  if (node.type === RuleInspectorBody) return node as ReactElement<BodyProps>;
  const { children } = node.props as { children?: ReactNode };
  return children === undefined ? null : findBody(children);
}

describe('MatcherModal', () => {
  // Without this, deleting `fixtures={fixtures}` from the modal keeps every
  // assertion above green while the feature disappears from both dashboards: the
  // suite renders the body directly, so the seam between the two is the one thing
  // it never exercises.
  it('hands its rule and fixtures to the body it renders', () => {
    const r = rule();
    const fixtures = forRule([{ label: 'project key', text: 'sk-proj-A', shouldMatch: true }]);

    const body = findBody(MatcherModal({ rule: r, fixtures, onClose: () => undefined }));

    // The type alongside the props, so a wrapper appearing in between fails
    // naming itself rather than reading every prop as undefined.
    expect(body?.type).toBe(RuleInspectorBody);
    expect(body?.props.rule).toBe(r);
    expect(body?.props.fixtures).toBe(fixtures);
  });

  it('renders no body at all when no rule is open', () => {
    expect(findBody(MatcherModal({ rule: null, onClose: () => undefined }))).toBeNull();
  });
});
