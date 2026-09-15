import type { WebSourceTool } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import {
  WebCaptureCardView,
  type WebCaptureSiteRow,
} from '../../src/security/WebCaptureCardView.tsx';

function site(over: Partial<WebCaptureSiteRow> = {}): WebCaptureSiteRow {
  return {
    tool: 'chatgpt',
    stateLabel: 'active',
    headline: '3 turns observed',
    drift: false,
    ...over,
  };
}

function render(props: Partial<Parameters<typeof WebCaptureCardView>[0]> = {}) {
  return renderToStaticMarkup(
    <WebCaptureCardView
      sites={[site()]}
      ruleId="web-capture-drift"
      severity="medium"
      isLoading={false}
      error={null}
      {...props}
    />,
  );
}

describe('WebCaptureCardView', () => {
  it('renders one row per site with its state word and headline', () => {
    const html = render({
      sites: [
        site({ tool: 'chatgpt', stateLabel: 'active', headline: '3 turns observed' }),
        site({ tool: 'claude-ai', stateLabel: 'idle', headline: 'watching; no turn observed' }),
      ],
    });

    expect(html).toContain('ChatGPT');
    expect(html).toContain('active');
    expect(html).toContain('3 turns observed');
    expect(html).toContain('Claude.ai');
    expect(html).toContain('idle');
    expect(html).toContain('watching; no turn observed');
  });

  it('a drifting row cites the rule and prints the fix', () => {
    const html = render({
      sites: [
        site({
          tool: 'claude-ai',
          stateLabel: 'blind',
          headline: 'messages were sent that the network never saw',
          drift: true,
          remediation: 'reload the tab',
        }),
      ],
      ruleId: 'web-capture-drift',
      severity: 'medium',
    });

    expect(html).toContain('web-capture-drift');
    expect(html).toContain('data-severity="medium"');
    expect(html).toContain('reload the tab');
  });

  it('a non-drifting row cites nothing, even carrying a remediation string on the row', () => {
    // The remediation is present on the row so this proves the card gates on
    // `drift`, not on the prop merely being absent.
    //
    // The severity is asserted through `data-severity`, never by matching the
    // bare word: `variant="medium"` expands to a class list carrying
    // `sev-medium`, so a document-wide `not.toContain('medium')` is a claim
    // about Tailwind tokens rather than about this card — it reddens on any
    // unrelated utility that contains the substring (which is what pushed the
    // site label off `font-medium`) and it would stay green on a real severity
    // leak spelled any other way.
    const html = render({
      sites: [
        site({
          tool: 'chatgpt',
          stateLabel: 'active',
          headline: 'fine',
          drift: false,
          remediation: 'should never render',
        }),
      ],
      ruleId: 'web-capture-drift',
      severity: 'medium',
    });

    expect(html).not.toContain('web-capture-drift');
    expect(html).not.toContain('data-severity');
    expect(html).not.toContain('should never render');
    // The positive control: the row itself rendered, so the three absences
    // above are the gate's doing rather than an empty document's.
    expect(html).toContain('ChatGPT');
  });

  it('renders an error state and no site rows', () => {
    const html = render({ error: 'boom', sites: [site()] });
    expect(html).toContain('boom');
    expect(html).not.toContain('ChatGPT');
  });

  it('renders skeletons while loading and no site rows', () => {
    const html = render({ isLoading: true, sites: [site()] });
    expect(html).not.toContain('ChatGPT');
  });

  it('gives every registered site a distinct, non-empty label', () => {
    // Every site rendered together, one row each: KNOWN_LABELS is what this
    // test independently expects the component's table to produce. A member
    // dropped from the component's own `Record<WebSourceTool, string>` table
    // renders that row's label as empty, which the assertions below catch —
    // that is the compile-time annotation's runtime counterpart.
    const tools: WebSourceTool[] = ['chatgpt', 'claude-ai'];
    const html = render({ sites: tools.map((tool) => site({ tool })) });

    const KNOWN_LABELS: Record<WebSourceTool, string> = {
      chatgpt: 'ChatGPT',
      'claude-ai': 'Claude.ai',
    };
    const labels = tools.map((tool) => KNOWN_LABELS[tool]);
    for (const [i, label] of labels.entries()) {
      expect(label.length).toBeGreaterThan(0);
      expect(label).not.toBe(tools[i]);
      expect(html).toContain(label);
    }
    expect(new Set(labels).size).toBe(tools.length);
  });
});
