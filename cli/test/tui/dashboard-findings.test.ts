import type { FindingView, TokenUsageSummary } from '@akasecurity/schema';
import { renderToString } from 'ink';
import { createElement } from 'react';
import { describe, expect, it } from 'vitest';

import { Dashboard } from '../../src/tui/Dashboard.tsx';
import type { FindingStatus, HealthReport } from '../../src/tui/report.ts';

const STATUS: FindingStatus = {
  score: 90,
  unreviewed: { critical: 0, high: 0, medium: 0, low: 0 },
  openFindings: 0,
};

function finding(overrides: Partial<FindingView>): FindingView {
  return {
    id: 'f-1',
    eventId: 'e-1',
    ruleId: 'secrets/stripe-live-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'sk_l****9x',
    actionTaken: 'block',
    confidence: 0.9,
    occurredAt: '2026-01-01T10:00:00.000Z',
    sourceTool: 'claude-code',
    kind: 'code_change',
    ...overrides,
  };
}

function renderFindings(findings: FindingView[]): string {
  return renderToString(
    createElement(Dashboard, {
      home: '/tmp/aka-home',
      report: {} as HealthReport,
      status: STATUS,
      findings,
      recommendations: [],
      tokenUsage: {} as TokenUsageSummary,
      initialView: 'findings',
    }),
    { columns: 200 },
  );
}

describe('aka tui — the Findings view', () => {
  it('shows the variable a secret is assigned to beside the masked value', () => {
    const out = renderFindings([finding({ variableName: 'STRIPE_KEY' })]);
    expect(out).toContain('STRIPE_KEY = sk_l****9x');
  });

  it('shows the masked value alone when no variable is recorded', () => {
    const out = renderFindings([finding({})]);
    expect(out).toContain('sk_l****9x');
    expect(out).not.toContain(' = sk_l****9x');
  });

  it('shortens a long name to fit the column and keeps the masked value whole', () => {
    const out = renderFindings([finding({ variableName: 'A_VERY_LONG_PAYMENTS_SECRET_NAME' })]);
    expect(out).toMatch(/A_VERY_LONG_P\S*… = sk_l\*\*\*\*9x/);
    expect(out).not.toContain('A_VERY_LONG_PAYMENTS_SECRET_NAME');
  });
});
