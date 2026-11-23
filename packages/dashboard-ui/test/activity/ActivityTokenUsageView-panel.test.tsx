// @vitest-environment jsdom
import type { TokenUsageSummary } from '@akasecurity/schema';
import { API_EQUIVALENT_LOWER_BOUND_NOTE, SPEND_LOWER_BOUND_NOTE } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ActivityTokenUsageView } from '../../src/activity/ActivityTokenUsageView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const SUMMARY: TokenUsageSummary = {
  models: [
    {
      provider: 'anthropic',
      model: 'claude-haiku-4-5',
      inputTokens: 1000,
      outputTokens: 0,
      cacheTokens: 0,
      totalTokens: 1000,
      estimatedCostUsd: 0.5,
      channel: 'api_key',
      costBasis: 'estimated',
    },
    {
      provider: 'anthropic',
      model: 'claude-haiku-4-5',
      inputTokens: 5000,
      outputTokens: 0,
      cacheTokens: 0,
      totalTokens: 5000,
      estimatedCostUsd: 2.5,
      channel: 'subscription',
      costBasis: 'api_equivalent',
    },
    {
      provider: 'anthropic',
      model: 'unpriced-model',
      inputTokens: 10,
      outputTokens: 0,
      cacheTokens: 0,
      totalTokens: 10,
      estimatedCostUsd: null,
      channel: 'subscription',
      costBasis: null,
    },
  ],
  sessionCount: 2,
  totalTokens: 6010,
  estimatedCostUsd: 0.5,
  costIsPartial: false,
  apiEquivalentUsd: 2.5,
  apiEquivalentIsPartial: true,
};

let mounted: MountedRoot;

beforeEach(() => {
  mounted = mountRoot();
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

function openPanel(): HTMLElement[][] {
  renderRoot(
    mounted.root,
    <ActivityTokenUsageView summary={SUMMARY} isLoading={false} error={null} />,
  );
  const chip = document.querySelector<HTMLButtonElement>('button[aria-label^="Token usage"]');
  expect(chip).not.toBeNull();
  act(() => {
    chip?.click();
  });
  return [...document.querySelectorAll('tbody tr')].map((row) => [
    ...row.querySelectorAll<HTMLElement>('td'),
  ]);
}

describe('ActivityTokenUsageView panel', () => {
  it('shows how each row was paid for, one row per channel of a model', () => {
    const rows = openPanel();
    expect(rows.map((cells) => [cells[1]?.textContent, cells[2]?.textContent])).toEqual([
      ['claude-haiku-4-5', 'API key'],
      ['claude-haiku-4-5', 'Subscription'],
      ['unpriced-model', 'Subscription'],
    ]);
  });

  it('labels a subscription cost as API-equivalent and an unpriced one as unknown', () => {
    const costs = openPanel().map((cells) => cells.at(-1)?.textContent);
    expect(costs).toEqual(['$0.50', '$2.50 API-eq.', '—']);
    expect(document.body.textContent).toContain(API_EQUIVALENT_LOWER_BOUND_NOTE);
    expect(document.body.textContent).not.toContain(SPEND_LOWER_BOUND_NOTE);
  });
});
