import { describe, expect, it } from 'vitest';

import { SubscriptionPlan } from '../src/zod/meta.ts';

describe('SubscriptionPlan', () => {
  it('accepts the Grok workplace plans', () => {
    expect(SubscriptionPlan.parse('grok_business')).toBe('grok_business');
    expect(SubscriptionPlan.parse('grok_enterprise')).toBe('grok_enterprise');
    expect(SubscriptionPlan.safeParse('supergrok').success).toBe(false);
  });
});
