import type { ResolvedEgressHit } from '@akasecurity/schema';

// One resolved hit with recognized-provider defaults, for every suite in this
// package that needs a type-complete hit and cares about a field or two. Kept
// here so the two suites that used to carry their own copy cannot drift apart
// on what a "default" hit looks like.
export function resolvedHit(over: Partial<ResolvedEgressHit> = {}): ResolvedEgressHit {
  return {
    host: 'api.stripe.com',
    kind: 'provider',
    name: 'Stripe',
    category: 'payments',
    trust: 'recognized',
    network: null,
    method: 'POST',
    transport: 'https',
    url: 'https://api.stripe.com/v1/charges',
    template: false,
    dataClass: 'customer',
    site: {
      file: 'src/billing/charge.ts',
      line: 42,
      snippet: 'const client = new Stripe(process.env.STRIPE_SECRET_KEY);',
      dynamic: false,
      vendored: false,
    },
    ...over,
  };
}
