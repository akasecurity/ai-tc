// The `MatchedExchange` the bridge would hand an adapter's `parseStream`.
//
// Resolved through the bridge's OWN matcher rather than assembled by hand, so
// a test drives the adapter with the endpoint the product would really pass —
// including, for an adapter serving several routes, the right one of them. A
// hand-built literal would agree with the product only until one of them moved.
import { compileEndpoints, matchCompiled } from '../../src/bridge.ts';
import type { MatchedExchange, ProviderAdapter } from '../../src/providers/types.ts';

// Used only for an adapter that declares no endpoint at all. It is NOT a
// stand-in for a real route: with nothing declared there is no endpoint the
// product could pass either, so this says "some conversation route" and no
// more. `.invalid` is reserved by RFC 2606 and resolves nowhere.
const UNDECLARED: MatchedExchange['endpoint'] = {
  host: 'undeclared.invalid',
  path: /^\//,
  kind: 'conversation',
};

export function matchedExchangeFor(
  adapter: ProviderAdapter,
  url = 'https://undeclared.invalid/turn',
): MatchedExchange {
  const matched = matchCompiled(compileEndpoints(adapter), url);
  return { url, endpoint: matched?.source ?? UNDECLARED };
}
