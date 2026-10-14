/**
 * The worker lookup when this module's own location is not a hierarchical URL.
 *
 * A module served as a `data:` URL, or by a loader under an opaque scheme, has
 * an `import.meta.url` that a relative path cannot be resolved against:
 * `new URL('./scan-worker.js', base)` throws `Invalid URL`. That is a location
 * with no worker beside it, so the scanner must answer `unavailable` like any
 * other missing worker, not reject.
 *
 * The literal `new URL('./scan-worker.js', import.meta.url)` has to stay spelled
 * against `import.meta.url` for static tracers to follow it (see
 * worker-url-literal.test.ts), so the resolver takes no base parameter to pass a
 * `data:` URL through. Instead this file swaps the global `URL` for one that
 * resolves that one relative path against a `data:` base, which is exactly what
 * the call sees when the module itself was loaded from one. Its own file, so the
 * module-level lookup cache it fills starts empty and is shared with nothing.
 */
import type { Rule } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createIsolatedScanner } from '../src/isolated-scan.ts';
import { countWorkerStarts } from './helpers/worker-starts.ts';

const OPAQUE_BASE = 'data:text/javascript,export{}';

const RealURL = globalThis.URL;

class OpaqueBaseURL extends RealURL {
  constructor(input: string | URL, base?: string | URL) {
    super(input, input === './scan-worker.js' ? OPAQUE_BASE : base);
  }
}

const BENIGN: Rule = {
  specVersion: 1,
  id: 'pulled/benign',
  name: 'pulled/benign',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: 'AKIA[A-Z0-9]{16}', flags: 'g' },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the worker lookup from a module with an opaque URL', () => {
  it('cannot resolve the sibling path at all', () => {
    // The premise: without it, the cases below would pass on a lookup that
    // simply found nothing.
    expect(() => new RealURL('./scan-worker.js', OPAQUE_BASE)).toThrow(TypeError);
  });

  it('answers unavailable, every time, and starts no thread', async () => {
    vi.stubGlobal('URL', OpaqueBaseURL);
    const starts = countWorkerStarts();
    const scanner = createIsolatedScanner(
      { verified: [], unverified: [BENIGN] },
      { onWorkerStart: starts.onWorkerStart },
    );
    try {
      for (const outcome of [
        await scanner.scan('anything'),
        await scanner.probe(BENIGN),
        await scanner.scan('anything'),
      ]) {
        expect(outcome.status).toBe('unavailable');
        if (outcome.status !== 'unavailable') continue;
        expect(outcome.reason).toContain('the scan worker script was not found');
      }
      expect(starts.count()).toBe(0);
    } finally {
      await scanner.close();
    }
  });
});
