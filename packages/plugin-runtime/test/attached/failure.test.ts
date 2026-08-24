import { RemoteRequestError } from '@akasecurity/remote';
import { describe, expect, it } from 'vitest';

import { classifyFailure } from '../../src/attached/failure.ts';

describe('classifyFailure', () => {
  describe('the two verdicts that name a remediation', () => {
    it('reads a 401 off the REAL client error type as `unauthorized`', () => {
      // Against the real type, not a stand-in: this is the seam that used to be
      // a regex over the error's message, and a contract test is the only kind
      // that fails when the client stops carrying a status.
      expect(classifyFailure(new RemoteRequestError(401))).toBe('unauthorized');
    });

    it('reads a 403 as `forbidden`, which is a DIFFERENT remediation', () => {
      // The whole reason these are not one member: a 401 is fixed by
      // re-attaching, and a 403 is not — the credential is already accepted, so
      // minting another one produces an identical refusal.
      expect(classifyFailure(new RemoteRequestError(403))).toBe('forbidden');
    });
  });

  describe('everything else is `unreachable`', () => {
    it.each([
      ['a 500 — answered, but not a verdict about this credential', new RemoteRequestError(500)],
      ['a 404', new RemoteRequestError(404)],
      ['a 429', new RemoteRequestError(429)],
      ['a transport failure, which carries no status at all', new Error('ECONNREFUSED')],
      ['the timeout withTimeout raises', new Error('attached gateway request timed out')],
    ])('%s', (_label, err) => {
      expect(classifyFailure(err)).toBe('unreachable');
    });

    it('is TOTAL — no input reaches a caller as a throw', () => {
      // Both callers are fail-open paths inside a catch. A classifier that
      // threw on an odd input would turn a swallowed backend failure into an
      // unswallowed one, which is the fail-open contract inverted.
      for (const value of [null, undefined, 'a string', 42, [], {}, Symbol('s')]) {
        expect(classifyFailure(value)).toBe('unreachable');
      }
    });
  });

  describe('the status is read STRUCTURALLY, and only when it is a status', () => {
    it('accepts a plain object carrying the field — never `instanceof`', () => {
      // This package is bundled into the plugin while @akasecurity/client is a
      // workspace dependency. A prototype identity that survives one bundler
      // configuration is not something to hang a security-visible verdict on,
      // so the check is on the shape (same contract as the backend's own
      // `errorStatus`).
      expect(classifyFailure({ status: 403 })).toBe('forbidden');
      expect(classifyFailure(Object.assign(new Error('nope'), { status: 401 }))).toBe(
        'unauthorized',
      );
    });

    it('ignores a status that is not one', () => {
      // The value can come from a body the backend did not author — a proxy, a
      // captive portal, a hand-edited fixture. A `status` field that is not an
      // HTTP status is not evidence of anything, and reading it as one would
      // let a third party choose the remediation a user is shown.
      for (const status of ['403', 403.5, NaN, Infinity, 0, 99, 600, null, { code: 403 }]) {
        expect(classifyFailure({ status })).toBe('unreachable');
      }
    });

    it('does not parse the message — text that mentions 403 is not a 403', () => {
      expect(classifyFailure(new Error('server said 403 forbidden'))).toBe('unreachable');
      expect(classifyFailure('401 Unauthorized')).toBe('unreachable');
    });
  });
});
