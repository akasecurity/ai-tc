import { RemoteFailureKind } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { classifyRemoteFailure, statusOf } from '../src/failure-kind.ts';
import {
  RemoteRequestError,
  RemoteRequestInvalid,
  RemoteResponseInvalid,
  RemoteRouteAbsent,
  RemoteTransportError,
} from '../src/http.ts';

// The classifier is read off `name` and `status` and nothing else, so the table
// below is deliberately half real error objects and half plain literals. The
// literals are the point: a caller may hold a copy of this package resolved
// separately from the one that threw, and then the only thing the two builds
// share is the shape. If an `instanceof` ever crept in, every row built with
// `new` would keep passing and every row built with `{}` would fail.

describe('statusOf', () => {
  it('reads the status a request error carries', () => {
    expect(statusOf(new RemoteRequestError(403))).toBe(403);
  });

  it('reads a status off a plain object with no prototype in common', () => {
    expect(statusOf({ status: 500 })).toBe(500);
  });

  it('reads the status a transport error carries when only the body was refused', () => {
    expect(statusOf(new RemoteTransportError('response too large', 401))).toBe(401);
  });

  it('is null for an error carrying no status', () => {
    expect(statusOf(new RemoteTransportError('socket hang up'))).toBeNull();
    expect(statusOf(new RemoteRouteAbsent('/v1/shares'))).toBeNull();
  });

  it('is null for anything that is not an object', () => {
    expect(statusOf(null)).toBeNull();
    expect(statusOf(undefined)).toBeNull();
    expect(statusOf('503')).toBeNull();
    expect(statusOf(503)).toBeNull();
  });

  it('refuses a status that is not an HTTP status', () => {
    // These arrive from bodies no deployment authored — a proxy, a captive
    // portal — and a number outside the range is not evidence of anything.
    expect(statusOf({ status: '403' })).toBeNull();
    expect(statusOf({ status: 42 })).toBeNull();
    expect(statusOf({ status: 600 })).toBeNull();
    expect(statusOf({ status: 403.5 })).toBeNull();
    expect(statusOf({ status: Number.NaN })).toBeNull();
  });
});

describe('classifyRemoteFailure', () => {
  const cases: [string, unknown, RemoteFailureKind][] = [
    // The classes this package throws.
    ['a 401 request error', new RemoteRequestError(401), 'unauthorized'],
    ['a 403 request error', new RemoteRequestError(403), 'forbidden'],
    ['a 404 request error', new RemoteRequestError(404), 'route-absent'],
    ['a 400 request error', new RemoteRequestError(400), 'rejected'],
    ['a 413 request error', new RemoteRequestError(413), 'rejected'],
    ['a 422 request error', new RemoteRequestError(422), 'rejected'],
    ['a 429 request error', new RemoteRequestError(429), 'unreachable'],
    ['a 500 request error', new RemoteRequestError(500), 'unreachable'],
    ['a 503 request error', new RemoteRequestError(503), 'unreachable'],
    ['an absent route', new RemoteRouteAbsent('/v1/shares'), 'route-absent'],
    [
      'a body this build refused to send',
      new RemoteRequestInvalid('/v1/shares', {}),
      'invalid-request',
    ],
    [
      'an answer this build cannot read',
      new RemoteResponseInvalid('/v1/shares', 'no body'),
      'unreachable',
    ],
    ['a transport failure', new RemoteTransportError('socket hang up'), 'unreachable'],
    ['a timeout', new RemoteTransportError('timed out after 15000ms'), 'unreachable'],
    // The same verdicts read off shapes alone.
    ['a bare route-absent shape', { name: 'RemoteRouteAbsent' }, 'route-absent'],
    ['a bare invalid-request shape', { name: 'RemoteRequestInvalid' }, 'invalid-request'],
    ['a bare 401 shape', { status: 401 }, 'unauthorized'],
    ['a bare 403 shape', { status: 403 }, 'forbidden'],
    ['a bare 404 shape', { status: 404 }, 'route-absent'],
    ['a bare 413 shape', { status: 413 }, 'rejected'],
    ['a bare 429 shape', { status: 429 }, 'unreachable'],
    ['a bare 502 shape', { status: 502 }, 'unreachable'],
    // Nothing to read.
    ['null', null, 'unreachable'],
    ['undefined', undefined, 'unreachable'],
    ['a string', 'forbidden', 'unreachable'],
    ['a number', 403, 'unreachable'],
    ['an empty object', {}, 'unreachable'],
    ['a non-numeric status', { status: 'x' }, 'unreachable'],
    ['an out-of-range status', { status: 9000 }, 'unreachable'],
  ];

  for (const [label, err, expected] of cases) {
    it(`maps ${label} to ${expected}`, () => {
      expect(classifyRemoteFailure(err)).toBe(expected);
    });
  }

  it('prefers the class over a status the same error also carries', () => {
    // A route this deployment never had is a version fact, not a refusal, and
    // it must not degrade into the generic 4xx bucket just because a 404 rode
    // along with it.
    const err = Object.assign(new RemoteRouteAbsent('/v1/shares'), { status: 404 });
    expect(classifyRemoteFailure(err)).toBe('route-absent');
    // A body never sent is a defect here, whatever status is attached to it.
    const local = Object.assign(new RemoteRequestInvalid('/v1/shares', {}), { status: 500 });
    expect(classifyRemoteFailure(local)).toBe('invalid-request');
  });

  it('answers with a member of the enum for every case above', () => {
    for (const [, err] of cases) {
      expect(RemoteFailureKind.options).toContain(classifyRemoteFailure(err));
    }
  });

  it('reaches every kind the vocabulary declares', () => {
    // Pins the classifier against the enum rather than against a hand-copied
    // list — a seventh kind added to the vocabulary with no way to produce it
    // fails here instead of shipping as dead copy.
    const produced = new Set(cases.map(([, err]) => classifyRemoteFailure(err)));
    expect([...produced].sort()).toEqual([...RemoteFailureKind.options].sort());
  });
});
