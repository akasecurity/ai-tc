import { describe, expect, it } from 'vitest';

import {
  HOUR_MS,
  MINUTE_MS,
  ONCE_BACKSTOP_MS,
  parseDuration,
  resolveScopeFlags,
  scopeFromAnswer,
} from './exception-scope.ts';

const NOW = Date.parse('2026-07-03T12:00:00.000Z');

describe('parseDuration', () => {
  it('parses minutes and hours', () => {
    expect(parseDuration('30m')).toBe(30 * MINUTE_MS);
    expect(parseDuration('1h')).toBe(HOUR_MS);
    expect(parseDuration('24h')).toBe(24 * HOUR_MS);
    expect(parseDuration(' 45m ')).toBe(45 * MINUTE_MS);
  });

  it('rejects malformed and zero durations', () => {
    for (const bad of ['', '1d', '90s', 'h', '0m', '-5m', '1.5h', '1 h']) {
      expect(() => parseDuration(bad)).toThrow(/invalid duration/);
    }
  });

  it('rejects anything over the 24h cap, pointing at --permanent', () => {
    expect(() => parseDuration('25h')).toThrow(/24h maximum/);
    expect(() => parseDuration('1441m')).toThrow(/24h maximum/);
  });
});

describe('resolveScopeFlags', () => {
  it('returns null when no scope flag is given (scope is never defaulted)', () => {
    expect(resolveScopeFlags({}, NOW)).toBeNull();
  });

  it('rejects more than one scope flag', () => {
    expect(() => resolveScopeFlags({ once: true, permanent: true }, NOW)).toThrow(
      /exactly ONE scope/,
    );
    expect(() => resolveScopeFlags({ once: true, for: '1h' }, NOW)).toThrow(/exactly ONE scope/);
  });

  it('--once maps to a single use with the 30-minute backstop expiry', () => {
    expect(resolveScopeFlags({ once: true }, NOW)).toEqual({
      scope: 'once',
      expiresAt: new Date(NOW + ONCE_BACKSTOP_MS).toISOString(),
      maxUses: 1,
    });
  });

  it('--for maps to temporary with an expiry and no use budget', () => {
    expect(resolveScopeFlags({ for: '2h' }, NOW)).toEqual({
      scope: 'temporary',
      expiresAt: new Date(NOW + 2 * HOUR_MS).toISOString(),
      maxUses: null,
    });
  });

  it('--permanent maps to no expiry and no budget', () => {
    expect(resolveScopeFlags({ permanent: true }, NOW)).toEqual({
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
    });
  });

  it('propagates the duration cap', () => {
    expect(() => resolveScopeFlags({ for: '48h' }, NOW)).toThrow(/24h maximum/);
  });
});

describe('scopeFromAnswer', () => {
  it('accepts once / permanent / a duration', () => {
    expect(scopeFromAnswer('once', NOW).scope).toBe('once');
    expect(scopeFromAnswer(' PERMANENT ', NOW).scope).toBe('permanent');
    expect(scopeFromAnswer('1h', NOW)).toEqual({
      scope: 'temporary',
      expiresAt: new Date(NOW + HOUR_MS).toISOString(),
      maxUses: null,
    });
  });

  it('rejects anything else with the duration parser message', () => {
    expect(() => scopeFromAnswer('forever', NOW)).toThrow(/invalid duration/);
  });
});
