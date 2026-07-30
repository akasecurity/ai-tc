import { describe, expect, it } from 'vitest';

import {
  assertNothingMuted,
  type AuditAdvisory,
  type AuditPayload,
  buildReport,
  classify,
  mdEscape,
  parseAuditPayload,
  validateWaivers,
  WaiverConfigError,
  waiverMatches,
} from '../src/lib.ts';

const advisory = (overrides: Partial<AuditAdvisory> = {}): AuditAdvisory => ({
  id: 1000001,
  github_advisory_id: 'GHSA-aaaa-bbbb-cccc',
  cves: ['CVE-2026-11111'],
  module_name: 'left-pad',
  severity: 'high',
  title: 'left-pad: something bad',
  url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  findings: [{ version: '1.0.0', paths: ['. > left-pad'] }],
  ...overrides,
});

const payload = (overrides: Partial<AuditPayload> = {}): AuditPayload => ({
  advisories: { '1000001': advisory() },
  muted: [],
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 } },
  ...overrides,
});

const waiver = (overrides: Record<string, unknown> = {}) => ({
  advisory: 'GHSA-aaaa-bbbb-cccc',
  reason: 'no patched release reachable',
  expires: '2100-01-01',
  ...overrides,
});

const TODAY = '2026-07-29';

describe('validateWaivers', () => {
  it('accepts a well-formed file and returns the waivers', () => {
    expect(validateWaivers({ waivers: [waiver()] })).toHaveLength(1);
  });

  it('accepts optional module and class fields', () => {
    const waivers = validateWaivers({
      waivers: [waiver({ module: 'left-pad', class: 'false-positive' })],
    });
    expect(waivers[0]?.module).toBe('left-pad');
    expect(waivers[0]?.class).toBe('false-positive');
  });

  it.each([
    ['not an object root', 'nope'],
    ['missing waivers array', {}],
    ['missing advisory', { waivers: [waiver({ advisory: undefined })] }],
    ['empty reason', { waivers: [waiver({ reason: ' ' })] }],
    ['missing expires', { waivers: [waiver({ expires: undefined })] }],
    ['non-ISO expires', { waivers: [waiver({ expires: 'someday' })] }],
    ['impossible expires date', { waivers: [waiver({ expires: '2026-13-99' })] }],
    ['empty module', { waivers: [waiver({ module: '' })] }],
    ['non-string class', { waivers: [waiver({ class: 7 })] }],
  ])('rejects %s with WaiverConfigError', (_name, raw) => {
    expect(() => validateWaivers(raw)).toThrow(WaiverConfigError);
  });
});

describe('parseAuditPayload', () => {
  it('returns the payload for a completed audit', () => {
    expect(parseAuditPayload(JSON.stringify(payload())).advisories).toHaveProperty('1000001');
  });

  it('rejects a transport error reported as JSON', () => {
    const stdout = JSON.stringify({ error: { code: 'ECONNREFUSED', message: 'request failed' } });
    expect(() => parseAuditPayload(stdout)).toThrow(/ECONNREFUSED/);
  });

  it('rejects non-JSON output', () => {
    expect(() => parseAuditPayload('ERR! socket hang up', 'stderr detail')).toThrow(
      /did not return JSON/,
    );
  });

  it('rejects JSON without an advisories field', () => {
    expect(() => parseAuditPayload('{"ok":true}')).toThrow(/no "advisories" field/);
  });
});

describe('assertNothingMuted', () => {
  it('passes when nothing is muted', () => {
    expect(() => {
      assertNothingMuted(payload());
    }).not.toThrow();
    expect(() => {
      assertNothingMuted({ advisories: {} });
    }).not.toThrow();
  });

  it('fails closed when pnpm.auditConfig mutes an advisory', () => {
    expect(() => {
      assertNothingMuted(payload({ muted: [{ id: 1 }] }));
    }).toThrow(WaiverConfigError);
    expect(() => {
      assertNothingMuted(payload({ muted: [{ id: 1 }] }));
    }).toThrow(/audit-waivers\.json/);
  });
});

describe('waiverMatches', () => {
  it('matches on GHSA id case-insensitively', () => {
    expect(waiverMatches(waiver({ advisory: 'ghsa-AAAA-bbbb-CCCC' }), advisory())).toBe(true);
  });

  it('matches on a CVE id', () => {
    expect(waiverMatches(waiver({ advisory: 'cve-2026-11111' }), advisory())).toBe(true);
  });

  it('does not match a different advisory', () => {
    expect(waiverMatches(waiver({ advisory: 'GHSA-zzzz-zzzz-zzzz' }), advisory())).toBe(false);
  });

  it('narrows by module when the waiver names one', () => {
    expect(waiverMatches(waiver({ module: 'left-pad' }), advisory())).toBe(true);
    expect(waiverMatches(waiver({ module: 'right-pad' }), advisory())).toBe(false);
  });
});

describe('classify', () => {
  it('blocks an unwaived high advisory', () => {
    const result = classify(payload(), [], TODAY);
    expect(result.blocking).toHaveLength(1);
    expect(result.waived).toHaveLength(0);
  });

  it('waives a matched high advisory and reports nothing stale', () => {
    const result = classify(payload(), [waiver()], TODAY);
    expect(result.blocking).toHaveLength(0);
    expect(result.waived).toHaveLength(1);
    expect(result.stale).toHaveLength(0);
  });

  it('treats expires as inclusive: a waiver lapses the day after its date', () => {
    const onTheDay = classify(payload(), [waiver({ expires: TODAY })], TODAY);
    expect(onTheDay.blocking).toHaveLength(0);

    const dayAfter = classify(payload(), [waiver({ expires: '2026-07-28' })], TODAY);
    expect(dayAfter.blocking).toHaveLength(1);
    expect(dayAfter.stale).toEqual([expect.objectContaining({ why: 'expired 2026-07-28' })]);
  });

  it('flags an active waiver matching nothing as stale', () => {
    const result = classify(payload(), [waiver({ advisory: 'GHSA-zzzz-zzzz-zzzz' })], TODAY);
    expect(result.stale).toEqual([
      expect.objectContaining({ why: 'matches no current advisory — likely fixed' }),
    ]);
  });

  it('routes sub-high severities below the gate regardless of waivers', () => {
    const low = payload({ advisories: { '1': advisory({ severity: 'low' }) } });
    const result = classify(low, [], TODAY);
    expect(result.blocking).toHaveLength(0);
    expect(result.nonBlocking).toHaveLength(1);
  });

  it('a module-mismatched waiver does not suppress and is reported stale', () => {
    const result = classify(payload(), [waiver({ module: 'right-pad' })], TODAY);
    expect(result.blocking).toHaveLength(1);
    expect(result.stale).toHaveLength(1);
  });
});

describe('mdEscape and buildReport', () => {
  it('escapes pipes, backticks, and newlines', () => {
    expect(mdEscape('a|b`c\nd')).toBe('a\\|b\\`c d');
  });

  it('renders every section and neutralizes registry-supplied markup', () => {
    const hostile = advisory({ title: 'bad | `rm -rf` title' });
    const report = buildReport({
      counts: { high: 2, low: 1 },
      blocking: [hostile],
      waived: [{ advisory: advisory(), waiver: waiver() }],
      stale: [{ waiver: waiver({ advisory: 'GHSA-old1-old1-old1' }), why: 'expired 2026-01-01' }],
      nonBlocking: [advisory({ severity: 'low' })],
    });
    expect(report).toContain('## Blocking advisories (1)');
    expect(report).toContain('## Waived (1)');
    expect(report).toContain('## Stale waivers (1)');
    expect(report).toContain('## Below the gate (1, non-blocking)');
    expect(report).toContain('2 high, 1 low');
    expect(report).toContain('bad \\| \\`rm -rf\\` title');
  });

  it('lists up to three dependency paths and counts the remainder', () => {
    const manyPaths = advisory({
      findings: [
        { paths: ['. > a > x', '. > b > x'] },
        { paths: ['cli > c > x', 'web-ui > d > x'] },
      ],
    });
    const report = buildReport({
      counts: { high: 1 },
      blocking: [manyPaths],
      waived: [],
      stale: [],
      nonBlocking: [],
    });
    expect(report).toContain('. > a > x<br>. > b > x<br>cli > c > x<br>+1 more');
  });

  it('reports a clean audit without advisory sections', () => {
    const report = buildReport({
      counts: {},
      blocking: [],
      waived: [],
      stale: [],
      nonBlocking: [],
    });
    expect(report).toContain('found: no advisories');
    expect(report).toContain('No blocking advisories.');
    expect(report).not.toContain('## Waived');
  });
});
