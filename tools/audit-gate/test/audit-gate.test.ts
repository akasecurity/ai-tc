import { describe, expect, it } from 'vitest';

import {
  assertNoAuditConfigMutes,
  assertNothingMuted,
  type AuditAdvisory,
  type AuditPayload,
  buildReport,
  classify,
  findAuditConfigMutes,
  mdEscape,
  normalizeNpmAudit,
  type NpmAuditPayload,
  parseAuditPayload,
  parseNpmAuditPayload,
  validateWaivers,
  type Waiver,
  WaiverConfigError,
  waiverMatches,
  waiversFor,
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

const waiver = (overrides: Record<string, unknown> = {}): Waiver => ({
  advisory: 'GHSA-aaaa-bbbb-cccc',
  scope: 'workspace',
  reason: 'no patched release reachable',
  expires: '2100-01-01',
  ...overrides,
});

const TODAY = '2026-07-29';

const npmVia = (overrides: Record<string, unknown> = {}) => ({
  source: 1104664,
  name: 'postcss',
  dependency: 'postcss',
  title: 'PostCSS: something bad',
  url: 'https://github.com/advisories/GHSA-dddd-eeee-ffff',
  severity: 'high',
  range: '<=8.5.17',
  ...overrides,
});

// The shape npm v2 emits when a pinned transitive is vulnerable: the advisory
// object sits on the vulnerable package's entry, while the depending package
// references it by bare name in its own "via".
const npmPayload = (overrides: Partial<NpmAuditPayload> = {}): NpmAuditPayload => ({
  vulnerabilities: {
    next: {
      name: 'next',
      severity: 'high',
      via: ['postcss'],
      nodes: ['node_modules/next'],
    },
    postcss: {
      name: 'postcss',
      severity: 'high',
      via: [npmVia()],
      nodes: ['node_modules/postcss'],
    },
  },
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 2, critical: 0, total: 2 } },
  ...overrides,
});

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

  it('accepts both audit scopes', () => {
    const waivers = validateWaivers({ waivers: [waiver({ scope: 'artifact' })] });
    expect(waivers[0]?.scope).toBe('artifact');
  });

  it.each([
    ['not an object root', 'nope'],
    ['missing waivers array', {}],
    ['missing advisory', { waivers: [waiver({ advisory: undefined })] }],
    ['missing scope', { waivers: [waiver({ scope: undefined })] }],
    ['unknown scope', { waivers: [waiver({ scope: 'global' })] }],
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

describe('parseNpmAuditPayload', () => {
  it('returns the payload for a completed audit', () => {
    const parsed = parseNpmAuditPayload(JSON.stringify(npmPayload()));
    expect(parsed.vulnerabilities).toHaveProperty('postcss');
  });

  it('rejects a transport error reported as JSON', () => {
    const stdout = JSON.stringify({ error: { code: 'ECONNREFUSED', summary: 'request failed' } });
    expect(() => parseNpmAuditPayload(stdout)).toThrow(/ECONNREFUSED/);
  });

  it('rejects non-JSON output', () => {
    expect(() => parseNpmAuditPayload('npm error network', 'stderr detail')).toThrow(
      /did not return JSON/,
    );
  });

  it('rejects JSON without a vulnerabilities field', () => {
    expect(() => parseNpmAuditPayload('{"ok":true}')).toThrow(/no "vulnerabilities" field/);
  });
});

describe('normalizeNpmAudit', () => {
  it('turns advisory objects into pnpm-shaped advisories and skips bare-name links', () => {
    const { advisories } = normalizeNpmAudit(npmPayload());
    const entries = Object.values(advisories);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      github_advisory_id: 'GHSA-dddd-eeee-ffff',
      module_name: 'postcss',
      severity: 'high',
      title: 'PostCSS: something bad',
      findings: [{ paths: ['node_modules/postcss'] }],
    });
  });

  it('falls back to the numeric source id when the url carries no GHSA id', () => {
    const viaWithoutGhsa = npmVia({ url: 'https://example.invalid/advisory' });
    const payload = npmPayload({
      vulnerabilities: {
        postcss: { name: 'postcss', severity: 'high', via: [viaWithoutGhsa] },
      },
    });
    const { advisories } = normalizeNpmAudit(payload);
    const entry = Object.values(advisories)[0];
    expect(entry?.github_advisory_id).toBeUndefined();
    expect(entry?.id).toBe(1104664);
  });

  it('drops the "total" from the counts so both modes report alike', () => {
    const counts = normalizeNpmAudit(npmPayload()).metadata?.vulnerabilities ?? {};
    expect(counts).not.toHaveProperty('total');
    expect(counts.high).toBe(2);
  });

  it('classifies a normalized payload with a module-pinned artifact waiver', () => {
    const artifactWaiver = waiver({
      advisory: 'GHSA-dddd-eeee-ffff',
      scope: 'artifact',
      module: 'postcss',
    });
    const result = classify(
      normalizeNpmAudit(npmPayload()),
      validateWaivers({ waivers: [artifactWaiver] }),
      TODAY,
    );
    expect(result.blocking).toHaveLength(0);
    expect(result.waived).toHaveLength(1);
    expect(result.stale).toHaveLength(0);
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

  it('fails closed when a payload reports muted advisories', () => {
    expect(() => {
      assertNothingMuted(payload({ muted: [{ id: 1 }] }));
    }).toThrow(WaiverConfigError);
    expect(() => {
      assertNothingMuted(payload({ muted: [{ id: 1 }] }));
    }).toThrow(/audit-waivers\.json/);
  });
});

// What pnpm 10.30.1 actually does with `auditConfig.ignoreGhsas` /
// `ignoreCves`: the advisory leaves `advisories`, `muted` stays EMPTY, and the
// severity counts are decremented to match. So the payload alone is
// indistinguishable from a clean tree, and assertNothingMuted — which reads
// only the payload — never fires. These cases drive the file-reading check
// that covers it. The shapes below are the two real files, not invented ones.
const MUTED_PNPM_PAYLOAD: AuditPayload = {
  advisories: {},
  muted: [],
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } },
};

const manifestWith = (pnpmSection: Record<string, unknown>): string =>
  JSON.stringify({ name: 'ai-tc', private: true, pnpm: pnpmSection });

describe('findAuditConfigMutes', () => {
  it('finds nothing when neither file configures auditConfig', () => {
    expect(
      findAuditConfigMutes({
        manifest: manifestWith({ overrides: { 'left-pad': '^1.3.0' } }),
        workspaceYaml: "packages:\n  - 'packages/*'\n\nonlyBuiltDependencies:\n  - esbuild\n",
      }),
    ).toEqual([]);
  });

  it('finds nothing when both files are absent', () => {
    expect(findAuditConfigMutes({})).toEqual([]);
  });

  it('names the manifest channel and the keys it carries', () => {
    const found = findAuditConfigMutes({
      manifest: manifestWith({ auditConfig: { ignoreGhsas: ['GHSA-aaaa-bbbb-cccc'] } }),
    });
    expect(found).toHaveLength(1);
    expect(found[0]).toContain('package.json');
    expect(found[0]).toContain('ignoreGhsas');
  });

  it('names ignoreCves too, and both keys when both are set', () => {
    expect(
      findAuditConfigMutes({
        manifest: manifestWith({ auditConfig: { ignoreCves: ['CVE-1'] } }),
      })[0],
    ).toContain('ignoreCves');
    const both = findAuditConfigMutes({
      manifest: manifestWith({ auditConfig: { ignoreGhsas: ['G'], ignoreCves: ['C'] } }),
    });
    expect(both[0]).toContain('ignoreCves, ignoreGhsas');
  });

  // The gate refuses on presence, so a key pnpm adds later needs no code change.
  it('catches an unrecognized auditConfig key', () => {
    expect(
      findAuditConfigMutes({
        manifest: manifestWith({ auditConfig: { ignoreSomethingNew: ['x'] } }),
      }),
    ).toHaveLength(1);
  });

  it('allows an auditConfig that is present but empty — it suppresses nothing', () => {
    expect(findAuditConfigMutes({ manifest: manifestWith({ auditConfig: {} }) })).toEqual([]);
  });

  // The second channel: pnpm 10 reads the same setting from the workspace file,
  // where it works identically and `pnpm config get auditConfig` reports it
  // (it does NOT report the manifest one, which is why both are read here).
  it('names the workspace-file channel', () => {
    const found = findAuditConfigMutes({
      workspaceYaml:
        "packages:\n  - 'packages/*'\n\nauditConfig:\n  ignoreGhsas:\n    - GHSA-aaaa-bbbb-cccc\n",
    });
    expect(found).toEqual(['pnpm-workspace.yaml "auditConfig"']);
  });

  it('reads the workspace key through a quoted spelling and CRLF line endings', () => {
    expect(
      findAuditConfigMutes({
        workspaceYaml: "packages:\r\n  - 'a'\r\n'auditConfig':\r\n  ignoreCves: []\r\n",
      }),
    ).toHaveLength(1);
  });

  it('ignores a commented-out or nested key of the same name', () => {
    expect(
      findAuditConfigMutes({
        workspaceYaml:
          '# auditConfig:\n#   ignoreGhsas: []\nsomethingElse:\n  auditConfig:\n    a: b\n',
      }),
    ).toEqual([]);
  });

  it('reports both channels when both are set', () => {
    expect(
      findAuditConfigMutes({
        manifest: manifestWith({ auditConfig: { ignoreCves: ['CVE-1'] } }),
        workspaceYaml: 'auditConfig:\n  ignoreGhsas: []\n',
      }),
    ).toHaveLength(2);
  });

  it('refuses an unparseable manifest rather than reading it as unmuted', () => {
    expect(() => findAuditConfigMutes({ manifest: '{"pnpm":' })).toThrow(WaiverConfigError);
  });
});

describe('assertNoAuditConfigMutes', () => {
  it('passes on the real repository shape', () => {
    expect(() => {
      assertNoAuditConfigMutes({
        manifest: manifestWith({ overrides: {} }),
        workspaceYaml: "packages:\n  - 'packages/*'\n",
      });
    }).not.toThrow();
  });

  it('fails closed and points at the file to edit', () => {
    const sources = { manifest: manifestWith({ auditConfig: { ignoreGhsas: ['GHSA-a-b-c'] } }) };
    expect(() => {
      assertNoAuditConfigMutes(sources);
    }).toThrow(WaiverConfigError);
    expect(() => {
      assertNoAuditConfigMutes(sources);
    }).toThrow(/package\.json/);
    expect(() => {
      assertNoAuditConfigMutes(sources);
    }).toThrow(/audit-waivers\.json/);
  });

  // The case that separates this check from the one it backs up. Under the
  // payload-only guard this combination passed: pnpm had already dropped the
  // advisory and reported nothing muted, so the gate saw a clean tree and
  // exited 0. Deleting the file read makes this case — and only this case —
  // go red.
  it('catches the mute that the payload guard cannot see', () => {
    expect(() => {
      assertNothingMuted(MUTED_PNPM_PAYLOAD);
    }).not.toThrow();
    expect(classify(MUTED_PNPM_PAYLOAD, [], TODAY).blocking).toEqual([]);

    expect(() => {
      assertNoAuditConfigMutes({
        manifest: manifestWith({ auditConfig: { ignoreGhsas: ['GHSA-aaaa-bbbb-cccc'] } }),
      });
    }).toThrow(WaiverConfigError);
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

describe('waiversFor', () => {
  it('selects only the waivers scoped to the running audit', () => {
    const waivers = validateWaivers({
      waivers: [waiver(), waiver({ advisory: 'GHSA-dddd-eeee-ffff', scope: 'artifact' })],
    });
    expect(waiversFor('workspace', waivers).map((w) => w.advisory)).toEqual([
      'GHSA-aaaa-bbbb-cccc',
    ]);
    expect(waiversFor('artifact', waivers).map((w) => w.advisory)).toEqual(['GHSA-dddd-eeee-ffff']);
  });

  it("keeps one audit's unmatched waiver out of the other audit's stale list", () => {
    const waivers = validateWaivers({
      waivers: [waiver(), waiver({ advisory: 'GHSA-dddd-eeee-ffff', scope: 'artifact' })],
    });
    const result = classify(payload(), waiversFor('workspace', waivers), TODAY);
    expect(result.waived).toHaveLength(1);
    expect(result.stale).toHaveLength(0);
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
      mode: 'workspace',
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
      mode: 'workspace',
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
      mode: 'workspace',
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

  it('titles and hints each mode for its own audit', () => {
    const base = { counts: { high: 1 }, waived: [], stale: [], nonBlocking: [] };
    const workspace = buildReport({ mode: 'workspace', blocking: [advisory()], ...base });
    expect(workspace).toContain('# Dependency audit — workspace');
    expect(workspace).toContain('`pnpm audit` over the workspace lockfile');
    expect(workspace).toContain('raising its floor via `pnpm.overrides`');

    const artifact = buildReport({ mode: 'artifact', blocking: [advisory()], ...base });
    expect(artifact).toContain('# Dependency audit — shipped artifact');
    expect(artifact).toContain("end-user resolution of the published CLI's runtime dependencies");
    expect(artifact).toContain('raising the affected range in cli/package.json');
  });
});
