import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import {
  advisoryId,
  advisoryIdsFromReport,
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
  readPnpmConfigSources,
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

  // Both channels answer the same way about an empty `auditConfig`. It
  // suppresses nothing either way, so this is about the rule being statable:
  // the YAML half cannot tell empty from non-empty without a parser, so if the
  // manifest half allowed it the two would disagree and "refuses on presence"
  // would be true of only one of them.
  it('refuses an empty auditConfig in either channel, and names no keys for it', () => {
    const manifest = findAuditConfigMutes({ manifest: manifestWith({ auditConfig: {} }) });
    expect(manifest).toEqual(['package.json "pnpm.auditConfig"']);
    expect(manifest[0]).not.toContain('()');
    expect(findAuditConfigMutes({ workspaceYaml: 'auditConfig:\n' })).toHaveLength(1);
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

// The daily report's new-vs-seen comparison. Both sides of it are RENDERED
// markdown — this run's report, and the tracking issue a previous run posted —
// so one reader answers both, and a shape it cannot see is an advisory that is
// silently never mentioned again.
describe('advisoryId', () => {
  // Built by DELETING the key rather than by setting it to undefined: the
  // workspace runs `exactOptionalPropertyTypes`, under which an explicit
  // undefined is not the same as an absent property — and absent is the shape
  // the registry really produces.
  const withoutGhsa = (overrides: Partial<AuditAdvisory> = {}): AuditAdvisory => {
    const full = advisory(overrides);
    delete full.github_advisory_id;
    return full;
  };

  it('prefers the GHSA id the registry supplied', () => {
    expect(advisoryId(advisory())).toBe('GHSA-aaaa-bbbb-cccc');
  });

  // The case the whole extractor exists for: `buildReport` falls back to the
  // numeric registry id, so such an advisory renders perfectly and used to
  // match nothing.
  it('falls back to the numeric registry id when there is no GHSA id', () => {
    expect(advisoryId(withoutGhsa({ id: 1090893 }))).toBe('1090893');
  });

  it('is the empty string when the advisory carries neither', () => {
    const neither = withoutGhsa();
    delete neither.id;
    expect(advisoryId(neither)).toBe('');
  });
});

describe('advisoryIdsFromReport', () => {
  const reportFor = (...advisories: AuditAdvisory[]): string =>
    buildReport({
      mode: 'workspace',
      counts: { high: advisories.length },
      blocking: advisories,
      waived: [],
      stale: [],
      nonBlocking: [],
    });

  it('reads back every id a report it was handed rendered', () => {
    expect(advisoryIdsFromReport(reportFor(advisory()))).toEqual(['GHSA-aaaa-bbbb-cccc']);
  });

  // The regression. Driven through buildReport rather than a hand-written
  // table row, so the reader is proven against what the gate really emits —
  // a literal here would go on passing if the report's link form changed.
  it('reads a numeric-id advisory, which the GHSA-only match dropped', () => {
    const numeric = advisory({ id: 1090893, url: 'https://npmjs.com/advisories/1090893' });
    delete numeric.github_advisory_id;
    expect(advisoryIdsFromReport(reportFor(numeric))).toEqual(['1090893']);
  });

  it('dedupes and sorts, so the two sides can be compared directly', () => {
    const second = advisory({
      github_advisory_id: 'GHSA-dddd-eeee-ffff',
      module_name: 'right-pad',
    });
    const doubled = `${reportFor(advisory(), second)}\n${reportFor(advisory())}`;
    expect(advisoryIdsFromReport(doubled)).toEqual(['GHSA-aaaa-bbbb-cccc', 'GHSA-dddd-eeee-ffff']);
  });

  // The other direction, and the reason the match is anchored on the link form
  // rather than on a bare `GHSA-…` anywhere in the text. A maintainer writing
  // "GHSA-9999-9999-9999 is not us" on the tracking issue would otherwise put
  // that id in the SEEN set, and the next run would post nothing about it.
  it('ignores an id mentioned in prose rather than rendered as an advisory row', () => {
    expect(
      advisoryIdsFromReport('GHSA-9999-9999-9999 is unrelated, and 1090893 is a version number.'),
    ).toEqual([]);
  });

  it('finds nothing in a report that carried no advisories', () => {
    expect(advisoryIdsFromReport(reportFor())).toEqual([]);
  });
});

// The mute guard driven against REAL FILES on disk, not canned strings.
//
// This is what the original defect calls for. `assertNothingMuted` was correct
// in isolation and unreachable in practice: it read pnpm's `muted` field, which
// pnpm leaves empty for a muted advisory, so a canned payload carrying
// `muted: [{...}]` tested a shape pnpm never produces. The replacement reads the
// two files pnpm takes the setting from — so the reader itself has to be driven
// over real files, or the fix repeats the mistake one module along.
describe('readPnpmConfigSources (real files)', () => {
  const dirs: string[] = [];
  const scratch = (): string => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-audit-config-'));
    dirs.push(dir);
    return dir;
  };
  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it('reads a real manifest carrying a real mute, and the gate refuses it', () => {
    const dir = scratch();
    const manifest = join(dir, 'package.json');
    const yaml = join(dir, 'pnpm-workspace.yaml');
    writeFileSync(
      manifest,
      JSON.stringify({
        name: 'x',
        pnpm: { auditConfig: { ignoreGhsas: ['GHSA-6cpc-mj5c-m9rq'] } },
      }),
    );
    writeFileSync(yaml, "packages:\n  - 'packages/*'\n");

    const sources = readPnpmConfigSources(manifest, yaml);
    // The key is named, so a reader is sent to the exact line rather than to
    // the file. The YAML half cannot do this without a parser, which is why the
    // two channels answer differently in detail while agreeing on the refusal.
    expect(findAuditConfigMutes(sources)).toEqual([
      'package.json "pnpm.auditConfig" (ignoreGhsas)',
    ]);
    expect(() => {
      assertNoAuditConfigMutes(sources);
    }).toThrow(WaiverConfigError);
  });

  // The YAML channel, which no payload could ever reveal either.
  it('reads a real pnpm-workspace.yaml carrying a real mute', () => {
    const dir = scratch();
    const manifest = join(dir, 'package.json');
    const yaml = join(dir, 'pnpm-workspace.yaml');
    writeFileSync(manifest, JSON.stringify({ name: 'x' }));
    writeFileSync(
      yaml,
      "packages:\n  - 'packages/*'\n\nauditConfig:\n  ignoreCves:\n    - CVE-1\n",
    );
    expect(findAuditConfigMutes(readPnpmConfigSources(manifest, yaml))).toEqual([
      'pnpm-workspace.yaml "auditConfig"',
    ]);
  });

  // THE discriminating case, over real files: a payload that reports nothing
  // muted — byte-for-byte what a clean run produces — together with a manifest
  // that mutes. Delete the file read and this case, alone, goes green wrongly.
  it('refuses a muting manifest even though the payload looks perfectly clean', () => {
    const dir = scratch();
    const manifest = join(dir, 'package.json');
    writeFileSync(manifest, JSON.stringify({ pnpm: { auditConfig: { ignoreGhsas: ['G'] } } }));

    const clean = payload({ muted: [], advisories: {} });
    // The payload half sees nothing to complain about, exactly as it did in
    // production while both audits reported green.
    expect(() => {
      assertNothingMuted(clean);
    }).not.toThrow();
    expect(() => {
      assertNoAuditConfigMutes(readPnpmConfigSources(manifest, join(dir, 'nope.yaml')));
    }).toThrow(WaiverConfigError);
  });

  it('treats a genuinely absent file as nothing to look at', () => {
    const dir = scratch();
    const sources = readPnpmConfigSources(
      join(dir, 'package.json'),
      join(dir, 'pnpm-workspace.yaml'),
    );
    expect(sources).toEqual({});
    expect(() => {
      assertNoAuditConfigMutes(sources);
    }).not.toThrow();
  });

  // Absent means ENOENT and nothing else. A file that exists but cannot be read
  // must not report as "no config here" — that reaches the exact outcome this
  // check exists to prevent, by the one door a reader is most likely to leave open.
  it('refuses a file that exists but cannot be read', (ctx) => {
    const dir = scratch();
    const manifest = join(dir, 'package.json');
    writeFileSync(manifest, JSON.stringify({ pnpm: { auditConfig: {} } }));
    chmodSync(manifest, 0o000);
    // Root ignores the mode, and Windows does not implement it — where the
    // platform decides instead of the test, skip rather than return: a return
    // reports as a pass for an assertion that never ran.
    let readable = true;
    try {
      readFileSync(manifest, 'utf8');
    } catch {
      readable = false;
    }
    if (readable) {
      chmodSync(manifest, 0o600);
      ctx.skip('this platform or user ignores the unreadable mode');
      return;
    }
    try {
      expect(() => readPnpmConfigSources(manifest, join(dir, 'nope.yaml'))).toThrow(
        /could not be read/,
      );
    } finally {
      chmodSync(manifest, 0o600);
    }
  });
});

// The doc-guard the finding asks for. Both documents state what the gate does
// with a pnpm-native mute, and the previous version of that claim was FALSE
// against the pinned pnpm — it said the gate refuses "while anything is muted",
// which reads the payload field pnpm leaves empty. Nothing guarded it, which is
// why it went false unnoticed. This drives the claim against the real function.
describe('the mute claim in CLAUDE.md and CONTRIBUTING.md', () => {
  const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
  const read = (name: string): string => readFileSync(join(REPO_ROOT, name), 'utf8');

  // Both docs must name BOTH channels. A claim naming only `pnpm.auditConfig`
  // sends a reader to check one file and call the tree clean.
  it.each(['CLAUDE.md', 'CONTRIBUTING.md'])(
    '%s names both files pnpm reads the setting from',
    (doc) => {
      const text = read(doc);
      expect(text).toContain('pnpm.auditConfig');
      expect(text).toContain('pnpm-workspace.yaml');
    },
  );

  // And neither may claim the refusal comes from pnpm's own `muted` field.
  // That is the false statement this replaced, and it is the one a reader would
  // reasonably write again.
  it.each(['CLAUDE.md', 'CONTRIBUTING.md'])(
    '%s does not claim the payload reveals a mute',
    (doc) => {
      const text = read(doc);
      expect(text).not.toMatch(/refuses to run while anything is muted/);
    },
  );

  // The behaviour the docs describe, driven against the real gate: refusal on
  // the PRESENCE of the key, in either channel, whether or not it carries
  // entries. Both docs say so; this is what makes that true rather than stated.
  it('refuses on the presence of the key in either channel, empty or not', () => {
    for (const sources of [
      { manifest: JSON.stringify({ pnpm: { auditConfig: {} } }) },
      { manifest: JSON.stringify({ pnpm: { auditConfig: { ignoreGhsas: ['G'] } } }) },
      { workspaceYaml: 'auditConfig:\n' },
      { workspaceYaml: 'auditConfig:\n  ignoreCves:\n    - CVE-1\n' },
    ]) {
      expect(() => {
        assertNoAuditConfigMutes(sources);
      }).toThrow(WaiverConfigError);
    }
  });

  // The exit code both docs name. A guard on the wording alone would pass while
  // the gate exited 1 (retryable-looking) or 2 (transient) instead.
  it('is documented as exit 3, the deterministic-configuration code', () => {
    expect(read('CONTRIBUTING.md')).toMatch(/exit 3/);
    expect(read('CLAUDE.md')).toMatch(/exit 3/);
  });
});

// Regression from the xhigh review of this change. Only ONE side of the dedup
// comparison is text buildReport wrote; the other is the tracking issue's body
// and comments, which is arbitrary human markdown.
describe('advisoryIdsFromReport against the human side of the comparison', () => {
  it('ignores an ordinary numbered link in a comment', () => {
    // `[2](url)` in prose used to put `2` into the seen set, which would then
    // silence a later advisory whose registry id is 2 — the exact silent drop
    // this function exists to fix, reached from the other direction.
    expect(
      advisoryIdsFromReport('Tracked, see [2](https://example.com/notes) for context.'),
    ).toEqual([]);
  });

  // The positive control: both row shapes buildReport really emits still read,
  // or the case above is satisfied by a reader that finds nothing anywhere.
  it('still reads both row shapes the report emits', () => {
    expect(
      advisoryIdsFromReport('| left-pad | high | [GHSA-aaaa-bbbb-cccc](https://x) | t | v |'),
    ).toEqual(['GHSA-aaaa-bbbb-cccc']);
    expect(advisoryIdsFromReport('| pkg | [1090893](https://x) | 2026-01-01 | why |')).toEqual([
      '1090893',
    ]);
  });

  // The closing pipe is a lookahead so one cell's separator is not eaten as the
  // next cell's opener. No row emitted today has two link cells, which is why a
  // later edit that adds one would lose an id with nothing going red.
  it('reads both ids when two link cells are adjacent', () => {
    expect(advisoryIdsFromReport('| a | [GHSA-a-b-c](u) | [4](v) | x |')).toEqual([
      '4',
      'GHSA-a-b-c',
    ]);
  });
});
