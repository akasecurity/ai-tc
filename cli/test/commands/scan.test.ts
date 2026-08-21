import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { maskMatch } from '@akasecurity/detections';
import type { EgressRecordResult, ProjectInventoryResult } from '@akasecurity/local-ops';
import { DB_FILENAME, MAX_EGRESS_CALL_SITES_PER_PROJECT } from '@akasecurity/persistence';
import { bundledDetections, dataDir } from '@akasecurity/plugin-sdk';
import type { Severity } from '@akasecurity/schema';
import { DEFAULT_ACTIONS, Severity as SeverityEnum } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { renderEgressLine, renderInventoryLine, runScan } from '../../src/commands/scan.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// `aka scan`'s two machine contracts — `--format json` (what another program
// parses) and `--fail-on` (what a CI gate branches on) — plus the ignore
// layering that decides which files reach them at all.
//
// Everything here drives `runScan` itself against a real temp store, because
// the fields these ACs name are the CLI's own projection: the walker one layer
// down (packages/local-ops/test/fs-scan.test.ts) proves that `gitignored`
// provenance and the pointer shield are computed, and this file proves they
// survive into the payload a consumer actually reads. Neither substitutes for
// the other — a projection that dropped a field would keep every fs-scan
// assertion green.
//
// The AKA home and the scan target are separate temp trees on purpose: a store
// living inside the tree under scan would be walked by the scan, so the file
// counts below would drift with the store's own sidecars.

// The fixtures are each a bundled rule's OWN `examples[0]`, looked up at run
// time rather than restated — so no secret-shaped literal is written into this
// public repository by hand, and a rule that is renamed or loses its example
// fails loudly here instead of quietly matching nothing.
// Indexed in ONE pass: the registry is every compiled-in pack, and the four
// constants below would otherwise walk all of it four times at import.
const BUNDLED_EXAMPLES = new Map(
  bundledDetections().flatMap((pack) =>
    pack.rules.map((rule) => [rule.id, rule.examples?.[0]] as const),
  ),
);

function bundledExample(ruleId: string): string {
  if (!BUNDLED_EXAMPLES.has(ruleId)) {
    throw new Error(`no bundled rule ${ruleId} — the fixture cannot be built`);
  }
  const example = BUNDLED_EXAMPLES.get(ruleId);
  if (example === undefined || example.length === 0) {
    throw new Error(`bundled rule ${ruleId} has no example — the fixture cannot be built`);
  }
  return example;
}

// One fixture per severity band. The band each one really produces is asserted
// as a positive control before any exit-code case reads it: without that, a
// fixture that stopped matching would make every "exits 0" assertion below pass
// for exactly the wrong reason.
const CRITICAL_TEXT = bundledExample('secrets/aws-access-key');
const HIGH_TEXT = bundledExample('code-flaws/deser-yaml-unsafe');
const MEDIUM_TEXT = bundledExample('code-flaws/crypto-weak-hash-md5');
const LOW_TEXT = bundledExample('core-code-context/internal-ip');

// The raw value the JSON must never carry a run of. It is a secret only in
// shape — it is the rule's own published example — but it is the value this
// command would be handling if it were real.
const RAW = CRITICAL_TEXT;

// A syntactically valid vault pointer. Its base32 body is exactly what a
// generic entropy rule matches, which is why every scan surface blanks pointer
// spans before the engine runs.
const POINTER = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;

// The exact top-level key set of the machine contract, and the exact per-finding
// key set. Asserted as SETS rather than with a type: a TypeScript interface
// asserts nothing at run time, and an extra field silently added to the payload
// is a contract change a consumer has to cope with just as much as a missing one.
const PAYLOAD_KEYS = ['target', 'scanned', 'findings', 'inventory', 'egress'];
const FINDING_KEYS = [
  'file',
  'gitignored',
  'ruleId',
  'category',
  'severity',
  'span',
  'maskedMatch',
  'actionTaken',
  'confidence',
];

interface ScanFinding {
  file: string;
  gitignored: boolean;
  ruleId: string;
  category: string;
  severity: Severity;
  span: { start: number; end: number };
  maskedMatch: string;
  actionTaken: string;
  confidence: number;
}

interface ScanPayload {
  target: string;
  scanned: number;
  findings: ScanFinding[];
  inventory: { name: string; url: string; fileCount: number; truncated: boolean } | null;
  egress: { destinations: number; endpoints: number; callSites: number; truncated: boolean } | null;
}

describe('renderInventoryLine', () => {
  function inv(overrides: Partial<ProjectInventoryResult> = {}): ProjectInventoryResult {
    return {
      projectId: 'p1',
      name: 'ai-tc',
      url: 'https://github.com/acme/ai-tc.git',
      fileCount: 785,
      truncated: false,
      ...overrides,
    };
  }

  it('reports the recorded file count for a full walk', () => {
    expect(renderInventoryLine(inv())).toBe('Inventory: ai-tc · 785 project file(s) recorded');
  });

  it('marks a truncated walk as partial', () => {
    expect(renderInventoryLine(inv({ fileCount: 20_000, truncated: true }))).toBe(
      'Inventory: ai-tc · 20000 project file(s) recorded (partial walk)',
    );
  });

  it('says the tree is unchanged when the walk recorded nothing', () => {
    expect(renderInventoryLine(inv({ fileCount: 0 }))).toBe(
      'Inventory: ai-tc · file tree unchanged',
    );
  });
});

describe('renderEgressLine', () => {
  function egress(overrides: Partial<EgressRecordResult> = {}): EgressRecordResult {
    return {
      project: 'widgets',
      destinations: 3,
      endpoints: 7,
      callSites: 12,
      truncated: false,
      droppedFiles: [],
      ...overrides,
    };
  }

  it('summarizes destinations, endpoints and call sites', () => {
    expect(renderEgressLine(egress())).toBe(
      'Data shares: 3 destination(s) · 7 endpoint(s) · 12 call site(s)',
    );
  });

  it('names the cap when the call-site walk was truncated', () => {
    const line = renderEgressLine(egress({ truncated: true }));
    // The product's own constant, not a \d+ wildcard and not a restated
    // literal: a regression that printed a different number would satisfy the
    // wildcard, and hand-copying the value here would go stale silently.
    expect(line).toContain(`capped at ${String(MAX_EGRESS_CALL_SITES_PER_PROJECT)} call sites`);
  });
});

describe('runScan', () => {
  let home: string;
  let root: string;
  let out: string;
  let err: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-scan-home-'));
    mkdirSync(dataDir(home), { recursive: true });
    root = mkdtempSync(join(tmpdir(), 'aka-scan-root-'));
    out = '';
    err = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    removeTrees([home, root]);
    process.exitCode = undefined;
  });

  // Every run goes through the real argv parser — the flags ARE the contract, so
  // a helper that bypassed parseArgs would pin something no user can invoke.
  async function scan(args: string[]): Promise<void> {
    out = '';
    err = '';
    process.exitCode = undefined;
    await runScan([...args, '--home', home]);
  }

  async function scanJson(target: string, extra: string[] = []): Promise<ScanPayload> {
    await scan([target, '--format', 'json', ...extra]);
    return JSON.parse(out) as ScanPayload;
  }

  function exitCode(): number {
    // An unset `process.exitCode` is how node exits 0, which is the value the
    // acceptance criteria are written in.
    return process.exitCode === undefined ? 0 : Number(process.exitCode);
  }

  function severitiesOf(payload: ScanPayload): Severity[] {
    return [...new Set(payload.findings.map((f) => f.severity))].sort(
      (a, b) => SeverityEnum.options.indexOf(a) - SeverityEnum.options.indexOf(b),
    );
  }

  function storeExists(): boolean {
    return existsSync(join(dataDir(home), DB_FILENAME));
  }

  // The nearest `.git` at or above `dir`, mirroring findGitRoot's upward walk.
  // Used to state the precondition the null-inventory case depends on.
  function gitRootAbove(dir: string): string | undefined {
    for (let at = dir; ; at = dirname(at)) {
      if (existsSync(join(at, '.git'))) return at;
      if (dirname(at) === at) return undefined;
    }
  }

  // The fixture five cases share. The variable NAME decides what the rules
  // match (see the pointer case below), so it is written once rather than
  // copied — five copies drift, and a drifting one changes what its test
  // detects without changing what it looks like.
  function writeSecretFile(name = 'app.ts'): string {
    const file = join(root, name);
    writeFileSync(file, `const key = '${RAW}';\n`);
    return file;
  }

  // The at-rest rows, read straight from the store file. `.akaignore`'s contract
  // is "no read, no event, no finding", and the middle one is invisible from the
  // payload: a walker that skipped REPORTING a file while still capturing it
  // would satisfy every JSON assertion in this file.
  function storedEventPaths(): string[] {
    const raw = new DatabaseSync(join(dataDir(home), DB_FILENAME), { readOnly: true });
    try {
      const rows = raw
        .prepare(
          `SELECT json_extract(attributes, '$.file_path') AS path
             FROM audit_events WHERE event_type = 'code_change'`,
        )
        .all() as unknown as { path: string | null }[];
      return rows.map((r) => r.path ?? '');
    } finally {
      raw.close();
    }
  }

  describe('--format json', () => {
    it('emits the documented payload, with every finding field present and no others', async () => {
      writeSecretFile();

      const payload = await scanJson(root);

      expect(Object.keys(payload).sort()).toEqual([...PAYLOAD_KEYS].sort());
      expect(payload.target).toBe(root);
      expect(payload.scanned).toBe(1);
      expect(payload.findings.length).toBeGreaterThan(0);

      const finding = payload.findings[0];
      expect(finding).toBeDefined();
      expect(Object.keys(finding ?? {}).sort()).toEqual([...FINDING_KEYS].sort());

      // The fields a consumer branches on, checked for TYPE as well as presence
      // — a null severity is still a present key.
      expect(finding?.file).toBe(join(root, 'app.ts'));
      expect(finding?.gitignored).toBe(false);
      expect(SeverityEnum.options).toContain(finding?.severity);
      expect(typeof finding?.ruleId).toBe('string');
      expect(typeof finding?.category).toBe('string');
      expect(typeof finding?.confidence).toBe('number');
      expect(typeof finding?.span.start).toBe('number');
      expect(typeof finding?.span.end).toBe('number');

      // Outside a git repo there is no project to record, so `inventory` is
      // present and null rather than absent — the key is the contract.
      //
      // That rests on an environmental precondition: findGitRoot walks UP, so a
      // TMPDIR sitting inside a checkout would yield a real identity here.
      // Asserted rather than assumed, so such a machine fails naming the cause
      // instead of accusing the projection.
      expect(gitRootAbove(root)).toBeUndefined();
      expect(payload.inventory).toBeNull();
    });

    it('emits the same five keys on a clean scan, with findings as an empty array', async () => {
      // A consumer parses one shape. A clean scan that dropped `findings`
      // entirely, or emitted null for it, breaks every `.findings.length` on the
      // other side — and the case above cannot see that, because it only ever
      // scans a file that matches.
      writeFileSync(join(root, 'clean.ts'), 'export const ok = 1;\n');

      const payload = await scanJson(root);

      expect(Object.keys(payload).sort()).toEqual([...PAYLOAD_KEYS].sort());
      expect(Array.isArray(payload.findings)).toBe(true);
      expect(payload.findings).toEqual([]);
      expect(payload.scanned).toBe(1);
    });

    it('carries the per-category default action when the store has no installed snapshot', async () => {
      writeSecretFile();

      const payload = await scanJson(root);
      const finding = payload.findings.find((f) => f.ruleId === 'secrets/aws-access-key');

      expect(finding).toBeDefined();
      expect(finding?.actionTaken).toBe(DEFAULT_ACTIONS.secret);
    });

    it('addresses the match with a span into the file as written', async () => {
      const content = `const key = '${RAW}';\n`;
      writeFileSync(join(root, 'app.ts'), content);

      const payload = await scanJson(root);
      const finding = payload.findings.find((f) => f.ruleId === 'secrets/aws-access-key');

      expect(finding).toBeDefined();
      expect(content.slice(finding?.span.start, finding?.span.end)).toBe(RAW);
    });

    it('reports the project row and file tree when the target is inside a git repo', async () => {
      // resolveRepoIdentity is pure file I/O and never spawns git, so a `.git`
      // directory carrying a config is a real repo as far as it is concerned.
      mkdirSync(join(root, '.git'));
      writeFileSync(
        join(root, '.git', 'config'),
        '[remote "origin"]\n\turl = https://github.com/acme/widgets.git\n',
      );
      writeFileSync(join(root, 'app.ts'), 'export const ok = 1;\n');

      const payload = await scanJson(root);

      expect(payload.inventory).not.toBeNull();
      expect(payload.inventory?.name).toBe('widgets');
      expect(payload.inventory?.url).toBe('https://github.com/acme/widgets.git');
      expect(typeof payload.inventory?.fileCount).toBe('number');
      expect(typeof payload.inventory?.truncated).toBe('boolean');
    });
  });

  describe('the JSON never contains a raw secret', () => {
    it('prints the masked preview and no run of the value it stands for', async () => {
      writeSecretFile();

      const payload = await scanJson(root);
      const finding = payload.findings.find((f) => f.ruleId === 'secrets/aws-access-key');

      // The positive control, on the same bytes: the payload really did carry
      // this finding, and the preview really is the product's own mask. Without
      // it an empty or finding-less payload would satisfy every absence check
      // below vacuously.
      expect(finding).toBeDefined();
      expect(finding?.maskedMatch).toBe(maskMatch(RAW));
      expect(out).toContain(maskMatch(RAW));

      expectNoEchoOf(out, RAW);
    });

    it('keeps the value out of the text summary too', async () => {
      writeSecretFile();

      await scan([root]);

      // Positive control first — the text mode really did report a finding, so
      // the absence assertion below is reading bytes that exist. The count is
      // matched as "non-zero" rather than pinned: how many rules a value trips
      // is pack content, and this case is about what the line PRINTS.
      expect(out).toContain(`Scanned 1 file(s) under ${root}`);
      expect(out).toMatch(/· [1-9]\d* finding\(s\) recorded/);
      expectNoEchoOf(out, RAW);
    });
  });

  // A pointer's body is exactly what a generic secret rule matches, and this is
  // live rather than hypothetical: with the shield removed, the COMPILED-IN
  // packs alone re-detect a pointer as a secret. So the engine never sees one —
  // shieldPointers blanks every pointer span BEFORE the scan, and the filler is
  // the SAME LENGTH by design, because a shorter or longer one would slide every
  // subsequent span off the value it addresses.
  //
  // Both halves are pinned below, and they are guarded by different things. The
  // blanking is what stops the match; `dropShieldedFindings` is the second layer,
  // for a rule whose span merely brushes a blanked region, and no bundled rule
  // does that today — removing it alone leaves these cases green. The span half
  // is what only this layer can show, since the span is what the JSON hands a
  // consumer.
  describe('vault pointers', () => {
    it('leaves every later span addressing the right bytes and reports nothing in any pointer', async () => {
      // TWO pointers, not one: the criterion is about EVERY other span, and a
      // shield that stopped after its first match would keep a single-pointer
      // case green while leaving the second pointer visible to the engine.
      //
      // The variable NAMES are load-bearing and were the difference between this
      // case working and merely looking like it did. What detects a pointer body
      // is `secrets-infra/env-key-value`, which keys on a secret-ish assignment
      // target — so with names like `a` and `b` no rule fires on either pointer,
      // an unshielded second pointer produces nothing, and the loop below is
      // satisfied by a payload the regression never touched.
      const content = `const token = '${POINTER}';\nconst secret = '${POINTER}';\nconst key = '${RAW}';\n`;
      writeFileSync(join(root, 'app.ts'), content);

      const pointerSpans: { start: number; end: number }[] = [];
      for (
        let at = content.indexOf(POINTER);
        at !== -1;
        at = content.indexOf(POINTER, at + POINTER.length)
      ) {
        pointerSpans.push({ start: at, end: at + POINTER.length });
      }
      // The fixture really does carry two — otherwise the loop below is the
      // single-pointer case wearing a longer name.
      expect(pointerSpans).toHaveLength(2);

      const payload = await scanJson(root);
      const finding = payload.findings.find((f) => f.ruleId === 'secrets/aws-access-key');

      // The secret sits after BOTH pointers, so its span is only correct against
      // the original text if each was replaced by the same number of characters.
      expect(finding).toBeDefined();
      expect(content.slice(finding?.span.start, finding?.span.end)).toBe(RAW);

      for (const f of payload.findings) {
        for (const p of pointerSpans) {
          expect(f.span.start >= p.end || f.span.end <= p.start).toBe(true);
        }
      }
    });

    it('reports nothing at all for an already-pointerized file', async () => {
      writeFileSync(join(root, 'app.ts'), `const token = '${POINTER}';\n`);

      const payload = await scanJson(root);

      expect(payload.findings).toEqual([]);
    });
  });

  describe('--fail-on', () => {
    // The whole matrix in one case per fixture: four thresholds against a file
    // whose own severity band is asserted first, so "exits 0" can never pass
    // because the fixture quietly stopped matching.
    async function exitCodesByThreshold(
      filename: string,
      text: string,
      expectedBand: Severity[],
    ): Promise<Record<Severity, number>> {
      const file = join(root, filename);
      writeFileSync(file, `${text}\n`);

      const payload = await scanJson(file);
      expect(severitiesOf(payload)).toEqual(expectedBand);

      const codes = {} as Record<Severity, number>;
      for (const threshold of SeverityEnum.options) {
        await scan([file, '--fail-on', threshold]);
        codes[threshold] = exitCode();
      }
      return codes;
    }

    it('exits 1 at every threshold for a critical finding', async () => {
      expect(await exitCodesByThreshold('critical.ts', CRITICAL_TEXT, ['critical'])).toEqual({
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
      });
    });

    it('exits 0 only above a high finding', async () => {
      expect(await exitCodesByThreshold('high.py', HIGH_TEXT, ['high'])).toEqual({
        critical: 0,
        high: 1,
        medium: 1,
        low: 1,
      });
    });

    it('exits 0 above a medium finding', async () => {
      expect(await exitCodesByThreshold('medium.py', MEDIUM_TEXT, ['medium'])).toEqual({
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
      });
    });

    it('exits 1 only at low for a low finding', async () => {
      expect(await exitCodesByThreshold('low.ts', LOW_TEXT, ['low'])).toEqual({
        critical: 0,
        high: 0,
        medium: 0,
        low: 1,
      });
    });

    it('exits 0 with no findings at all, whatever the threshold', async () => {
      const file = join(root, 'clean.ts');
      writeFileSync(file, 'export const ok = 1;\n');

      for (const threshold of SeverityEnum.options) {
        await scan([file, '--fail-on', threshold]);
        expect(exitCode()).toBe(0);
      }
    });

    // The two flags are documented separately but a CI job uses them TOGETHER —
    // parse the report, gate on the status. Nothing else here runs them in the
    // same invocation, and the failure mode is specific: anything the gate
    // printed to stdout would land inside the payload and break the parse on the
    // other side, which no single-flag case can see.
    it('still emits parseable json when the gate trips', async () => {
      const file = join(root, 'critical.ts');
      writeFileSync(file, `${CRITICAL_TEXT}\n`);

      await scan([file, '--format', 'json', '--fail-on', 'critical']);

      expect(exitCode()).toBe(1);
      // The parse is itself the guard against stray output: JSON.parse rejects
      // extra text on EITHER side of the object, so a gate that announced itself
      // fails here rather than below.
      const payload = JSON.parse(out) as ScanPayload;
      expect(Object.keys(payload).sort()).toEqual([...PAYLOAD_KEYS].sort());
      expect(payload.findings.length).toBeGreaterThan(0);
      // What the parse does NOT see is the formatting, which a consumer reading
      // the stream (rather than a parser) can depend on: pin the pretty-printed
      // 2-space form and the single trailing newline.
      expect(out).toBe(`${JSON.stringify(payload, null, 2)}\n`);
      expect(err).toBe('');
    });

    it('emits the payload and exits 0 when the gate does not trip', async () => {
      const file = join(root, 'low.ts');
      writeFileSync(file, `${LOW_TEXT}\n`);

      await scan([file, '--format', 'json', '--fail-on', 'critical']);

      expect(exitCode()).toBe(0);
      const payload = JSON.parse(out) as ScanPayload;
      expect(payload.findings.length).toBeGreaterThan(0);
    });

    it('leaves the exit code alone when the flag is absent', async () => {
      writeFileSync(join(root, 'critical.ts'), `${CRITICAL_TEXT}\n`);

      await scan([root]);

      expect(exitCode()).toBe(0);
      expect(out).toContain('finding(s) recorded');
    });
  });

  describe('invalid flags', () => {
    // The four cases above reject a bad option VALUE and return, which is the
    // path that owns its own message and exit code. A bad option NAME — the
    // likelier typo — never reaches any of that: `parseArgs` throws, so runScan
    // writes nothing, sets nothing, and the 1 comes from cli.ts's
    // `main().catch`. Pinned here because the collision case below rests on
    // every exit-1 path being separable by the stdout/stderr split, and this one
    // is the exception to that.
    //
    // The error is captured OUTSIDE its own catch: a try/catch that throws its
    // own guard error would assert against that error instead of this one.
    function throwFrom(argv: string[]): Promise<NodeJS.ErrnoException | undefined> {
      out = '';
      err = '';
      process.exitCode = undefined;
      return runScan(argv).then(
        () => undefined,
        (e: unknown) => e as NodeJS.ErrnoException,
      );
    }

    it('lets an unknown option name throw rather than reporting it', async () => {
      const error = await throwFrom([root, '--home', home, '--frmat', 'json']);

      expect(error).toBeDefined();
      expect(error?.code).toBe('ERR_PARSE_ARGS_UNKNOWN_OPTION');
      // Neither stream, and no exit code — this is what makes it the odd one out.
      expect(out).toBe('');
      expect(err).toBe('');
      expect(exitCode()).toBe(0);
      expect(storeExists()).toBe(false);
    });

    it('lets an option given no value throw rather than reading the next flag', async () => {
      // `--format` last in argv has nothing to consume. Written without the
      // shared helper on purpose: that helper appends `--home <dir>`, which
      // `--format` would swallow as its value and the case would not arise.
      const error = await throwFrom([root, '--home', home, '--format']);

      expect(error).toBeDefined();
      expect(error?.code).toBe('ERR_PARSE_ARGS_INVALID_OPTION_VALUE');
      expect(out).toBe('');
      expect(err).toBe('');
    });

    it('rejects an unknown --format, names it, and never opens the store', async () => {
      await scan([root, '--format', 'yaml']);

      expect(exitCode()).toBe(1);
      expect(err).toContain("invalid --format 'yaml'");
      expect(err).toContain('text or json');
      expect(out).toBe('');
      // Validation precedes the store, so a typo does not create one.
      expect(storeExists()).toBe(false);
    });

    it('rejects an unknown --fail-on, names the real severities, and never opens the store', async () => {
      await scan([root, '--fail-on', 'catastrophic']);

      expect(exitCode()).toBe(1);
      expect(err).toContain("invalid --fail-on 'catastrophic'");
      for (const severity of SeverityEnum.options) expect(err).toContain(severity);
      expect(out).toBe('');
      expect(storeExists()).toBe(false);
    });

    it('rejects an empty --fail-on rather than reading it as absent', async () => {
      await scan([root, '--fail-on', '']);

      expect(exitCode()).toBe(1);
      expect(err).toContain('invalid --fail-on');
    });

    it('accepts every severity the schema defines', async () => {
      writeFileSync(join(root, 'clean.ts'), 'export const ok = 1;\n');

      for (const threshold of SeverityEnum.options) {
        await scan([root, '--fail-on', threshold]);
        expect(err).toBe('');
        expect(exitCode()).toBe(0);
      }
    });
  });

  describe('a target that is not there', () => {
    it('exits 1 saying no such file or directory, and reports no scan', async () => {
      const missing = join(root, 'nope');

      await scan([missing]);

      expect(exitCode()).toBe(1);
      expect(err).toContain('no such file or directory');
      expect(err).toContain(missing);
      // Never "scanned 0 files" — an empty result would read as a clean repo.
      expect(out).toBe('');
      expect(storeExists()).toBe(false);
    });

    it('says so in json mode too, on stderr rather than as an empty payload', async () => {
      await scan([join(root, 'nope'), '--format', 'json']);

      expect(exitCode()).toBe(1);
      expect(err).toContain('no such file or directory');
      expect(out).toBe('');
    });
  });

  describe('ignore layering', () => {
    it('marks a .gitignore match as gitignored but still scans it', async () => {
      writeFileSync(join(root, '.gitignore'), 'scratch.env\n');
      writeFileSync(join(root, 'tracked.ts'), `const key = '${RAW}';\n`);
      writeFileSync(join(root, 'scratch.env'), `AWS_ACCESS_KEY_ID=${RAW}\n`);

      const payload = await scanJson(root);
      const byFile = new Map(payload.findings.map((f) => [f.file, f.gitignored]));

      // Scanned, not skipped: local scratch is exactly where real secrets hide.
      expect(byFile.get(join(root, 'scratch.env'))).toBe(true);
      // The control — an ordinary file in the same walk is marked false, so the
      // flag is a real verdict rather than a constant.
      expect(byFile.get(join(root, 'tracked.ts'))).toBe(false);
      expect(payload.scanned).toBe(3); // both files plus the .gitignore itself
    });

    it('hard-skips an .akaignore match: no read, no event, no finding', async () => {
      writeFileSync(join(root, '.akaignore'), 'skipped.ts\n');
      writeFileSync(join(root, 'kept.ts'), `const key = '${RAW}';\n`);
      writeFileSync(join(root, 'skipped.ts'), `const key = '${RAW}';\n`);

      const payload = await scanJson(root);
      const files = payload.findings.map((f) => f.file);

      // No finding. The control: the same bytes in kept.ts DO produce one, so
      // the absence is the ignore file's doing and not the rule's.
      expect(files).toContain(join(root, 'kept.ts'));
      expect(files).not.toContain(join(root, 'skipped.ts'));
      // No read — `scanned` counts files whose content was actually read.
      expect(payload.scanned).toBe(2); // kept.ts plus the .akaignore itself
      // No event. Same shape: the positive control comes first, so an empty
      // read (a query that matched nothing, a store that never opened) cannot
      // satisfy the absence check vacuously.
      const events = storedEventPaths();
      expect(events).toContain(join(root, 'kept.ts'));
      expect(events).not.toContain(join(root, 'skipped.ts'));
    });

    it('lets an .akaignore negation beat the vendored-directory and dot-directory floor', async () => {
      writeFileSync(join(root, '.akaignore'), '!build/\n!.config/\n');
      mkdirSync(join(root, 'build'));
      writeFileSync(join(root, 'build', 'gen.ts'), `const key = '${RAW}';\n`);
      mkdirSync(join(root, '.config'));
      writeFileSync(join(root, '.config', 'creds.ts'), `const key = '${RAW}';\n`);

      const payload = await scanJson(root);
      const files = payload.findings.map((f) => f.file);

      expect(files).toContain(join(root, 'build', 'gen.ts'));
      expect(files).toContain(join(root, '.config', 'creds.ts'));
    });

    it('still skips the default floor without a negation', async () => {
      // The other side of the case above: with no `!` the same two directories
      // are skipped, so the negation is doing the work rather than the floor
      // having quietly stopped applying.
      mkdirSync(join(root, 'build'));
      writeFileSync(join(root, 'build', 'gen.ts'), `const key = '${RAW}';\n`);
      mkdirSync(join(root, '.config'));
      writeFileSync(join(root, '.config', 'creds.ts'), `const key = '${RAW}';\n`);

      const payload = await scanJson(root);

      expect(payload.findings).toEqual([]);
      expect(payload.scanned).toBe(0);
    });

    it('scans a directly-named file even when .akaignore excludes it', async () => {
      writeFileSync(join(root, '.akaignore'), 'skipped.ts\n');
      const file = join(root, 'skipped.ts');
      writeFileSync(file, `const key = '${RAW}';\n`);

      // Naming the file is explicit user intent, so no ignore file is consulted.
      const named = await scanJson(file);
      expect(named.findings.map((f) => f.file)).toContain(file);

      // The control: reached through the directory walk, the same file is
      // skipped — so the bypass is what the direct target buys.
      const walked = await scanJson(root);
      expect(walked.findings.map((f) => f.file)).not.toContain(file);
    });
  });

  // Pinned as CURRENT BEHAVIOUR, not endorsed: a CI gate reading only the exit
  // status cannot tell "findings at or above the threshold" from "you typed the
  // flag wrong" or "that path does not exist". Most scanners reserve a separate
  // code (2) for usage errors. Today the only discriminator is that the two
  // error paths write to stderr and produce no stdout, while the --fail-on path
  // writes its report and stays silent on stderr. Tracked separately.
  describe('the --fail-on exit code collides with the error exit code', () => {
    it('returns 1 for findings, an invalid flag and a missing path alike', async () => {
      const file = join(root, 'critical.ts');
      writeFileSync(file, `${CRITICAL_TEXT}\n`);

      await scan([file, '--fail-on', 'critical']);
      const findings = { code: exitCode(), stderr: err, stdout: out };

      await scan([file, '--format', 'yaml']);
      const badFlag = { code: exitCode(), stderr: err, stdout: out };

      await scan([join(root, 'nope')]);
      const missing = { code: exitCode(), stderr: err, stdout: out };

      expect([findings.code, badFlag.code, missing.code]).toEqual([1, 1, 1]);

      // The one thing that does separate them today.
      expect(findings.stderr).toBe('');
      expect(findings.stdout).not.toBe('');
      expect(badFlag.stderr).not.toBe('');
      expect(badFlag.stdout).toBe('');
      expect(missing.stderr).not.toBe('');
      expect(missing.stdout).toBe('');
    });

    // The case above pins the BEHAVIOUR, and a behaviour nobody wrote down is a
    // trap rather than a contract: the only place a CI author learns that a 1
    // is ambiguous is the comment on the command that produces it. Prose beside
    // a green suite is unguarded prose, so the comment is read here — a rewrite
    // that drops the warning fails rather than passing quietly.
    it('says so where a CI author would look — the command that documents the flags', () => {
      // Derived from import.meta.url rather than hand-written: a literal
      // `file:///…` is POSIX-only.
      const source = readFileSync(
        fileURLToPath(new URL('../../src/commands/scan.ts', import.meta.url)),
        'utf8',
      );
      // Scoped to the header, above the first export — the same block that
      // documents --format and --fail-on, not a mention buried further down.
      const firstExport = source.indexOf('\nexport ');
      // Guards the SLICE, not the product: a missed anchor makes indexOf return
      // -1, and `slice(0, -1)` is very nearly the whole file — so every
      // assertion below would go on passing while silently weakening from
      // "documented in the header" to "documented anywhere".
      expect(firstExport).toBeGreaterThan(0);
      const header = source.slice(0, firstExport);
      expect(header).toContain('--fail-on');

      expect(header).toMatch(/Exit codes/i);
      // The claim itself: 1 is overloaded, and by which paths.
      expect(header).toMatch(/overloaded/i);
      expect(header).toMatch(/--format/);
      expect(header).toMatch(/does not exist|no such file/i);
      // And the discriminator, so the note is actionable rather than a shrug.
      expect(header).toMatch(/stderr/);
      expect(header).toMatch(/stdout/);

      // The COUNT and the fourth path, pinned separately — and not decoration.
      // An earlier version of this comment said "three error paths", which is
      // wrong: parseArgs throws for an unknown option name or a missing option
      // value, and cli.ts's main().catch turns that into the same 1. Every
      // assertion above passed on that wrong text, because each one only checks
      // that the comment is ABOUT exit codes. Naming the count is what makes a
      // regression to it fail here.
      expect(header).toMatch(/\bFOUR\b/);
      expect(header).not.toMatch(/\bthree error paths\b/);
      expect(header).toMatch(/parseArgs/);
      expect(header).toMatch(/main\(\)\.catch/);
    });
  });
});
