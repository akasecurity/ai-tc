import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { maskMatch } from '@akasecurity/detections';
import type {
  EgressRecordResult,
  ProjectInventoryResult,
  SharesForwardConnection,
  SharesForwardOutcome,
  SharesForwardSendResult,
} from '@akasecurity/local-ops';
import { FORWARD_FAILURE_LINES } from '@akasecurity/local-ops';
import {
  applyOnboarding,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  DB_FILENAME,
  MAX_EGRESS_CALL_SITES_PER_PROJECT,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { bundledDetections, dataDir } from '@akasecurity/plugin-sdk';
import type { EgressIngestRequest, Severity } from '@akasecurity/schema';
import {
  DEFAULT_ACTIONS,
  EgressIngestRequest as EgressIngestRequestSchema,
  RemoteFailureKind,
  Severity as SeverityEnum,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { ScanDeps } from '../../src/commands/scan.ts';
import {
  renderEgressLine,
  renderForwardLine,
  renderInventoryLine,
  runScan,
} from '../../src/commands/scan.ts';
import { startLoopbackServer } from '../helpers/loopback.ts';
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
const PAYLOAD_KEYS = ['target', 'scanned', 'findings', 'inventory', 'egress', 'forward'];
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
  forward: SharesForwardOutcome | null;
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
      // The resolved input rides back with the totals. This line renders none
      // of it, so the smallest well-formed one keeps the fixture honest about
      // the shape without pretending the renderer reads it.
      input: {
        projectKey: 'git:https://github.com/acme/widgets.git',
        project: 'widgets',
        projectId: null,
        reconcile: { mode: 'walk', walkedPrefix: '' },
        hits: [],
      },
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
  async function scan(args: string[], deps: ScanDeps = {}): Promise<void> {
    out = '';
    err = '';
    process.exitCode = undefined;
    await runScan([...args, '--home', home], deps);
  }

  async function scanJson(
    target: string,
    extra: string[] = [],
    deps: ScanDeps = {},
  ): Promise<ScanPayload> {
    await scan([target, '--format', 'json', ...extra], deps);
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

  describe('a protected target is refused, not reported as a clean scan', () => {
    // The walker's refusal has to reach a surface, or it is worse than no
    // exclusion at all: `aka scan --home <dir> <dir>` used to print
    // `Scanned 0 file(s) … 0 finding(s)` and exit 0 — a successful report of a
    // directory it never opened. `scan()` appends `--home home`, so naming
    // `home` as the target is exactly that invocation.
    //
    // A file the walk WOULD have yielded is seeded first, so an empty result
    // cannot be read as an empty directory.
    beforeEach(() => {
      writeFileSync(join(home, 'notes.txt'), 'hello\n');
    });

    it('names the refusal on stderr and exits non-zero', async () => {
      await scan([home]);
      expect(exitCode()).toBe(1);
      expect(err).toContain('aka scan:');
      expect(err).toContain(home);
      // Nothing on stdout: the summary line IS the false report.
      expect(out).toBe('');
    });

    it('emits no payload in --format json either', async () => {
      // A machine consumer parses stdout, so a zero-file payload here is the
      // same false negative in a form something else branches on.
      await scan([home, '--format', 'json']);
      expect(exitCode()).toBe(1);
      expect(out).toBe('');
    });
  });

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

  // What `aka scan` does about the register it just wrote, on a machine that is
  // attached to a deployment.
  //
  // The transport is INJECTED in every case but two, and that is not only for
  // speed: it is the only way to reach each refusal the deployment can answer
  // with, and each of those has its own remediation to render. The two
  // exceptions drive the real client against a real loopback server, because
  // the claims that matter most here — no source text in the body, a digested
  // project key, the credential in a header and nowhere else — are claims about
  // the bytes that left the process, and a fake sender is handed a value rather
  // than a request.
  //
  // Every case runs against the temp `--home` this file already sets up, so an
  // attachment on the machine running the suite decides nothing. The fake
  // sender is the only sender those cases install; there is no second one for a
  // stray real send to go out through.
  describe('forwarding', () => {
    const ENDPOINT = 'https://aka.acme.test';
    const LABEL = 'Acme Prod';
    // High-entropy and not credential-shaped, so expectNoEchoOf's window cannot
    // collide with ordinary output text (see the Testing conventions).
    const TEST_KEY = 'm4rk8wq2zv7nt3hc6yb9pl5sd1xg0fj';

    interface Sent {
      connection: SharesForwardConnection;
      request: EgressIngestRequest;
    }

    // Both halves of an attachment, written through the real writers: the
    // settings descriptor that names a deployment, and a credential file minted
    // for that same deployment. `apiKey: null` writes only the first half,
    // which is the shape a machine is in after a hand-edited settings.json or a
    // credential someone deleted.
    function attachHome(
      options: { endpoint?: string; label?: string; apiKey?: string | null } = {},
    ): void {
      const endpoint = options.endpoint ?? ENDPOINT;
      applyOnboarding(
        {
          runMode: 'attached',
          controlPlane: {
            endpoint,
            attachedAt: '2026-09-01T10:00:00.000Z',
            ...(options.label === undefined ? {} : { label: options.label }),
          },
        },
        home,
        // No managed overlay: an administrator's file on the machine running
        // this suite must not decide what these cases see.
        null,
      );
      const apiKey = options.apiKey === undefined ? TEST_KEY : options.apiKey;
      if (apiKey === null) return;
      writeControlPlaneCredential(settingsDir(home), { specVersion: 1, endpoint, apiKey });
    }

    // Records what it was handed, so a case can assert both what crossed and
    // that nothing did.
    function recorder(answer: SharesForwardSendResult | (() => never)) {
      const sent: Sent[] = [];
      return {
        sent,
        send: (connection: SharesForwardConnection, request: EgressIngestRequest) => {
          sent.push({ connection, request });
          if (typeof answer === 'function') return answer();
          return Promise.resolve(answer);
        },
      };
    }

    // One outbound call site, so the register has something in it. A bare URL
    // constant is the smallest thing the extractor records, and it matches no
    // bundled rule — which the --fail-on case below depends on.
    function writeCallSite(): void {
      writeFileSync(
        join(root, 'client.ts'),
        "export const CHARGES = 'https://api.stripe.com/v1/charges';\n",
      );
    }

    // The forward's own line, told apart from the local-write line above it by
    // its verb rather than by position — both start `Data shares:`.
    function forwardLine(): string | null {
      return out.split('\n').find((line) => /^Data shares: (?:not )?forwarded/.test(line)) ?? null;
    }

    it('sends nothing and reports nothing on a machine attached to no deployment', async () => {
      writeCallSite();
      const transport = recorder({ ok: true });

      await scan([root], { send: transport.send });

      expect(transport.sent).toEqual([]);
      // The whole point of the null outcome: a standalone install's output is
      // what it was before this command could forward anything at all.
      expect(forwardLine()).toBeNull();
      // And the local write still happened, so the silence is about the forward
      // rather than about the pass having been skipped.
      expect(out).toMatch(/^Data shares: \d+ destination/m);
    });

    it('carries `forward` as a sixth JSON key, null when there is no deployment', async () => {
      writeCallSite();
      const transport = recorder({ ok: true });

      const payload = await scanJson(root, [], { send: transport.send });

      expect(Object.keys(payload).sort()).toEqual([...PAYLOAD_KEYS].sort());
      expect(payload.forward).toBeNull();
      expect(transport.sent).toEqual([]);
      // The other keys are untouched by the addition.
      expect(payload.target).toBe(root);
      expect(payload.egress).not.toBeNull();
    });

    it('forwards the register it just recorded and says where it went', async () => {
      writeCallSite();
      attachHome({ label: LABEL });
      const transport = recorder({ ok: true });

      await scan([root], { send: transport.send });

      const sent = transport.sent[0];
      expect(sent).toBeDefined();
      const request = sent?.request;
      // A register with nothing in it would satisfy every projection assertion
      // below vacuously.
      expect(request?.hits.length).toBeGreaterThan(0);

      // The LABEL, not the URL: what is printed is the deployment's display
      // name when an administrator gave it one.
      expect(forwardLine()).toBe(
        `Data shares: forwarded to ${LABEL} · ${String(request?.hits.length ?? 0)} call site(s)`,
      );

      // The wire projection, asserted on what the sender was actually handed.
      expect(request?.projectKey).toMatch(/^[0-9a-f]{64}$/);
      expect(request?.reconcile.mode).toBe('walk');
      // Serialised rather than walked, so a snippet at ANY depth is caught —
      // including one on a field this case does not know about.
      expect(JSON.stringify(request)).not.toContain('snippet');
      // The plaintext project key never leaves either, and the scan's own root
      // is what it is built from here.
      expect(JSON.stringify(request)).not.toContain(root);

      // The credential goes to the endpoint the DESCRIPTOR names.
      expect(sent?.connection).toEqual({ endpoint: ENDPOINT, apiKey: TEST_KEY });
    });

    it('reports the forward in JSON as the outcome object', async () => {
      writeCallSite();
      attachHome({ label: LABEL });
      const transport = recorder({ ok: true });

      const payload = await scanJson(root, [], { send: transport.send });

      expect(payload.forward).toEqual({
        status: 'forwarded',
        endpoint: LABEL,
        callSites: transport.sent[0]?.request.hits.length,
      });
    });

    // Every kind, driven from the enum rather than from a list here: a seventh
    // one arrives as a failing case rather than as a line nobody wrote.
    it.each(RemoteFailureKind.options)('explains a %s refusal', async (kind) => {
      writeCallSite();
      attachHome();
      const transport = recorder({ ok: false, kind });

      await scan([root], { send: transport.send });

      expect(forwardLine()).toBe(
        `Data shares: not forwarded to ${ENDPOINT} — ${FORWARD_FAILURE_LINES[kind]}`,
      );
      expect(exitCode()).toBe(0);
    });

    // The `it.each` above passes just as well if two kinds share a sentence,
    // and a shared sentence is how somebody is sent to fix the wrong thing.
    it('gives every kind its own remediation', () => {
      const lines = Object.values(FORWARD_FAILURE_LINES);
      expect(new Set(lines).size).toBe(RemoteFailureKind.options.length);
      // The 403 has a self-service remedy that a bare "ask an admin" hides: a
      // key minted before this route existed is refused until it is re-minted,
      // and re-attaching is what mints one.
      expect(FORWARD_FAILURE_LINES.forbidden).toMatch(/re-attach/);
      expect(FORWARD_FAILURE_LINES.forbidden).toMatch(/org admin/);
    });

    it('treats a sender that throws as unreachable rather than as a failed scan', async () => {
      writeCallSite();
      attachHome();
      const transport = recorder(() => {
        throw new Error('socket hung up');
      });

      const payload = await scanJson(root, [], { send: transport.send });

      expect(payload.forward).toEqual({
        status: 'failed',
        endpoint: ENDPOINT,
        kind: 'unreachable',
      });
      expect(exitCode()).toBe(0);
    });

    it('never carries the resolved input, a snippet or the plaintext key into JSON', async () => {
      // The recorder hands back the input it wrote beside the totals — every
      // call site's source line and the project key in plaintext — and the JSON
      // builder picks the totals by name. This pins that a future spread of
      // the whole record would be caught, because --format json is the stream
      // a CI pipeline captures.
      writeCallSite();
      attachHome({ label: LABEL });
      const transport = recorder({ ok: true });

      const payload = await scanJson(root, [], { send: transport.send });

      const raw = JSON.stringify(payload);
      expect(raw).not.toContain('"input"');
      expect(raw).not.toContain('"projectKey"');
      expect(raw).not.toContain('snippet');
      expectNoEchoOf(raw, "export const CHARGES = 'https://api.stripe.com/v1/charges';");
      // The positive control: the register itself was recorded and forwarded.
      expect(payload.egress).not.toBeNull();
      expect(payload.forward).toMatchObject({ status: 'forwarded' });
    });

    it('names the reason a run stayed local', () => {
      // Two reasons, two lines: an opt-out names the flag the person passed,
      // the switch names the page where it lives.
      expect(renderForwardLine({ status: 'disabled', endpoint: LABEL, reason: 'opt-out' })).toBe(
        'Data shares: not forwarded (--no-forward)',
      );
      expect(
        renderForwardLine({ status: 'disabled', endpoint: LABEL, reason: 'data-shares-off' }),
      ).toBe('Data shares: not forwarded (Data Shares is off in Settings)');
    });

    it('records locally and sends nothing under --no-forward', async () => {
      writeCallSite();
      attachHome();
      const transport = recorder({ ok: true });

      await scan([root, '--no-forward'], { send: transport.send });

      expect(transport.sent).toEqual([]);
      expect(forwardLine()).toBe('Data shares: not forwarded (--no-forward)');
      // The flag skips the forward, never the write it would have forwarded.
      expect(out).toMatch(/^Data shares: \d+ destination/m);
    });

    it('reports --no-forward in JSON as a disabled outcome naming the deployment', async () => {
      writeCallSite();
      attachHome();
      const transport = recorder({ ok: true });

      const payload = await scanJson(root, ['--no-forward'], { send: transport.send });

      expect(payload.forward).toEqual({
        status: 'disabled',
        reason: 'opt-out',
        endpoint: ENDPOINT,
      });
      expect(transport.sent).toEqual([]);
    });

    it('names the deployment it holds no usable credential for, and sends nothing', async () => {
      writeCallSite();
      attachHome({ apiKey: null });
      const transport = recorder({ ok: true });

      await scan([root], { send: transport.send });

      expect(transport.sent).toEqual([]);
      expect(forwardLine()).toBe(
        `Data shares: not forwarded to ${ENDPOINT} — ` +
          'no usable credential; re-attach with `aka attach`',
      );
    });

    it('leaves the exit code entirely to --fail-on', async () => {
      writeCallSite();
      writeFileSync(join(root, 'clean.ts'), 'export const ok = 1;\n');
      attachHome();

      // A failing forward on a tree with nothing to report: the gate is about
      // findings, and the forward is not one of them.
      await scan([root, '--fail-on', 'low'], {
        send: recorder({ ok: false, kind: 'unreachable' }).send,
      });
      expect(forwardLine()).toContain(FORWARD_FAILURE_LINES.unreachable);
      expect(exitCode()).toBe(0);

      // And the other direction: a successful forward does not rescue a tree
      // that trips the threshold.
      writeFileSync(join(root, 'critical.ts'), `${CRITICAL_TEXT}\n`);
      await scan([root, '--fail-on', 'critical'], { send: recorder({ ok: true }).send });
      expect(forwardLine()).toMatch(/^Data shares: forwarded to /);
      expect(exitCode()).toBe(1);
    });

    it('puts a valid request on the wire, with the key in a header and nowhere else', async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        attachHome({ endpoint: server.origin });
        server.reply((_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        });

        // NO injected sender: this is the client the command builds for itself.
        await scan([root]);

        expect(server.received).toHaveLength(1);
        const req = server.received[0];
        expect(req?.method).toBe('POST');
        expect(req?.url).toBe('/v1/shares');
        expect(req?.headers['x-api-key']).toBe(TEST_KEY);

        // Validated against the contract rather than eyeballed: a body this
        // build assembles wrongly must fail here, on the machine that still has
        // the plaintext, rather than as somebody's remote 400.
        const parsed = EgressIngestRequestSchema.safeParse(JSON.parse(req?.body ?? '{}'));
        expect(parsed.error?.message ?? 'valid').toBe('valid');
        expect(req?.body).not.toContain('snippet');

        expect(forwardLine()).toMatch(/^Data shares: forwarded to /);
        // The key rides in a header and appears in no rendered sentence, on
        // either stream. `out` is non-empty (asserted just above), so this is
        // not searching empty bytes.
        expectNoEchoOf(out, TEST_KEY);
        expect(err).toBe('');

        // A manual scan is not the hook path and must not borrow its breaker: a
        // scan on a machine with no signal would otherwise silence the session
        // forwarding that machine does afterwards.
        for (const name of [ATTACHED_FORWARD_STATE_FILENAME, ATTACHED_FORWARD_DROPS_FILENAME]) {
          expect(existsSync(join(dataDir(home), name))).toBe(false);
        }
      } finally {
        await server.close();
      }
    });

    it('renders the refusal a real 403 produces', async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        attachHome({ endpoint: server.origin });
        server.reply((_req, res) => {
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end('{"error":{"code":"FORBIDDEN"}}');
        });

        await scan([root]);

        expect(forwardLine()).toBe(
          `Data shares: not forwarded to ${server.origin} — ${FORWARD_FAILURE_LINES.forbidden}`,
        );
        expect(exitCode()).toBe(0);
      } finally {
        await server.close();
      }
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

      // The fourth early return, and the one whose target DOES exist — so it
      // collides with the other three on the exit code while being a different
      // kind of answer.
      await scan([home]);
      const refused = { code: exitCode(), stderr: err, stdout: out };

      expect([findings.code, badFlag.code, missing.code, refused.code]).toEqual([1, 1, 1, 1]);

      // The one thing that does separate them today.
      expect(findings.stderr).toBe('');
      expect(findings.stdout).not.toBe('');
      expect(badFlag.stderr).not.toBe('');
      expect(badFlag.stdout).toBe('');
      expect(missing.stderr).not.toBe('');
      expect(missing.stdout).toBe('');
      expect(refused.stderr).not.toBe('');
      expect(refused.stdout).toBe('');
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
      expect(header).toMatch(/\bFIVE\b/);
      // Both earlier undercounts, each kept as the regression it was: the
      // comment said "three error paths" before parseArgs was counted, and
      // "FOUR paths" before the protected-target refusal became the fourth
      // early return.
      expect(header).not.toMatch(/\bthree error paths\b/);
      expect(header).not.toMatch(/\bFOUR paths\b/);
      expect(header).toMatch(/parseArgs/);
      expect(header).toMatch(/main\(\)\.catch/);
      // The newest of the five, and the one a reader is least likely to guess:
      // a target can be refused for what it HOLDS rather than for being absent.
      expect(header).toMatch(/refuses to read/i);
    });
  });
});
