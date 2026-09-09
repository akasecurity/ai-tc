import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import { EgressIngestRequest, type Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { runScan } from '../../app/(app)/scan/actions.ts';
import { startLoopbackServer } from '../helpers/loopback.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

/**
 * The dashboard's folder scan against a hostile installed pack.
 *
 * This action runs the INSTALLED-PACK snapshot — pulled and custom packs
 * included, none of them reviewed by this repository — over a user-chosen tree.
 * A regex has no upper bound, so one catastrophic pattern would not slow the
 * request down, it would stop it answering: unlike a plugin hook, a Server
 * Action has no harness timeout to be killed by, so nothing would ever return.
 *
 * The bound itself is covered where it lives (packages/local-ops/test/
 * guarded-scan.test.ts). What only this suite can show is that the ACTION is
 * wired to it — including the half that is invisible from source, because the
 * action resolves its worker from a path this package's build produces. The
 * `build:worker` turbo task builds it before this one runs, and it is the ONLY
 * task that writes `dist/` — see test/scan-worker-build.test.ts for why that
 * shape is load-bearing. Both suites here drive the real artifact, so a
 * second writer racing this run does not read as a build problem: it reads as
 * the action's own wording ("shipped without its scan worker" when the file is
 * gone at `existsSync`, no culprit quarantined when it vanishes under the
 * worker's load) and would send a reader to debug the timing battery.
 *
 * Setup follows the four steps every web-ui Server Action test needs: redirect
 * the home dir by mocking `node:os` (the action resolves ~/.aka from it, and
 * n/no-process-env rules out an env override), stub `next/cache` (revalidatePath
 * needs a Next render context that does not exist under vitest), and close and
 * drop the memoised DB handle on globalThis around every test.
 */
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Clears the timing battery in microseconds — every probe fails at the `zzq`
// literal before reaching the nested quantifier — and then backtracks without
// end on text that carries it. The rule is schema-valid: `matchesEmptyString`
// turns away a `*`-quantified outer group, and this one requires a character.
const HOSTILE: Rule = {
  specVersion: 1,
  id: 'hostile/battery-blind',
  name: 'Battery-blind pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(?:zzq)(a+)+$`, flags: 'g' },
};
const HOSTILE_TEXT = `zzq${'a'.repeat(34)}!`;

// See guarded-scan.test.ts: three hostile files, so an unbounded walk is
// decisively past the ceiling below rather than merely near it.
const HOSTILE_FILES = 3;

// A real compiled-in rule and text it matches, taken from the packs rather than
// restated here. This is the control for "the rules that never needed a bound
// keep detecting", so it has to be one the guard really treats as CI-verified.
function bundledControl(): { rule: Rule; text: string } {
  for (const pack of bundledDetections()) {
    for (const rule of pack.rules) {
      const example = rule.examples?.[0];
      if (rule.matcher.type === 'regex' && example !== undefined && example.length > 0) {
        return { rule, text: example };
      }
    }
  }
  throw new Error('no bundled regex rule with an example — the control cannot be built');
}
const CONTROL = bundledControl();

// The action runs the SHIPPED budgets (there is no seam to shorten them, and a
// seam here would be a seam in production code for a test's benefit), so the
// worst case is two worker starts at ISOLATED_START_BUDGET_MS = 5s plus two
// scan deadlines at ISOLATED_SCAN_BUDGET_MS = 2s. x2 for a loaded runner.
const CEILING_MS = 2 * (2 * 5_000 + 2 * 2_000);

// Above the ceiling, so a blown bound fails on the assertion — which names what
// was exceeded — rather than on the package's 20s default, which just says the
// test timed out.
const CASE_TIMEOUT_MS = 120_000;

let home: string;
let target: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

// Install the bundled packs plus a pulled pack carrying `rules`, and mark every
// regex rule in that pulled pack as already measured SAFE.
//
// The pre-seeded verdict is what makes this a test of the SCAN bound. Without
// it the hostile rule has to survive a live measurement on the runner first, and
// a slow one quarantines it at the pre-flight instead — the scan bound then
// never runs and the case still passes on its other assertions, because the
// bundled control did the detecting. It is also the honest steady state: a real
// machine measures a rule once, ever.
function installPulled(rules: Rule[]): void {
  const db = openLocalDatabase(dataDir());
  try {
    db.installedPacks.recordInventory([
      ...bundledDetections(),
      {
        namespace: 'hostile',
        packId: 'redos',
        version: '1.0.0',
        name: 'Hostile pulled pack',
        rules,
      },
    ]);
    for (const rule of rules) {
      const key = ruleProbeKey(rule);
      if (key !== undefined) db.ruleProbeCache.setVerdict(key, 'safe', 0.1);
    }
  } finally {
    db.close();
  }
  // The action reads through the memoised handle, so it has to reopen and see
  // what this second handle just wrote.
  resetSingleton();
}

async function recordedRuleIds(): Promise<string[]> {
  const db = openLocalDatabase(dataDir());
  try {
    const findings = await db.findings.recentFindings({ limit: 50 });
    return findings.map((f) => f.ruleId);
  } finally {
    db.close();
  }
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-scan-'));
  osHome.dir = home;
  target = mkdtempSync(join(tmpdir(), 'aka-web-scan-target-'));
  resetSingleton();
  // The guard reports on stderr as well as in the response; keep the suite's
  // own output readable.
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  resetSingleton();
  removeTrees([home, target]);
});

describe('runScan — a pulled rule that never returns', () => {
  it(
    'answers, records what the bounded rules found, and names what it dropped',
    async () => {
      for (let i = 0; i < HOSTILE_FILES; i++) {
        writeFileSync(join(target, `app${String(i)}.ts`), `${HOSTILE_TEXT}\n${CONTROL.text}\n`);
      }
      installPulled([HOSTILE]);

      const started = performance.now();
      const result = await runScan(target);
      const elapsedMs = performance.now() - started;

      // The whole point: the request came back.
      expect(elapsedMs).toBeLessThan(CEILING_MS);
      expect(result.ok).toBe(true);
      expect(result.scanned).toBe(HOSTILE_FILES);

      // The compiled-in packs detected right through it — in every file, not
      // just the ones after the hang. (Counted rather than compared as a set:
      // the snapshot here is the whole bundled inventory, so an example that
      // matches one rule by design also matches its neighbours.)
      const ids = await recordedRuleIds();
      expect(ids.filter((id) => id === CONTROL.rule.id)).toHaveLength(HOSTILE_FILES);
      expect(ids).not.toContain(HOSTILE.id);
      expect(result.findings).toBe(ids.length);

      // And it says what was dropped — a scan that quietly ran a smaller
      // ruleset than the Detections page lists is the failure mode this whole
      // surface has to avoid.
      expect(result.droppedRules).toBeDefined();
      expect(result.droppedRules).toContain('1 rule');
      expect(result.droppedRules).toContain('time bound');

      // The pointer is offered here BECAUSE the bound named its culprit and
      // cached a verdict — so `aka detections` really does have something to
      // print. The wiring is what this asserts: the action reads that count
      // from the store rather than assuming it. (What the sentence does when
      // the count is zero is pinned in test/actions/dropped-rules.test.ts.)
      const store = openLocalDatabase(dataDir());
      try {
        expect(store.ruleProbeCache.countQuarantined()).toBeGreaterThan(0);
      } finally {
        store.close();
      }
      expect(result.droppedRules).toContain('aka detections');
    },
    CASE_TIMEOUT_MS,
  );
});

describe('runScan — an ordinary installed snapshot', () => {
  it(
    'reports nothing dropped and detects normally',
    async () => {
      writeFileSync(join(target, 'app.ts'), `${CONTROL.text}\n`);
      installPulled([]);

      const result = await runScan(target);

      expect(result.ok).toBe(true);
      expect(result.scanned).toBe(1);
      const ids = await recordedRuleIds();
      expect(ids).toContain(CONTROL.rule.id);
      expect(result.findings).toBe(ids.length);
      // The negative control for the case above: with nothing to bound, the
      // response carries no notice at all, so a `droppedRules` that appeared on
      // every scan would fail here rather than reading as normal.
      expect(result.droppedRules).toBeUndefined();

      // The egress recorder returns the resolved input it wrote — source lines
      // and the project key in plaintext — alongside the totals, and this
      // result is serialised to the browser. Only the totals may cross, and
      // the field's declared type cannot enforce that on the runtime object.
      expect(result.egress).toBeDefined();
      const wire = JSON.stringify(result);
      expect(wire).not.toContain('"input"');
      expect(wire).not.toContain('projectKey');
    },
    CASE_TIMEOUT_MS,
  );
});

/**
 * The forward the Scan page makes on an attached machine.
 *
 * Driven against a REAL server on loopback rather than a stubbed transport,
 * because the claims this path makes are claims about the request as it left the
 * process: no source text in the body, the project key replaced by a digest, the
 * credential in a header and nowhere else. A stub would show what the action
 * decided and nothing about what it sent.
 *
 * The setup ritual the suite above uses applies here too — the mocked `node:os`
 * puts the AKA home inside the temp dir, so the attachment these cases write is
 * the one the action reads and no case can reach the real one.
 */
describe('runScan — forwarding the register it just recorded', () => {
  const LABEL = 'Acme Prod';
  const TEST_KEY = 'not-a-real-key';

  // Both halves of an attachment, through the real writers: the settings
  // descriptor that names a deployment, and a credential minted for that same
  // deployment. `apiKey: null` writes only the first half, which is the shape a
  // machine is in after a credential someone deleted.
  function attachHome(endpoint: string, options: { label?: string; apiKey?: string | null } = {}) {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint,
          attachedAt: '2026-09-01T10:00:00.000Z',
          ...(options.label === undefined ? {} : { label: options.label }),
        },
      },
      join(home, '.aka'),
      // No managed overlay: an administrator's file on the machine running this
      // suite must not decide what these cases see.
      null,
    );
    const apiKey = options.apiKey === undefined ? TEST_KEY : options.apiKey;
    if (apiKey !== null) {
      writeControlPlaneCredential(settingsDir(), { specVersion: 1, endpoint, apiKey });
    }
  }

  // One outbound call site, so the register has something in it. A bare URL
  // constant is the smallest thing the extractor records.
  function writeCallSite(): void {
    writeFileSync(
      join(target, 'client.ts'),
      "export const CHARGES = 'https://api.stripe.com/v1/charges';\n",
    );
  }

  it(
    'puts a valid request on the wire and reports where it went',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        installPulled([]);
        attachHome(server.origin, { label: LABEL });
        server.reply((_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        });

        const result = await runScan(target);

        expect(server.received).toHaveLength(1);
        const req = server.received[0];
        expect(req?.method).toBe('POST');
        expect(req?.url).toBe('/v1/shares');
        expect(req?.headers['x-api-key']).toBe(TEST_KEY);

        // Validated against the contract rather than eyeballed: a body this
        // build assembles wrongly must fail here, on the machine that still has
        // the plaintext, rather than as somebody's remote 400.
        const parsed = EgressIngestRequest.safeParse(JSON.parse(req?.body ?? '{}'));
        expect(parsed.error?.message ?? 'valid').toBe('valid');
        // A register with nothing in it would satisfy the projection assertions
        // below vacuously.
        expect(parsed.data?.hits.length).toBeGreaterThan(0);
        expect(parsed.data?.projectKey).toMatch(/^[0-9a-f]{64}$/);
        expect(parsed.data?.reconcile.mode).toBe('walk');
        // Read off the serialised body, so a snippet at ANY depth is caught —
        // including one on a field this case does not know about. The scanned
        // tree's own path is the plaintext half of the project key, and it does
        // not travel either.
        expect(req?.body).not.toContain('snippet');
        expect(req?.body).not.toContain(target);

        // The LABEL, not the URL: what the page shows is the deployment's
        // display name when an administrator gave it one.
        expect(result.forward).toEqual({
          status: 'forwarded',
          endpoint: LABEL,
          callSites: parsed.data?.hits.length,
        });
        // The forward is a side benefit; the scan's own answer is unchanged.
        expect(result.ok).toBe(true);
        expect(result.egress?.callSites).toBeGreaterThan(0);

        // The credential rides in a header and appears in nothing the browser
        // receives.
        expectNoEchoOf(JSON.stringify(result), TEST_KEY);

        // A manual scan is not the hook path and must not borrow its breaker: a
        // scan on a machine with no signal would otherwise silence the session
        // forwarding that machine does afterwards.
        for (const name of [ATTACHED_FORWARD_STATE_FILENAME, ATTACHED_FORWARD_DROPS_FILENAME]) {
          expect(existsSync(join(dataDir(), name)), `${name} was created`).toBe(false);
        }
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'reports a refusal without touching the scan it already recorded',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        installPulled([]);
        attachHome(server.origin);
        server.reply((_req, res) => {
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end('{"error":{"code":"FORBIDDEN"}}');
        });

        const result = await runScan(target);

        expect(result.forward).toEqual({
          status: 'failed',
          endpoint: server.origin,
          kind: 'forbidden',
        });
        // Everything the scan itself produced is what it would have been with no
        // deployment in the picture at all.
        expect(result.ok).toBe(true);
        expect(result.scanned).toBe(1);
        expect(result.egress?.callSites).toBeGreaterThan(0);
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'names the deployment it holds no usable credential for, and sends nothing',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        installPulled([]);
        attachHome(server.origin, { apiKey: null });

        const result = await runScan(target);

        expect(server.received).toEqual([]);
        expect(result.forward).toEqual({ status: 'no-credential', endpoint: server.origin });
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'sends nothing and reports nothing on a machine attached to no deployment',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        installPulled([]);

        const result = await runScan(target);

        expect(server.received).toEqual([]);
        // Absent, not a `not-attached` outcome: the result a standalone install
        // receives has to be the one it received before this action could
        // forward anything, field for field.
        expect(result.forward).toBeUndefined();
        expect(JSON.stringify(result)).not.toContain('forward');
        // And the local write still happened, so the silence is about the
        // forward rather than about the pass having been skipped.
        expect(result.egress?.callSites).toBeGreaterThan(0);
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'forwards and withholds the same way on a scan that found no usable packs',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        // No installPulled(): a home with no detection packs is the branch the
        // action answers with `ok: false`, and it returns the register and the
        // forward alongside that error because the walk already extracted them.
        // Every case above takes the other branch, so the withholding the ok
        // branch is pinned for would be unpinned here — and this is a whole
        // second place the resolved input could be spread into a result the
        // browser receives.
        attachHome(server.origin, { label: LABEL });
        server.reply((_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        });

        const result = await runScan(target);

        expect(result.ok).toBe(false);
        expect(result.error).toContain('No detection packs installed');
        expect(result.forward?.status).toBe('forwarded');
        expect(result.egress?.callSites).toBeGreaterThan(0);

        const wire = JSON.stringify(result);
        expect(wire).not.toContain('"input"');
        expect(wire).not.toContain('snippet');
        expect(wire).not.toContain('projectKey');
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'returns the totals to the browser and never the resolved input',
    async () => {
      const server = await startLoopbackServer();
      try {
        writeCallSite();
        installPulled([]);
        attachHome(server.origin, { label: LABEL });
        server.reply((_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        });

        const result = await runScan(target);

        // The forward is handed the recorder's resolved input — source lines and
        // the project key in plaintext — and this result is serialised to the
        // browser. Adding a field to the result is exactly the edit that would
        // carry it along, so the whole payload is read rather than one field.
        const wire = JSON.stringify(result);
        expect(wire).not.toContain('"input"');
        expect(wire).not.toContain('snippet');
        expect(wire).not.toContain('projectKey');
        expect(wire).toContain('forwarded');
      } finally {
        await server.close();
      }
    },
    CASE_TIMEOUT_MS,
  );
});
