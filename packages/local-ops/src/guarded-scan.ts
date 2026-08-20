import type { MatchResult } from '@akasecurity/detections';
import type { LocalDatabase } from '@akasecurity/persistence';
import type {
  CompleteIsolatedScanOptions,
  GuardedScanner,
  IsolatedProbeOutcome,
  IsolatedScanner,
  RuleProbeGateway,
} from '@akasecurity/plugin-sdk';
import {
  bundledDetections,
  createGuardedScanner,
  createIsolatedScanner,
  filterUnsafeRules,
  ruleProbeKey,
} from '@akasecurity/plugin-sdk';
import type { Rule } from '@akasecurity/schema';

// The ReDoS bound for the filesystem scan, for the one caller that needs it:
// the dashboard's folder scan, which runs the INSTALLED-PACK snapshot — pulled
// and custom packs included — over a user-chosen tree.
//
// A regex has no upper bound and `scan()` is synchronous, so a pattern that
// backtracks forever is not a slow scan but a scan that never returns. On the
// hook path that shows up as a timed-out hook that fails open; in a Server
// Action there is no harness timeout at all, so the request simply never
// answers. Both gates the plugin runtime puts in front of that live in
// @akasecurity/plugin-sdk and are reused verbatim here:
//
//   - the timing pre-flight (filterUnsafeRules), which measures a pulled regex
//     rule against the adversarial battery ONCE and caches the verdict in
//     rule_probe_cache — the same table the hooks read and write, so a rule the
//     plugin already measured costs the dashboard nothing;
//   - the isolated scan (createGuardedScanner), which runs the whole ruleset on
//     a worker thread under a wall-clock deadline whenever any rule is standing
//     on that empirical verdict alone.
//
// Both measurements are unbounded runs of an untrusted pattern, so both happen
// on a thread that can be killed. `worker.terminate()` reaches V8's execution
// terminator; nothing on the calling thread can interrupt a spinning `exec`.
//
// What this module adds over the plugin's own wiring is WHERE THE WORKER IS.
// `isolated-scan.ts` resolves its worker as a sibling of the emitting bundle,
// which is right for the plugin's flat `scripts/` output and wrong everywhere
// else: a Next.js build inlines `import.meta.url` as the BUILD MACHINE's
// absolute source path, so the sibling lookup silently finds nothing on a
// user's machine (and would find the wrong tree on the build machine's own).
// So the worker location is a caller input here, never a guess — see
// `workerUrl`.

/**
 * How long a degradation lasts, in the words the plugin SDK's stderr warning
 * uses. A scanner built here covers ONE scan, unlike a hook's, which covers the
 * whole process: the dashboard is a long-running server, and a single hang must
 * not cost it its pulled rules until someone restarts it.
 */
const DEGRADE_SCOPE = 'the rest of this scan';

// What the pre-flight is told when there is nowhere safe to measure a rule.
// `filterUnsafeRules` excludes the rule WITHOUT persisting a verdict for this —
// it was never timed, and caching "quarantined" for a rule nobody measured
// would disable it forever on the strength of a missing file.
//
// This string is the whole diagnosis the user gets: the pre-flight prints it
// verbatim, once per pass, in place of a per-rule timing line. So it names the
// worker and reads as a clause inside that sentence, not as a standalone note.
const NO_WORKER: IsolatedProbeOutcome = {
  status: 'unavailable',
  reason:
    'this build shipped without its scan worker, so there was nowhere killable to measure them',
};

export interface GuardedFileScannerOptions {
  /**
   * The scan worker script. Isolation is only possible with one — the caller
   * owns its own build layout and is the only thing that can say where the
   * worker landed in it. Omitted (or a path that does not exist), nothing is
   * isolated: every rule that has only the timing pre-flight behind it is
   * dropped and reported rather than run unbounded.
   */
  workerUrl?: URL | undefined;
  /** Test seam: the wall-clock bound on scanning one file. */
  budgetMs?: number | undefined;
  /** Test seam: the wall-clock bound on measuring one rule against the battery. */
  probeBudgetMs?: number | undefined;
  /** Test seam: how long the worker has to load before it is called unavailable. */
  startBudgetMs?: number | undefined;
  /** Test seam: the whole pre-flight's budget, across every rule it measures. */
  passBudgetMs?: number | undefined;
  /**
   * Called with the thread id of each worker this scan constructs. How many
   * threads a scan builds is the property its suite is really about — none when
   * nothing needs bounding, one for the pre-flight, two to recover from a hang
   * and then name it — and the only other instrument for it is elapsed time,
   * which cannot separate an extra recovery cycle from a cold start on a busy
   * runner.
   *
   * It is also what makes the per-request lifetime observable: a scanner shared
   * across two scans builds no thread for the second.
   */
  onWorkerStart?: ((threadId: number) => void) | undefined;
}

/**
 * What the guard removed from a scan, split by whether a VERDICT SURVIVED it.
 *
 * That split is the one a reader acts on, and it does not follow the gates. A
 * rule the battery measured and failed leaves a `quarantined` row behind, so
 * `aka detections` can name it and `aka detections unquarantine` can undo it. A
 * rule that was never measured HERE leaves nothing — deliberately, since
 * caching a verdict for a rule nobody timed would disable it forever on the
 * strength of a missing worker or an unlucky pass budget. Both were "dropped
 * before the walk", but only one of them has anywhere to send the user.
 */
export interface DroppedRules {
  /**
   * Measured, failed, and cached: these are what `aka detections` lists. A
   * cached verdict from an earlier scan — or from a hook — counts here too,
   * because the row is what makes it visible, not who wrote it.
   */
  quarantined: number;
  /**
   * Nothing was cached, so there is nothing to point anyone at. Three ways in:
   * no worker to measure them on, the pre-flight's pass budget ran out first,
   * or the measurement ran past the wall budget while burning almost no CPU —
   * a busy machine rather than a slow pattern, which is a reading the pre-flight
   * refuses to make permanent. The rules are excluded from this scan and back on
   * the next one.
   */
  unmeasured: number;
  /**
   * Excluded mid-walk, when a scan hit the hard bound and isolation retired.
   * Every rule that was running under the bound goes, not just the culprit —
   * continuing without isolation would put back the unbounded call it exists to
   * prevent. A culprit that could be NAMED is quarantined for good; when none
   * could be, nothing is cached and collateral comes back on the next scan.
   */
  bound: number;
  /** Whether this scan had a worker at all — a build without one bounds nothing. */
  isolated: boolean;
}

// Closures, not methods — `scanText` is handed straight to `scanPathIntoStore`
// as a callback, and a method signature would make every such hand-off an
// unbound-method violation for a `this` that does not exist.
export interface GuardedFileScanner {
  /** Scan one file's text under the bound. */
  scanText: (text: string) => Promise<MatchResult[]>;
  /**
   * What the guard removed. Meaningful once the walk is done, and unchanged by
   * `close()` — so a caller that closes in a `finally` can still report it
   * afterwards.
   */
  dropped: () => DroppedRules;
  close: () => Promise<void>;
}

/**
 * The subset of DataGateway the pre-flight needs, over the local store. The
 * verdict cache is shared with the plugin on purpose: it is keyed by a content
 * hash of the pattern, so a rule the hooks already measured is never measured
 * again here, and a rule the dashboard terminates never loads in a hook.
 */
function probeGateway(db: LocalDatabase): RuleProbeGateway {
  return {
    getRuleProbeVerdict: (ruleKey) => Promise.resolve(db.ruleProbeCache.getVerdict(ruleKey)),
    setRuleProbeVerdict: (ruleKey, verdict, worstProbeMs) => {
      db.ruleProbeCache.setVerdict(ruleKey, verdict, worstProbeMs);
      return Promise.resolve();
    },
  };
}

// Probe keys for every compiled-in rule. These are gated by the CI adversarial
// battery on every commit, so they bypass the runtime timing gate entirely —
// re-measuring them would let a cold-cache pass on slow hardware quarantine a
// legitimate secret matcher and silently disable detection. Derived from
// `bundledDetections()` rather than the engine's process-global registry: this
// runs inside a long-lived Next server that deliberately never calls
// `registerBundledPacks()`, so the registry is empty there.
let bundledKeys: Set<string> | undefined;
function bundledProbeKeys(): Set<string> {
  bundledKeys ??= new Set(
    bundledDetections()
      .flatMap((pack) => pack.rules)
      .map(ruleProbeKey)
      .filter((key): key is string => key !== undefined),
  );
  return bundledKeys;
}

/**
 * Build a bounded scanner for `rules` — an installed-pack snapshot, pulled and
 * custom packs included.
 *
 * The ruleset splits by what stands behind each rule's running time, not by who
 * wrote it: the compiled-in packs and any matcher that cannot backtrack at all
 * (a keyword matcher compiles one fully-escaped literal per keyword) need no
 * bound, and everything else does. When nothing is left in that second group —
 * the state of a machine that installed nothing extra, which is the
 * overwhelming majority — no thread is started and the scan runs in-process at
 * exactly the cost it did before.
 *
 * The caller closes it.
 */
export async function createGuardedFileScanner(
  db: LocalDatabase,
  rules: Rule[],
  opts: GuardedFileScannerOptions = {},
): Promise<GuardedFileScanner> {
  const gateway = probeGateway(db);
  // Isolation needs a worker script, and only the caller knows where its own
  // build put one. Without it, nothing here can be killed — so the SDK's
  // sibling lookup is never reached (it finds `scan-worker.ts` in this repo and
  // nothing in a bundled build, which is the failure that only shows up once
  // installed), and a rule that cannot be bounded is dropped rather than run.
  const workerUrl = opts.workerUrl;
  // Annotated rather than inferred, and that annotation is the whole point.
  // `CompleteIsolatedScanOptions` requires every key of `IsolatedScanOptions` to
  // be present, so a field added to the SDK fails this build until it is named
  // here. Inferred, this object was free to list a subset — which it did, and
  // `onWorkerStart` reached the plugin's isolation and never the dashboard's
  // while typecheck, lint and every test stayed green.
  //
  // A field this caller deliberately does NOT expose is spelled `undefined`, so
  // "take the SDK's default" is written down rather than left as an absence
  // nobody can tell from an oversight.
  const isolation: CompleteIsolatedScanOptions = {
    workerUrl,
    budgetMs: opts.budgetMs,
    probeBudgetMs: opts.probeBudgetMs,
    startBudgetMs: opts.startBudgetMs,
    onWorkerStart: opts.onWorkerStart,
    // Not exposed: attribution decides which rule a hang is PINNED on, and the
    // verdict that follows is cached forever. The SDK's own floor is the only
    // value anything here should reach, and a folder scan has no reason to
    // widen or narrow it.
    minAttributionMs: undefined,
  };

  const bundled = bundledProbeKeys();
  const ciVerified: Rule[] = [];
  const needsGate: Rule[] = [];
  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key !== undefined && bundled.has(key)) ciVerified.push(rule);
    else needsGate.push(rule);
  }

  // The battery decides whether a pattern is safe by driving it into
  // backtracking, so measuring a rule is itself a way to hang on it. The
  // measurement therefore runs on a thread that can be killed — built on first
  // use, so a scan whose verdicts are all cached (the steady state) starts no
  // thread for the gate at all. With no worker to build, `filterUnsafeRules`
  // reports every uncached rule as unmeasurable and drops it, which is the
  // right answer: running it here to find out is the unbounded call the prober
  // exists to replace.
  let prober: IsolatedScanner | undefined;
  const gated = await filterUnsafeRules(needsGate, gateway, {
    passBudgetMs: opts.passBudgetMs,
    prober: {
      probe: (rule) => {
        if (workerUrl === undefined) return Promise.resolve(NO_WORKER);
        prober ??= createIsolatedScanner({ verified: [], unverified: [] }, isolation);
        return prober.probe(rule);
      },
    },
  });
  await prober?.close();

  // Attribute each dropped rule to what it left behind, by reading the verdict
  // cache — the same table `aka detections` reads. Only a rule that was
  // MEASURED has a row there, so only that one can be pointed at; saying "see
  // what is quarantined" about a rule nobody timed sends the user to an empty
  // list. `filterUnsafeRules` hands back the rule objects it was given, so
  // identity is what separates the survivors from the dropped.
  const survived = new Set(gated);
  let quarantined = 0;
  let unmeasured = 0;
  for (const rule of needsGate) {
    if (survived.has(rule)) continue;
    const key = ruleProbeKey(rule);
    let verdict;
    try {
      verdict = key === undefined ? undefined : (await gateway.getRuleProbeVerdict(key))?.verdict;
    } catch {
      // A reporting read must never cost the caller its scan. Unknown counts as
      // unmeasured: claiming a row exists that nobody could confirm is the one
      // wrong answer here.
      verdict = undefined;
    }
    if (verdict === 'quarantined') quarantined++;
    else unmeasured++;
  }

  // Only a REGEX matcher can run without an upper bound, so a pulled keyword
  // rule joins the verified set and a keyword-only custom pack starts no worker.
  // A regex rule that cleared the battery still needs the runtime bound — the
  // verdict is empirical, and a pattern written against that battery can earn it
  // while still backtracking forever on real text — so with no worker to enforce
  // one it is dropped here rather than promoted into the in-process set.
  const verified: Rule[] = [...ciVerified];
  const unverified: Rule[] = [];
  let unboundable = 0;
  for (const rule of gated) {
    if (rule.matcher.type !== 'regex') verified.push(rule);
    else if (workerUrl !== undefined) unverified.push(rule);
    else unboundable++;
  }

  const scanner: GuardedScanner = createGuardedScanner({ verified, unverified }, gateway, {
    ...isolation,
    degradeScope: DEGRADE_SCOPE,
  });
  // A rule dropped for want of a worker was never measured either — its cached
  // verdict is `safe`, which is exactly why it is not quarantined.
  unmeasured += unboundable;

  return {
    scanText: (text) => scanner.scan(text),
    dropped: () => ({
      quarantined,
      unmeasured,
      bound: scanner.degraded() ? unverified.length : 0,
      isolated: workerUrl !== undefined,
    }),
    close: () => scanner.close(),
  };
}
