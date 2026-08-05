import type { MatchResult, ScanContext } from '@akasecurity/detections';
import { scan } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { IsolatedScanner, IsolatedScanOptions, IsolatedScanOutcome } from './isolated-scan.ts';
import { createIsolatedScanner } from './isolated-scan.ts';
import type { RuleProbeGateway } from './rule-quarantine.ts';
import { quarantineRule } from './rule-quarantine.ts';

/**
 * Decides whether a scan runs in-process or under the hard bound, and what to
 * do when the bound fires.
 *
 * The ruleset splits by what stands behind each rule's running time, not by who
 * wrote it. `verified` covers the compiled-in packs, which CI measures against
 * the adversarial battery on every commit, and any rule whose matcher cannot
 * backtrack at all — a keyword matcher compiles one fully-escaped literal per
 * keyword, so no pattern its author supplies can make it catastrophic.
 * `unverified` is what is left: a regex from a pulled or custom pack, which no
 * review gate covers and which only the runtime timing pre-flight stands
 * behind — an empirical verdict a pattern written against that battery can earn
 * while still backtracking forever on real text.
 *
 * So the isolation follows the risk rather than the traffic:
 *
 *   - No unverified rules — the state of a machine that installed nothing extra,
 *     which is the overwhelming majority — and the scan runs in-process exactly
 *     as before. No thread, no message, no added latency at all.
 *   - Any unverified rule, and the WHOLE ruleset moves into the worker. Not the
 *     unverified half: splitting the scan in two would break `requiresNearby`
 *     corroboration across the halves and silently drop findings. Everything
 *     under one bound is also the stronger property.
 *
 * An ordinary scan makes one `scan()` call in the worker, so the isolated cost
 * scales in the ruleset exactly as the in-process cost does. Naming the rule
 * that hung needs a pass that walks the unverified rules one at a time, and
 * that pass is a RETRY of a scan that already timed out — never a tax on the
 * scans that succeed.
 *
 * Degradation never re-runs unverified rules in-process. Doing so would put back
 * the unbounded call the worker exists to prevent, so a scan that loses its
 * worker falls back to the verified rules only, and says so on stderr.
 */
export interface GuardedScanner {
  scan(text: string, context?: ScanContext): Promise<MatchResult[]>;
  /**
   * True once isolation has been retired, which means every pulled/custom-pack
   * regex rule has been dropped for the rest of THIS scanner's life — the rest
   * of the process for a caller that builds one and exits, the rest of one unit
   * of work for a caller that builds one per unit (see `degradeScope`). A
   * caller that records "this input was scanned" must not record it against the
   * full ruleset after this flips.
   */
  degraded(): boolean;
  close(): Promise<void>;
}

export interface GuardedScanPartition {
  verified: Rule[];
  unverified: Rule[];
}

export interface GuardedScanOptions extends IsolatedScanOptions {
  /**
   * How long a degradation lasts, in the words the stderr warning uses. The
   * default fits a process that builds ONE scanner and exits — every hook — so
   * "the rest of this process" and "the rest of this scanner" are the same
   * span. A caller that builds a scanner per unit of work says so here: the
   * dashboard's folder scan builds one per request precisely so a single hang
   * does not cost a long-running server its pulled rules until it is
   * restarted, and the default sentence would claim exactly that.
   */
  degradeScope?: string | undefined;
}

const DEFAULT_DEGRADE_SCOPE = 'the rest of this process';

function warnDegraded(scope: string, dropped: number, detail: string): void {
  process.stderr.write(
    `[aka] isolated scanning is off for ${scope}: ${detail}. ` +
      `${String(dropped)} pulled/custom-pack rule(s) are excluded; the built-in packs still run.\n`,
  );
}

export function createGuardedScanner(
  partition: GuardedScanPartition,
  gateway: Pick<RuleProbeGateway, 'setRuleProbeVerdict'>,
  opts?: GuardedScanOptions,
): GuardedScanner {
  const degradeScope = opts?.degradeScope ?? DEFAULT_DEGRADE_SCOPE;
  const verified = partition.verified;
  let unverified = partition.unverified;
  let isolated: IsolatedScanner | undefined =
    unverified.length > 0 ? createIsolatedScanner({ verified, unverified }, opts) : undefined;
  let retired = false;

  function inProcess(text: string, context: ScanContext | undefined): MatchResult[] {
    return scan(text, verified, context);
  }

  // One hang costs one bounded recovery per scanner, not one per field. A
  // PreToolUse hook can scan up to MCP_MAX_LEAF_COUNT fields; paying the
  // deadline on each would run the hook past the harness timeout, and a
  // timed-out hook fails open and lets the whole tool call through unscanned —
  // the exact bypass this guards. So the first failure retires isolation, and
  // with it every unverified rule, for the remaining life of this scanner. The
  // next one starts clean: an attributed culprit is quarantined in the shared
  // cache and never loads again, and any rule dropped only as collateral is
  // back. How long that costs is the caller's choice of scanner lifetime — a
  // hook builds one and exits, the dashboard builds one per folder scan.
  async function retire(): Promise<void> {
    const live = isolated;
    isolated = undefined;
    unverified = [];
    if (live) await live.close();
  }

  // Retire BECAUSE something failed, which is the case `degraded()` reports. An
  // ordinary close() retires the worker too but leaves no coverage gap behind
  // it, so it must not set this.
  async function degrade(): Promise<void> {
    retired = true;
    await retire();
  }

  // The scanner reports its failures rather than throwing them, so a throw here
  // is the unforeseen case. Take the same exit as any other lost worker: this
  // must not become the one path where a scan silently stops happening.
  async function attempt(
    active: IsolatedScanner,
    text: string,
    context: ScanContext | undefined,
    attribute: boolean,
  ): Promise<IsolatedScanOutcome> {
    try {
      return await active.scan(text, context, { attribute });
    } catch (error) {
      return {
        status: 'unavailable',
        reason: error instanceof Error ? error.message : 'the scan worker failed unexpectedly',
      };
    }
  }

  async function guardedScan(
    text: string,
    context: ScanContext | undefined,
  ): Promise<MatchResult[]> {
    const active = isolated;
    if (!active) return inProcess(text, context);

    let outcome = await attempt(active, text, context, false);
    if (outcome.status === 'ok') return outcome.findings;

    // A timeout is the one outcome worth a second look. The first pass runs the
    // ruleset in one call and so cannot say which rule hung; this retry walks
    // the unverified rules one at a time on a fresh thread, which is what turns
    // "something hung" into a rule id that can be quarantined for good. It
    // costs a second budget, and only ever once — isolation is retired below
    // whatever this returns.
    if (outcome.status === 'timeout') outcome = await attempt(active, text, context, true);

    const dropped = unverified.length;
    if (outcome.status === 'ok') {
      // The retry finished, so the first timeout was a stall rather than a rule
      // that cannot return. Nothing is blamed and nothing is cached, but
      // isolation still retires: a machine that stalls once stalls again, and
      // paying two budgets per field is the harness timeout this exists to
      // avoid. These findings are real — hand them back.
      warnDegraded(
        degradeScope,
        dropped,
        'a scan overran its bound once and no rule could be held responsible',
      );
      const findings = outcome.findings;
      await degrade();
      return findings;
    }

    if (outcome.status === 'timeout') {
      const culprit =
        outcome.culpritIndex === undefined ? undefined : unverified[outcome.culpritIndex];
      if (culprit) {
        await quarantineRule(
          gateway,
          culprit,
          outcome.elapsedMs,
          `it did not finish within the ${outcome.elapsedMs.toFixed(0)}ms isolated-scan bound ` +
            `and was terminated; excluded from every later scan.`,
        );
      }
      warnDegraded(
        degradeScope,
        dropped,
        culprit
          ? `rule "${culprit.id}" had to be terminated mid-scan`
          : `a scan was terminated at the ${outcome.elapsedMs.toFixed(0)}ms bound and no single ` +
              `rule could be held responsible, so nothing was quarantined and the next process ` +
              `will try these rules again`,
      );
    } else {
      warnDegraded(degradeScope, dropped, outcome.reason);
    }

    await degrade();
    return inProcess(text, context);
  }

  return {
    scan: guardedScan,
    degraded: () => retired,
    async close() {
      await retire();
    },
  };
}
