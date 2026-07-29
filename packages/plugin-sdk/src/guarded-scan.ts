import type { MatchResult, ScanContext } from '@akasecurity/detections';
import { scan } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { IsolatedScanner, IsolatedScanOptions } from './isolated-scan.ts';
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
 * Degradation never re-runs unverified rules in-process. Doing so would put back
 * the unbounded call the worker exists to prevent, so a scan that loses its
 * worker falls back to the verified rules only, and says so on stderr.
 */
export interface GuardedScanner {
  scan(text: string, context?: ScanContext): Promise<MatchResult[]>;
  close(): Promise<void>;
}

export interface GuardedScanPartition {
  verified: Rule[];
  unverified: Rule[];
}

function warnDegraded(dropped: number, detail: string): void {
  process.stderr.write(
    `[aka] isolated scanning is off for the rest of this process: ${detail}. ` +
      `${String(dropped)} pulled/custom-pack rule(s) are excluded; the built-in packs still run.\n`,
  );
}

export function createGuardedScanner(
  partition: GuardedScanPartition,
  gateway: Pick<RuleProbeGateway, 'setRuleProbeVerdict'>,
  opts?: IsolatedScanOptions,
): GuardedScanner {
  const verified = partition.verified;
  let unverified = partition.unverified;
  let isolated: IsolatedScanner | undefined =
    unverified.length > 0 ? createIsolatedScanner({ verified, unverified }, opts) : undefined;

  function inProcess(text: string, context: ScanContext | undefined): MatchResult[] {
    return scan(text, verified, context);
  }

  // One hang costs one budget per process, not one per field. A PreToolUse hook
  // can scan up to MCP_MAX_LEAF_COUNT fields; paying the deadline on each would
  // run the hook past the harness timeout, and a timed-out hook fails open and
  // lets the whole tool call through unscanned — the exact bypass this guards.
  // So the first failure retires isolation, and with it every unverified rule,
  // for the remainder of the process. The next process starts clean: an
  // attributed culprit is quarantined in the shared cache and never loads
  // again, and any rule dropped only as collateral is back.
  async function retire(): Promise<void> {
    const live = isolated;
    isolated = undefined;
    unverified = [];
    if (live) await live.close();
  }

  async function guardedScan(
    text: string,
    context: ScanContext | undefined,
  ): Promise<MatchResult[]> {
    const active = isolated;
    if (!active) return inProcess(text, context);

    let outcome;
    try {
      outcome = await active.scan(text, context);
    } catch (error) {
      // The scanner reports its failures rather than throwing them, so this is
      // the unforeseen case. Take the same exit as any other lost worker: this
      // must not become the one path where a scan silently stops happening.
      outcome = {
        status: 'unavailable' as const,
        reason: error instanceof Error ? error.message : 'the scan worker failed unexpectedly',
      };
    }
    if (outcome.status === 'ok') return outcome.findings;

    const dropped = unverified.length;
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
        dropped,
        culprit
          ? `rule "${culprit.id}" had to be terminated mid-scan`
          : `a scan was terminated at the ${outcome.elapsedMs.toFixed(0)}ms bound and no single ` +
              `rule could be held responsible`,
      );
    } else {
      warnDegraded(dropped, outcome.reason);
    }

    await retire();
    return inProcess(text, context);
  }

  return {
    scan: guardedScan,
    async close() {
      await retire();
    },
  };
}
