import { randomUUID } from 'node:crypto';

import type { MatchResult, ScanContext } from '@akasecurity/detections';
import { getLoadedRules, maskMatch, redact } from '@akasecurity/detections';
import type {
  ActionTaken,
  DetectedFindingWithKey,
  EventMetadata,
  ExceptionBundleEntry,
  Policy,
  Rule,
  SourceTool,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';

import type { DataGateway } from './data-gateway.ts';
import { buildIngestEvent, contentHashOf } from './events.ts';
import { computeFindingKey } from './finding-key.ts';
import type { FingerprintKey } from './fingerprint.ts';
import { fingerprintValue, loadOrCreateFingerprintKey, readFingerprintKey } from './fingerprint.ts';
import type { GuardedScanner } from './guarded-scan.ts';
import { createGuardedScanner } from './guarded-scan.ts';
import type { IsolatedScanner, IsolatedScanOptions } from './isolated-scan.ts';
import { createIsolatedScanner } from './isolated-scan.ts';
import { dropShieldedFindings, shieldPointers } from './pointer-shield.ts';
import { registerBundledPacks } from './rule-packs.ts';
import { filterUnsafeRules, ruleProbeKey } from './rule-quarantine.ts';
import type { BlockedDetectionRef, CaptureInput, CaptureResult } from './types.ts';

// Global handling-mode ceiling: when true, settings.policy === 'warn' caps
// every block/redact decision down to warn. Disabled — per-category policy
// rows are the sole authority over block/redact/warn/log.
const ENFORCEMENT_CEILING_ENABLED = false as boolean;

// Worst-first ordering for collapsing multiple findings into one decision.
const ACTION_PRIORITY: ActionTaken[] = ['block', 'redact', 'warn', 'log', 'allow'];

/**
 * Start of an added-latency measurement, or `undefined` if the clock could not
 * be read. `performance.now()` is monotonic — a wall clock stepped by NTP mid-
 * capture can run backwards and produce a negative duration, which would drag a
 * percentile down exactly the way a fabricated zero would.
 *
 * Never throws: an unreadable clock costs the row its measurement and nothing
 * else. That is the whole reason the pair returns `undefined` rather than 0 —
 * a fail-open path must degrade to "not measured", never to "took no time".
 */
function startTiming(): number | undefined {
  try {
    return performance.now();
  } catch {
    return undefined;
  }
}

/**
 * Whole milliseconds since `startedAt`, or `undefined` when there is nothing
 * honest to report — no start reading, an unreadable clock now, or a
 * non-finite/negative difference. Rounded because the column and the contract
 * are integer milliseconds; a sub-millisecond capture therefore reports 0,
 * which is a real measurement of a real capture and not the absence of one.
 */
function elapsedMs(startedAt: number | undefined): number | undefined {
  if (startedAt === undefined) return undefined;
  try {
    const delta = performance.now() - startedAt;
    if (!Number.isFinite(delta) || delta < 0) return undefined;
    return Math.round(delta);
  } catch {
    return undefined;
  }
}

// The capture facts detection-exception conditions are ANDed against, and the
// provenance stamped onto blocked-detections ledger rows. `capture()` fills it
// from the CaptureInput; `processText()` has none (a conditioned grant can
// therefore never match there — fail secure, not a bug).
interface ExceptionEvalContext {
  sourceTool?: SourceTool | undefined;
  metadata?: EventMetadata | undefined;
  // Grant ids whose use was ALREADY spent by this same capture's pointer
  // crossing. A matching entry suppresses without consuming and without the
  // budget re-check — the budget was spent by the crossing that revealed the
  // value now being scanned, and charging it twice would re-tokenize the very
  // value the grant just revealed.
  preAuthorizedGrantIds?: readonly string[] | undefined;
}

// A grant is active while unexpired and under its use budget. The bundle's
// useCount is a snapshot (cheap pre-filter); gateway.consumeException re-checks
// atomically against the store, which is what actually claims the use.
function entryIsActive(entry: ExceptionBundleEntry, now: number): boolean {
  if (entry.expiresAt !== null && Date.parse(entry.expiresAt) <= now) return false;
  if (entry.maxUses !== null && entry.useCount >= entry.maxUses) return false;
  return true;
}

// Every PRESENT condition must match the capture context. A condition with no
// corresponding fact (processText has no metadata; nothing carries a provider
// yet) is a NON-match: an absent fact never satisfies a narrowing the approver
// asked for.
function conditionsMatch(
  conditions: ExceptionBundleEntry['conditions'],
  ctx: ExceptionEvalContext,
): boolean {
  if (conditions === null) return true;
  if (conditions.repo !== undefined && conditions.repo !== ctx.metadata?.repo) return false;
  if (conditions.sourceTool !== undefined && conditions.sourceTool !== ctx.sourceTool) return false;
  if (conditions.provider !== undefined) return false;
  return true;
}

// registerBundledPacks() parses + validates every bundled rule JSON. A hook runs
// in its own process, so it would happen once there regardless — but tests build
// many runtimes in one process. Gate it on a module flag so the parse cost is
// paid once and later createPluginRuntime calls are free.
let bundlesPacked = false;

/**
 * The hook-path runtime, built over a {@link DataGateway} rather than a
 * concrete store — `@akasecurity/plugin-runtime` resolves the gateway from
 * PluginConfig. Detection runs in-process; the ruleset and policies are PULLED
 * via `gateway.getPolicyBundle()` on first use: the runtime detects with the
 * bundled packs PLUS the bundle's rules, and resolves enforcement actions from
 * the bundle's policies (falling back to DEFAULT_ACTIONS for any category
 * without an explicit policy).
 *
 * Masking happens here (not in the data layer): `capture` turns raw matches into
 * already-masked DetectedFinding[] before handing them to the gateway, so the
 * data boundary never sees a secret. Every method is async and fully fail-open.
 * The caller owns the gateway's lifetime and must `await close()`.
 *
 * Detection exceptions: between scan and the action collapse, findings whose
 * resolved action is block/redact are matched against the bundle's exception
 * entries by (ruleId, keyed fingerprint of the exact raw match). A matched +
 * consumed grant downgrades those findings to 'allow'. This step — unlike the
 * rest of the runtime — fails SECURE: any doubt (missing dataDir, bad key file,
 * consume error) means no exception applies and enforcement proceeds; the
 * surrounding fail-open catch still protects the session. `opts.dataDir` is
 * where the fingerprint key lives; without it, exception evaluation and the
 * blocked-detections bookkeeping are skipped entirely.
 */
export function createPluginRuntime(
  gateway: DataGateway,
  settings: WorkspaceSettings,
  opts?: { dataDir?: string | undefined; scanIsolation?: IsolatedScanOptions | undefined },
): PluginRuntime {
  if (!bundlesPacked) {
    registerBundledPacks();
    bundlesPacked = true;
  }
  const policyMode = settings.policy;
  const dataDir = opts?.dataDir;
  let policies: Policy[] = [];
  let rules: Rule[] = [];
  // Runs the scan under a hard wall-clock bound when the ruleset carries any
  // pulled/custom-pack rule, and in-process otherwise. Built once the ruleset
  // is known (see ensureInitialized).
  let scanner: GuardedScanner | undefined;
  let bundleExceptions: ExceptionBundleEntry[] = [];
  let initialized = false;
  // Resolution indexes built ONCE from the bundle (see ensureInitialized): the
  // standalone-complete bundle now carries one policy PER RULE (~100+), and
  // resolveAction runs 2–4× per finding on the hot hook path, so a linear scan
  // per call would be O(policies) each time. First-write-wins mirrors the old
  // `.find` order (explicit DB ruleId policies precede pack-derived ones).
  const ruleActionIndex = new Map<string, ActionTaken>();
  const categoryActionIndex = new Map<string, ActionTaken>();
  // Rule ids whose pack chose Redact & Vault. Reassigned wholesale on each
  // bundle load rather than mutated, so a re-initialised runtime cannot inherit
  // a stale membership from the previous bundle.
  let reversibleRuleIndex: ReadonlySet<string> = new Set<string>();

  // Pull the policy bundle once per runtime: cache its policies for action
  // resolution and compose the effective ruleset. When the bundle marks its
  // rules COMPLETE (the user's installed snapshot — enabled packs only), they
  // replace the compiled-in bundled packs entirely, so pack updates and the
  // enable/disable toggle genuinely gate what runs. Otherwise (older caches,
  // or the fail-open fallback) keep the historical composition: bundled packs
  // + pulled rules.
  async function ensureInitialized(): Promise<void> {
    if (initialized) return;
    const bundle = await gateway.getPolicyBundle();
    policies = bundle.policies;
    // Index enabled policies once, first-write-wins so the earliest matching
    // policy takes precedence exactly as the previous `.find` scans did.
    for (const p of policies) {
      if (!p.enabled) continue;
      if ('ruleId' in p.target) {
        if (!ruleActionIndex.has(p.target.ruleId)) ruleActionIndex.set(p.target.ruleId, p.action);
      } else if (!categoryActionIndex.has(p.target.category)) {
        categoryActionIndex.set(p.target.category, p.action);
      }
    }
    // The reversibility axis rides beside the policies rather than on them (see
    // PolicyBundle.reversibleRuleIds). An absent field means an older producer,
    // and the empty set it yields is the pre-existing one-way behaviour.
    reversibleRuleIndex = new Set(bundle.reversibleRuleIds ?? []);
    // The compiled-in bundled packs are already proven safe by the CI
    // adversarial battery on every commit, so they bypass the runtime timing
    // gate entirely — whether they arrive via getLoadedRules() or because the
    // installed snapshot that delivered bundle.rules IS those same bundled
    // packs. Re-checking them at runtime would let a cold-cache pass budget
    // quarantine a legitimate rule (e.g. a secret matcher) on slow hardware,
    // silently disabling detection. Only genuinely pulled/custom-pack rules —
    // those whose probe key is not among the bundled set — reach the gate.
    const bundledProbeKeys = new Set(
      getLoadedRules()
        .map(ruleProbeKey)
        .filter((key): key is string => key !== undefined),
    );
    const incoming = bundle.rules ?? [];
    const ciVerified = incoming.filter((rule) => {
      const key = ruleProbeKey(rule);
      return key !== undefined && bundledProbeKeys.has(key);
    });
    const needsGate = incoming.filter((rule) => !ciVerified.includes(rule));
    // The timing battery decides whether a pattern is safe by driving it into
    // backtracking, so measuring a rule is itself a way to hang on it — the
    // measurement runs on a thread that can be killed, never on this one.
    // Built on first use, so a machine whose verdicts are all cached (the
    // steady state) starts no thread for the gate at all.
    let prober: IsolatedScanner | undefined;
    const gated = await filterUnsafeRules(needsGate, gateway, {
      prober: {
        probe: (rule) => {
          prober ??= createIsolatedScanner({ verified: [], unverified: [] }, opts?.scanIsolation);
          return prober.probe(rule);
        },
      },
    });
    await prober?.close();
    // A rule that clears the timing gate has an EMPIRICAL verdict behind it: it
    // beat one fixed probe battery, which a pattern written against that battery
    // can do while still backtracking forever on real text. So the scan itself
    // runs under a hard, engine-level bound whenever such a rule is in play —
    // and in-process at no added cost when none is (see guarded-scan.ts).
    //
    // Only a REGEX matcher can run without an upper bound. A keyword matcher
    // compiles one fully-escaped literal per keyword, which cannot backtrack
    // whatever the pack author wrote, so a pulled keyword rule runs in-process
    // like a bundled one — a keyword-only custom pack starts no worker at all.
    const verified: Rule[] = bundle.rulesComplete
      ? [...ciVerified]
      : [...getLoadedRules(), ...ciVerified];
    const unverified: Rule[] = [];
    for (const rule of gated) {
      if (rule.matcher.type === 'regex') unverified.push(rule);
      else verified.push(rule);
    }
    rules = [...verified, ...unverified];
    scanner = createGuardedScanner({ verified, unverified }, gateway, opts?.scanIsolation);
    bundleExceptions = bundle.exceptions ?? [];
    initialized = true;
  }

  // The fingerprint key, resolved lazily at most once per runtime (a hook is a
  // short-lived process). undefined = not tried yet; null = unavailable —
  // no dataDir, or a corrupt/unreadable key file, which fails SECURE (no
  // exceptions applied, no ledger rows) rather than minting a replacement key.
  let cachedKey: FingerprintKey | null | undefined;

  // For exception EVALUATION: strictly read-only. A bundle that carries grants
  // implies the key already exists (grants cannot be created without it), so
  // evaluation never mints — a deleted or corrupt key file fails SECURE (no
  // grant applies), never gets silently replaced.
  function keyForEvaluation(): FingerprintKey | null {
    if (cachedKey === undefined) {
      try {
        cachedKey = dataDir ? readFingerprintKey(dataDir) : null;
      } catch {
        cachedKey = null;
      }
    }
    return cachedKey;
  }

  // For the blocked-detections ledger: MAY mint on first use. The first
  // block/redact is the moment the exception feature becomes relevant — a user
  // who never trips enforcement keeps a zero key footprint, while the first
  // block mints the key so its ledger row is approvable. Corruption still
  // fails secure (loadOrCreate throws on corrupt; only absence mints), and a
  // null from a prior read-only miss is upgraded here since absence — not
  // corruption — is the only way that null arises with a dataDir present.
  function keyForLedger(): FingerprintKey | null {
    if (cachedKey === undefined || cachedKey === null) {
      try {
        cachedKey = dataDir ? loadOrCreateFingerprintKey(dataDir) : null;
      } catch {
        cachedKey = null;
      }
    }
    return cachedKey;
  }

  function resolveAction(ruleId: string, category: string): ActionTaken {
    // A per-rule policy — the per-detection Monitor/Warn/Redact/Block assignment
    // the standalone gateway synthesizes from installed_packs.policy_id — wins
    // over the category default, so a detection set to Monitor actually stops
    // enforcing rather than falling through to DEFAULT_ACTIONS (secret → warn).
    // O(1) via the indexes built in ensureInitialized.
    const byRule = ruleActionIndex.get(ruleId);
    if (byRule !== undefined) return byRule;
    const byCategory = categoryActionIndex.get(category);
    if (byCategory !== undefined) return byCategory;
    // category is an arbitrary string; treat the lookup as possibly-missing so the 'log' fallback stays reachable.
    const fallback = (DEFAULT_ACTIONS as Partial<Record<string, ActionTaken>>)[category];
    return fallback ?? 'log';
  }

  // The action that applies to ONE finding: an excepted finding's action is
  // 'allow' — its grant was already consumed — and every other finding resolves
  // through its own rule/category policy. This is per-finding, unlike `decide`'s
  // worst-first collapse across the whole capture: a capture that mixes a
  // blocked secret with a warned code-context match applies 'block' to the
  // former and 'warn' to the latter.
  //
  // The legacy global ceiling is applied HERE so this stays the single
  // definition of the action that actually applied: when it is enabled, 'warn'
  // handling mode floors block/redact to warn. `decide`'s aggregate collapse and
  // the findings audit trail both resolve through this function, so neither can
  // record a stronger action than the capture actually took.
  function actionForFinding(
    finding: MatchResult,
    excepted?: ReadonlySet<MatchResult>,
  ): ActionTaken {
    if (excepted?.has(finding)) return 'allow';
    const action = resolveAction(finding.ruleId, finding.category);
    if (
      ENFORCEMENT_CEILING_ENABLED &&
      policyMode === 'warn' &&
      (action === 'block' || action === 'redact')
    ) {
      return 'warn';
    }
    return action;
  }

  function decide(
    findings: MatchResult[],
    text: string,
    excepted?: ReadonlySet<MatchResult>,
  ): CaptureResult {
    if (findings.length === 0) return { action: 'log', text, findings: [] };

    const actionFor = (finding: MatchResult): ActionTaken => actionForFinding(finding, excepted);

    // `worst` already reflects the legacy global ceiling: actionForFinding caps
    // block/redact to warn when it is enabled, so the collapse inherits the cap
    // and never needs to re-apply it here.
    let worst: ActionTaken = 'log';
    for (const finding of findings) {
      const action = actionFor(finding);
      if (ACTION_PRIORITY.indexOf(action) < ACTION_PRIORITY.indexOf(worst)) worst = action;
    }

    if (worst === 'block') return { action: 'block', text: null, findings };
    if (worst === 'redact') {
      const redactFindings = findings.filter((f) => actionFor(f) === 'redact');
      // The subset whose own detection chose Redact & Vault. A per-finding
      // split, not a per-capture one: a capture mixing a vaulted secret with a
      // one-way-redacted PII match must vault only the first, which is the whole
      // point of moving reversibility onto the per-detection axis.
      //
      // Filtered from redactFindings rather than from `findings`, so a rule
      // assigned Redact & Vault whose finding resolved to some OTHER action
      // (an exception downgraded it to 'allow', a category policy floored it)
      // cannot be vaulted — only a value actually being stripped is ever kept.
      const reversibleFindings = redactFindings.filter((f) => reversibleRuleIndex.has(f.ruleId));
      return {
        action: 'redact',
        text: redact(text, redactFindings),
        findings,
        enforcedFindings: redactFindings,
        reversibleFindings,
      };
    }
    return { action: worst, text, findings };
  }

  // Compute (and memoize per call) the keyed fingerprint of a finding's exact
  // raw match — at most once per finding, shared between exception matching and
  // the blocked-detections ledger.
  function fingerprintOf(
    key: FingerprintKey,
    finding: MatchResult,
    cache: Map<MatchResult, string>,
  ): string {
    let fp = cache.get(finding);
    if (fp === undefined) {
      fp = fingerprintValue(key, finding.rawMatch);
      cache.set(finding, fp);
    }
    return fp;
  }

  // The exception matching step (between scan and the action collapse). Fails
  // SECURE end to end: any error — inside or out — yields "no exceptions
  // applied" and enforcement proceeds as usual. Consumption happens ONCE per
  // unique (ruleId, fingerprint) pair per capture, even when the same value
  // appears in multiple spans; every span of a consumed pair is downgraded.
  async function applyExceptions(
    findings: MatchResult[],
    ctx: ExceptionEvalContext,
    fpCache: Map<MatchResult, string>,
  ): Promise<{ excepted: Set<MatchResult>; exceptionIds: string[] }> {
    const excepted = new Set<MatchResult>();
    const exceptionIds: string[] = [];
    try {
      // Legacy global ceiling (disabled by default). When enabled, 'warn'
      // handling mode blocks/redacts nothing, so there is no enforcement to
      // bypass — evaluating would only burn use budgets.
      if (ENFORCEMENT_CEILING_ENABLED && policyMode === 'warn') return { excepted, exceptionIds };
      const enforced = findings.filter((f) => {
        const action = resolveAction(f.ruleId, f.category);
        return action === 'block' || action === 'redact';
      });
      // Short-circuits, in order: nothing enforced, then no grants at all —
      // the permanent state of most machines, kept at zero added work.
      if (enforced.length === 0 || bundleExceptions.length === 0) {
        return { excepted, exceptionIds };
      }
      const key = keyForEvaluation();
      if (!key) return { excepted, exceptionIds };

      // Grants written under a rotated-away key version never match. Key
      // collisions cannot shadow one another here: uq_exceptions_active
      // guarantees at most ONE active grant per (rule, fingerprint,
      // keyVersion), and the bundle carries active grants only.
      const entries = new Map<string, ExceptionBundleEntry>();
      for (const entry of bundleExceptions) {
        if (entry.keyVersion === key.version) {
          entries.set(`${entry.ruleId}:${entry.valueFingerprint}`, entry);
        }
      }
      if (entries.size === 0) return { excepted, exceptionIds };

      // Group enforced findings by (ruleId, fingerprint) so one consume covers
      // every span of the same value in this capture.
      const groups = new Map<string, MatchResult[]>();
      for (const finding of enforced) {
        const pair = `${finding.ruleId}:${fingerprintOf(key, finding, fpCache)}`;
        const group = groups.get(pair);
        if (group) group.push(finding);
        else groups.set(pair, [finding]);
      }

      const now = Date.now();
      const preAuthorized = new Set(ctx.preAuthorizedGrantIds ?? []);
      for (const [pair, group] of groups) {
        const entry = entries.get(pair);
        if (!entry) continue;
        // A crossing this capture already spent: apply without consuming and
        // without re-checking the budget the crossing just used up.
        if (preAuthorized.has(entry.id)) {
          if (!conditionsMatch(entry.conditions, ctx)) continue;
          for (const finding of group) excepted.add(finding);
          exceptionIds.push(entry.id);
          continue;
        }
        if (!entryIsActive(entry, now) || !conditionsMatch(entry.conditions, ctx)) {
          continue;
        }
        // Fail-secure consume: a throw counts as "does not apply".
        let consumed = false;
        try {
          consumed = await gateway.consumeException(entry.id);
        } catch {
          consumed = false;
        }
        if (!consumed) continue;
        for (const finding of group) excepted.add(finding);
        exceptionIds.push(entry.id);
      }
      return { excepted, exceptionIds };
    } catch {
      // Any evaluation error → no exceptions applied; enforcement proceeds.
      return { excepted: new Set<MatchResult>(), exceptionIds: [] };
    }
  }

  // When the FINAL decision (post-exception) is block/redact, record one
  // blocked-detections ledger row per unique still-enforced (ruleId,
  // fingerprint) pair — the CLI approve flow turns these into grants. Purely
  // best-effort bookkeeping: requires an ALREADY-available fingerprint key and
  // never affects the decision. Returns the recorded references.
  async function recordBlockedDetections(
    decision: CaptureResult,
    excepted: ReadonlySet<MatchResult>,
    ctx: ExceptionEvalContext,
    fpCache: Map<MatchResult, string>,
  ): Promise<BlockedDetectionRef[]> {
    const references: BlockedDetectionRef[] = [];
    try {
      if (decision.action !== 'block' && decision.action !== 'redact') return references;
      const key = keyForLedger();
      if (!key) return references;
      const seen = new Set<string>();
      for (const finding of decision.findings) {
        // The same per-finding resolution the findings write uses, so the ledger
        // and the findings table agree by construction on what was enforced
        // (excepted findings resolve to 'allow' and are skipped here).
        const action = actionForFinding(finding, excepted);
        if (action !== 'block' && action !== 'redact') continue;
        const fp = fingerprintOf(key, finding, fpCache);
        const pair = `${finding.ruleId}:${fp}`;
        if (seen.has(pair)) continue;
        seen.add(pair);
        const reference = randomUUID().replaceAll('-', '').slice(0, 6);
        const maskedValue = maskMatch(finding.rawMatch);
        try {
          await gateway.recordBlockedDetection({
            reference,
            ruleId: finding.ruleId,
            category: finding.category,
            valueFingerprint: fp,
            keyVersion: key.version,
            maskedValue,
            sessionId: ctx.metadata?.sessionId ?? null,
            repo: ctx.metadata?.repo ?? null,
          });
          // The rich ref keeps the adapter's masked preview aligned BY
          // CONSTRUCTION with the ledger row the reference points at — the
          // message can never describe a different value than approve resolves.
          references.push({ reference, ruleId: finding.ruleId, maskedValue });
        } catch {
          // best-effort: a failed ledger write never affects the decision
        }
      }
    } catch {
      // best-effort bookkeeping only
    }
    return references;
  }

  // The shared scan → exception match → decide → ledger pipeline behind both
  // processText and capture.
  async function evaluate(
    text: string,
    context: ScanContext | undefined,
    ctx: ExceptionEvalContext,
  ): Promise<{ decision: CaptureResult; excepted: Set<MatchResult>; exceptionIds: string[] }> {
    try {
      await ensureInitialized();
      // Vault pointers are blanked out of the scanned text first, so no
      // installed rule can ever match inside one (same-length filler keeps
      // every other offset valid against the original text). The shielded text
      // is what crosses into the worker too: "no rule ever sees a pointer" has
      // to hold wherever the engine runs, and the spans stay comparable because
      // the filler preserves every offset.
      // ensureInitialized either assigns `scanner` or throws, so this cannot
      // fire — and it is a guard rather than a second `scan()` call precisely
      // because of that. A fallback arm here would be unreachable code on the
      // one line where the pointer shield has to be applied, i.e. a place for
      // the two paths to drift apart unnoticed. The outer catch owns the
      // impossible case; it must never be an unshielded scan.
      if (!scanner) throw new Error('the runtime initialized without a scanner');
      const shielded = shieldPointers(text);
      const matched = await scanner.scan(shielded.text, context);
      const findings = dropShieldedFindings(matched, shielded.spans);
      const fpCache = new Map<MatchResult, string>();
      const { excepted, exceptionIds } = await applyExceptions(findings, ctx, fpCache);
      const decision = decide(findings, text, excepted);
      const blockedReferences = await recordBlockedDetections(decision, excepted, ctx, fpCache);
      if (blockedReferences.length > 0) decision.blockedReferences = blockedReferences;
      return { decision, excepted, exceptionIds };
    } catch {
      // Fail-open: a scan/policy error must never break the host session.
      return {
        decision: { action: 'log', text, findings: [] },
        excepted: new Set<MatchResult>(),
        exceptionIds: [],
      };
    }
  }

  // `context` scopes appliesTo-tagged rules to the text's language when a file
  // path is known (the worktree scan); hook-path prompts pass none and run the
  // full ruleset.
  async function processText(text: string, context?: ScanContext): Promise<CaptureResult> {
    return (await evaluate(text, context, {})).decision;
  }

  async function capture(input: CaptureInput, opts: CaptureOptions = {}): Promise<CaptureResult> {
    // Added latency is measured from here — the caller is blocked from this
    // line until `capture` returns, and everything between here and the event
    // build below is inspection work the host session waits on. A capture that
    // brought its own `occurredAt` is replaying past work (the transcript
    // backfill, the worktree scan), so it is never timed: its scan duration is
    // latency nobody experienced, and recording it would mix background work
    // into a p50 that answers "what does inspection cost a live session?".
    const timingStartedAt = input.occurredAt === undefined ? startTiming() : undefined;
    const filePath = input.metadata?.filePath;
    const { decision, excepted, exceptionIds } = await evaluate(
      input.text,
      filePath ? { filePath } : undefined,
      {
        sourceTool: input.sourceTool,
        metadata: input.metadata,
        preAuthorizedGrantIds: opts.preAuthorizedGrantIds,
      },
    );
    // 'with-findings' (the historical backfill) only persists messages that
    // actually leaked something, so a 30-day transcript sweep doesn't flood the
    // store with benign events. The live hook path keeps the default 'always'.
    if (opts.persist === 'with-findings' && decision.findings.length === 0) return decision;
    try {
      // Secrets-at-rest: persist the text with EVERY finding's span masked —
      // excepted findings included; an exception changes enforcement, never
      // at-rest hygiene — and keep content_hash of the ORIGINAL so dedup has
      // a stable fingerprint. Only detected spans are masked: content outside
      // them is stored as-is in the local store, protected by file permissions,
      // not encryption (e.g. a keyword rule whose span covers only the key
      // label leaves the value after it in the stored content).
      const contentHash = contentHashOf(input.text);
      const storedContent =
        decision.findings.length > 0 ? redact(input.text, decision.findings) : input.text;
      // Stamp the applied exception ids onto the persisted event so the trail
      // shows WHY an enforced category passed (a declared EventMetadata field).
      // The measurement is read HERE, immediately before the event is built,
      // because the value has to be inside the row being written — so it spans
      // detection, exception resolution and redaction, and stops short of the
      // store write itself. It is therefore a lower bound on what the hook
      // costs end to end, and `EventMetadata.inspectionMs` says so; an absent
      // reading is left absent rather than defaulted.
      const inspectionMs = elapsedMs(timingStartedAt);
      const metadata =
        exceptionIds.length > 0 || inspectionMs !== undefined
          ? {
              ...input.metadata,
              ...(exceptionIds.length > 0 ? { exceptionIds } : {}),
              ...(inspectionMs !== undefined ? { inspectionMs } : {}),
            }
          : input.metadata;
      const event = buildIngestEvent({
        kind: input.kind,
        sourceTool: input.sourceTool,
        content: storedContent,
        contentHash,
        occurredAt: input.occurredAt,
        metadata,
      });
      // At-rest finding identity: only worktree-scan captures (kind ===
      // 'code_change', always carrying a filePath) get a stable finding_key
      // (see finding-key.ts) — a re-scan of the same file reconciles onto the
      // same findings row instead of duplicating it (SqliteFindingsRepository's
      // ON CONFLICT (finding_key) upsert). In-flight captures (prompt/response)
      // are streamed once and never re-scanned, so there is nothing to
      // correlate against and they carry no key. keyForLedger() MAY mint the
      // fingerprint key here on first use — same rationale as
      // recordBlockedDetections below: the first at-rest finding is the moment
      // a stable value fingerprint becomes relevant.
      const isAtRest = input.kind === 'code_change' && filePath !== undefined;
      const findingKeyFingerprintKey = isAtRest ? keyForLedger() : null;
      const findingKeyFpCache = new Map<MatchResult, string>();
      // Mask the real secret here — the raw value never reaches the gateway/DB.
      // Every finding is recorded with the action that actually applied to IT —
      // its own policy resolution, or 'allow' when a grant excepted it — not the
      // capture's collapsed decision, so the findings table stays the one
      // enforcement audit trail.
      const findings: DetectedFindingWithKey[] = decision.findings.map((match) => {
        const maskedMatch = maskMatch(match.rawMatch);
        const findingKey =
          isAtRest && filePath
            ? computeFindingKey({
                ruleId: match.ruleId,
                filePath,
                // The same keyed HMAC fingerprint used for detection
                // exceptions/blocked_detections when a key is available;
                // falls back to the masked match so at-rest findings still get
                // a stable (if weaker) identity on a workspace with no dataDir.
                valueFingerprint: findingKeyFingerprintKey
                  ? fingerprintOf(findingKeyFingerprintKey, match, findingKeyFpCache)
                  : maskedMatch,
              })
            : undefined;
        return {
          id: randomUUID(),
          eventId: event.id,
          ruleId: match.ruleId,
          category: match.category,
          severity: match.severity,
          span: match.span,
          maskedMatch,
          actionTaken: actionForFinding(match, excepted),
          confidence: match.confidence,
          ...(findingKey ? { findingKey } : {}),
        };
      });
      await gateway.recordCapture({ event, findings, dedupe: opts.dedupe });
      // Thread the produced at-rest finding_keys back onto the decision (the
      // scanner's re-scan resolver diffs these against a path's previously-open
      // keys). Only meaningful for at-rest captures — an in-flight capture's
      // findings never carry a findingKey, so mapping would yield [].
      if (isAtRest) {
        decision.findingKeys = findings
          .map((f) => f.findingKey)
          .filter((k): k is string => k !== undefined && k !== null);
      }
    } catch {
      // Fail-open: a persistence failure never changes the enforcement decision.
    }
    return decision;
  }

  // A stable fingerprint of the EFFECTIVE ruleset (bundled packs + pulled bundle
  // rules) — the worktree scanner keys its skip ledger on it, so any rule
  // addition/change/removal invalidates every "already scanned, clean" entry.
  // Hashed over id-sorted full rule content: a rule edit without a version bump
  // still changes the fingerprint. Fail-open toward rescanning: if the bundle
  // pull fails, return a nonce so no stale ledger entry is trusted.
  async function rulesetFingerprint(): Promise<string> {
    try {
      await ensureInitialized();
      const sorted = [...rules].sort((a, b) => a.id.localeCompare(b.id));
      return contentHashOf(JSON.stringify(sorted));
    } catch {
      return `unresolved-${randomUUID()}`;
    }
  }

  // True once a scan lost its worker and every pulled/custom-pack regex rule was
  // dropped for the rest of this process. A caller that records "this input was
  // scanned" against `rulesetFingerprint()` must not do so afterwards: the
  // fingerprint still names the full ruleset, so a clean row written now would
  // suppress a re-read that the dropped rules never got to make.
  function scanIsolationDegraded(): boolean {
    return scanner?.degraded() ?? false;
  }

  async function close(): Promise<void> {
    try {
      // The worker thread must not outlive the runtime that started it — a
      // stray thread would hold the process open past the hook's own exit.
      await scanner?.close();
    } catch {
      // A thread that will not shut down cleanly must not cost the caller its
      // store handle, which is the close that actually matters.
    }
    await gateway.close();
  }

  return { processText, capture, rulesetFingerprint, scanIsolationDegraded, close };
}

// Persistence policy for capture(): 'always' records an event for every call
// (the live hook path, so the activity timeline is complete); 'with-findings'
// records only when something was detected (the historical backfill).
// `dedupe: 'content-hash'` marks the capture as re-runnable bulk ingest so the
// gateway drops content it has already recorded (fresh event ids on a re-run
// would otherwise duplicate rows). Never set it on the live hook path.
export interface CaptureOptions {
  persist?: 'always' | 'with-findings';
  dedupe?: 'content-hash';
  // Grant ids already spent by this capture's own pointer crossing (see
  // ExceptionEvalContext.preAuthorizedGrantIds).
  preAuthorizedGrantIds?: readonly string[];
}

export interface PluginRuntime {
  // Enforcement decision + best-effort blocked-detection bookkeeping (the
  // short-lived approve-flow ledger, when a fingerprint key is available);
  // no event write.
  processText(text: string, context?: ScanContext): Promise<CaptureResult>;
  // Decision + persist (event with masked content + N masked findings).
  capture(input: CaptureInput, opts?: CaptureOptions): Promise<CaptureResult>;
  // Fingerprint of the effective ruleset, for scan-ledger invalidation.
  rulesetFingerprint(): Promise<string>;
  // True once the pulled/custom-pack regex rules were dropped mid-process
  // because a scan lost its worker. Anything keyed on `rulesetFingerprint()`
  // must stop writing once this is true — the fingerprint describes a ruleset
  // that is no longer the one running.
  scanIsolationDegraded(): boolean;
  close(): Promise<void>;
}
