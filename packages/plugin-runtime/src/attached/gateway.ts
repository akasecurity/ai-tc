import type { BlockedDetectionInput, ResolutionInput } from '@akasecurity/persistence';
import { llmCallId, toolCallId } from '@akasecurity/persistence';
import type {
  CaptureRecord,
  DataGateway,
  LocalStoreMaintenance,
  RuleProbeVerdictEntry,
  ScanLedgerEntry,
  ScanLedgerState,
} from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  AuditEventInput,
  ConfigInventoryReport,
  ConfigScanRecord,
  DayActivity,
  DetectionCategory,
  EgressIngestRequest,
  EgressWriteSummary,
  FindingView,
  HealthSummary,
  IngestAck,
  IngestBatch,
  IngestEvent,
  InventoryContext,
  InventoryFacets,
  LlmCallInput,
  Policy,
  PolicyBundle,
  ProjectFilesScan,
  RecordProjectEgressInput,
  ResolvedInventory,
  RuleProbeVerdict,
  SessionTokenReport,
  SimpleDetectionPolicy,
  StorePostureSnapshot,
  ToolCallInput,
  ToolCallInspection,
} from '@akasecurity/schema';
import { actionRank, DEFAULT_ACTIONS, isActionAtLeast, strongerAction } from '@akasecurity/schema';

import { toEgressIngestRequest } from './egress-wire.ts';
import { recordForwardDrops } from './forward-drops.ts';
import type { ForwardPolicy } from './forward-policy.ts';
import { REQUEST_TIMEOUT_MS, withTimeout } from './with-timeout.ts';

/**
 * The subset of the transport this gateway uses. Declared structurally rather
 * than imported so a test can pass a lightweight fake, and so this module keeps
 * no dependency on the package that opens sockets.
 *
 * WRITE-ONLY, plus the posture self-report. There are deliberately no reads:
 * every read is served from the local store, and the credential a machine holds
 * is scoped to the five writes plus the policy bundle and whoami — nothing
 * else. A read added here would be a method that cannot work against the
 * credential this gateway actually holds.
 */
export interface AttachedClient {
  ingestEvents(batch: IngestBatch): Promise<IngestAck>;
  ingestInventory(context: InventoryContext): Promise<ResolvedInventory>;
  // `inspections` is present only for a tool_call carrying detected secrets
  // (see recordToolCalls below); the control plane links each to this event.
  recordAuditEvent(event: AuditEventInput & { inspections?: ToolCallInspection[] }): Promise<void>;
  // The throttled self-report of this machine's local store state (see
  // posture-reporter.ts). The response is unused — whether the promise settles
  // is all the throttle needs.
  reportStorePosture(snapshot: StorePostureSnapshot): Promise<unknown>;
  // One project's egress-recording unit, already projected to the
  // wire-boundary-safe shape by `toEgressIngestRequest`. The response is
  // unused — see recordProjectEgress below for why.
  recordProjectEgress(request: EgressIngestRequest): Promise<unknown>;
}

export interface AttachedDataGatewayDeps {
  /**
   * The inner LOCAL gateway — a StandaloneDataGateway in production. It is the
   * read model and the system of record on the device; the control plane holds the
   * organization's copy.
   *
   * Typed as requiring the full `LocalStoreMaintenance` rather than a
   * `Partial<>`: this composite implements the capability BY DELEGATION, so
   * `hasLocalStoreMaintenance(composite)` answers true, and a partial inner
   * gateway would make that answer a lie — the runtime would call a member
   * that is not there. Requiring it here turns that into a compile error at
   * the one construction site instead of a TypeError inside a hook.
   */
  local: DataGateway & LocalStoreMaintenance;
  client: AttachedClient;
  // Reads the out-of-band-pulled organization policy bundle from the on-disk cache.
  // Null when the cache is cold (no pull yet) — the local bundle then stands
  // alone, which is exactly standalone behaviour.
  readCachedBundle: () => Promise<PolicyBundle | null>;
  /** Budgets + the two-level circuit breaker guarding every forward. */
  forward: ForwardPolicy;
  /**
   * Where the sibling state files live — the same `~/.aka/data` the breaker and
   * the sync marker use.
   *
   * REQUIRED rather than optional, for the reason the `local` member above is:
   * an optional one would let a construction site omit it and silently stop
   * recording batch drops, which is the exact invisibility `forward-drops.ts`
   * exists to end. A missing dataDir is a compile error at the construction
   * site instead of a machine that quietly loses events.
   */
  dataDir: string;
  // The throttled posture self-report, split into its two phases
  // (posture-reporter.ts). `prepare` is everything LOCAL — throttle, attempt
  // stamp, and the blocking store read; `send` is the bounded network post.
  // `ensureInventory` runs both strictly AFTER the inventory call has
  // settled — see the ordering rationale there. Optional: omitted entirely
  // in tests/configurations that don't need it, and `ensureInventory` no-ops
  // when it's absent.
  posture?: {
    prepare(): Promise<StorePostureSnapshot | null>;
    send(snapshot: StorePostureSnapshot): Promise<void>;
  };
}

// WHY EVERY COMPARISON BELOW EXISTS: the cached organization bundle is read from
// disk with no signature or provenance check — so a compromised control plane or
// a tampered cache file must not be able to use a policy to REDUCE enforcement,
// either below the compiled-in default for its category or below what the
// user's own local bundle already enforces. Raising is unaffected.
//
// The ORDERING those comparisons read is `@akasecurity/schema`'s single ladder
// (`actionRank` / `isActionAtLeast` / `strongerAction`), never a rank map of
// this module's own. A private copy stood here, and a copy is what drifts: the
// day an archetype's action moves, a stale ladder goes on ranking `redact`
// under `warn` and the clamp licenses exactly the downgrade it exists to refuse.

/**
 * The stronger of two actions; either may be absent.
 *
 * A thin null-tolerant wrapper over the schema's `strongerAction`, and the
 * absence is the whole reason it exists: "no floor at all" and "the weakest
 * floor" are different answers here — an unresolvable rule id gets the first —
 * and spelling the first as `'allow'` would clamp against a floor nobody set.
 */
function strongerOf(a: ActionTaken | null, b: ActionTaken | null): ActionTaken | null {
  if (a === null) return b;
  if (b === null) return a;
  return strongerAction(a, b);
}

// ruleId -> category for every rule the gateway can resolve. A policy whose
// category can't be resolved this way is left unclamped rather than guessed at,
// so every source that can name a rule id has to be represented here — a rule
// missing from this map has NO floor at all.
//
// THREE TIERS, WEAKEST TRUST FIRST, because later writes win an id collision:
//
//   1. `wireRules` — the untrusted organization bundle. Seeded first so it still
//      supplies a floor for marketplace rule ids nothing else has heard of,
//      while never overriding a tier below it.
//   2. `localRules` — the device's own installed packs. More trustworthy than
//      the wire (nothing remote wrote them) and less than compiled-in. Without
//      them a locally installed marketplace rule resolves to no category, so a
//      a remote `{ ruleId, action: 'allow' }` targeting it passes UNCLAMPED.
//   3. `bundledDetections()` — compiled into this build, so it anchors the
//      clamp whatever anyone else claims.
//
// Tier 1 losing to tiers 2 and 3 is the load-bearing part: the wire rules come
// from the SAME unsigned bundle this clamp exists to defend against, so a
// tampered bundle must not be able to redeclare a known rule's category to pick
// its own floor — e.g. moving `secrets/aws-access-key` from `secret` to
// `code_context` (floor warn -> log) and pairing that with a ruleId-targeted
// `allow` policy to slip a real secret past at only 'log'.
//
// The two arrays are separate PARAMETERS rather than one pre-concatenated list
// on purpose: the order is a security property, and a single argument would let
// a call site pass `[...local, ...wire]` — which reads just as naturally and
// silently inverts tiers 1 and 2.
function ruleCategoryMap(
  wireRules: PolicyBundle['rules'],
  localRules: PolicyBundle['rules'],
): Map<string, DetectionCategory> {
  const map = new Map<string, DetectionCategory>();
  for (const rule of wireRules ?? []) map.set(rule.id, rule.category);
  for (const rule of localRules ?? []) map.set(rule.id, rule.category);
  for (const pack of bundledDetections()) {
    for (const rule of pack.rules) map.set(rule.id, rule.category);
  }
  return map;
}

/**
 * The key a policy resolves under, matching how the runtime indexes them.
 *
 * The runtime keeps ruleId-targeted and category-targeted policies in two
 * SEPARATE indexes and consults the rule one first, so the two namespaces must
 * stay distinct here too — collapsing them would let a category policy and a
 * ruleId policy contend for one slot and silently drop one.
 */
function policyKey(policy: Policy): string {
  return 'ruleId' in policy.target
    ? `rule:${policy.target.ruleId}`
    : `category:${policy.target.category}`;
}

/** The compiled-in floor for a policy's resolved category, or null if unknown. */
function floorFor(
  policy: Policy,
  categoryByRuleId: Map<string, DetectionCategory>,
): ActionTaken | null {
  const category =
    'category' in policy.target
      ? policy.target.category
      : categoryByRuleId.get(policy.target.ruleId);
  return category === undefined ? null : DEFAULT_ACTIONS[category];
}

/**
 * Merge the cached TENANT bundle's policies over the LOCAL bundle's, raise-only.
 *
 * ⚠ This is the one place in E1 where a correct-looking merge silently produces
 * WEAKER enforcement, because of how the runtime consumes the result. It indexes
 * policies FIRST-WRITE-WINS (plugin-sdk `runtime.ts` ensureInitialized: it walks
 * `bundle.policies` in order and only `set`s a key it does not already have).
 * So a naive `[...remote, ...local]` concatenation hands the remote side precedence
 * for every contended target — and a remote policy that is weaker than the
 * user's LOCAL policy but still at or above the compiled-in DEFAULT_ACTIONS
 * floor passes a clamp written against that floor while quietly downgrading
 * real enforcement. Concretely: local says `block` for `secret`, the default
 * floor is `warn`, the remote side says `warn` — floor-clamping alone sees nothing
 * wrong, and the device stops blocking secrets.
 *
 * So the merge does not rely on order at all. It resolves each contended target
 * to the STRONGER of the two sides and emits exactly ONE policy per key, which
 * makes the result correct under first-write-wins whatever order it is read in.
 * The floor clamp is still applied on top, for targets only the remote side declares.
 *
 * ⚠ AND THE SAME BUG REACHES ACROSS THE TWO NAMESPACES, where "contended
 * target" does not model it. `policyKey` keeps `rule:` and `category:` distinct
 * because the runtime keeps two indexes — but it does not treat them as
 * independent: `resolveAction` consults `ruleActionIndex` FIRST and returns
 * unconditionally, so a ruleId policy outranks the category policy that would
 * otherwise cover that rule. Two policies on different keys therefore never
 * meet in the comparison below while one still overrides the other in practice:
 * local `{ category: 'secret', action: 'block' }` + remote
 * `{ ruleId: 'aka.secret.aws-access-key', action: 'allow' }` both survive, and
 * the device stops blocking AWS keys.
 *
 * The compiled-in floor cannot catch that on its own, and not by accident:
 * DEFAULT_ACTIONS is derived from `severityFloorPolicy`, which only ever returns
 * 'warn' or 'monitor'. The floor is NEVER 'redact' or 'block', so every local
 * block/redact policy sits strictly above it and a floor-only clamp is blind to
 * exactly the strongest enforcement the user has. So a remote ruleId policy is
 * clamped to the stronger of the compiled-in floor and whatever the LOCAL
 * bundle's category policy enforces for that rule's category — the raise-only
 * rule stated against what the device EFFECTIVELY enforces, not against the one
 * key that happens to match.
 *
 * Disabled policies are carried through untouched, after the merged set: the
 * runtime skips them when indexing, so they cannot affect resolution, and
 * dropping them would silently discard state the user can re-enable.
 */
function mergeRaiseOnly(
  localPolicies: Policy[],
  remotePolicies: Policy[],
  categoryByRuleId: Map<string, DetectionCategory>,
): Policy[] {
  const merged = new Map<string, Policy>();
  const disabled: Policy[] = [];

  // What the TENANT enforces per CATEGORY, already clamped to the compiled-in
  // floor. Computed before either loop so no ordering within either side can
  // change it, and the exact mirror of `localCategoryAction` below: each side's
  // category policies floor the OTHER side's ruleId policies, because a ruleId
  // policy is the one that wins at resolution time and so is the one able to
  // undercut a category policy sitting on a different key.
  const remoteCategoryAction = new Map<DetectionCategory, ActionTaken>();
  for (const policy of remotePolicies) {
    if (!policy.enabled) continue;
    if (!('category' in policy.target)) continue;
    // First-write-wins, matching how the runtime would index these.
    if (remoteCategoryAction.has(policy.target.category)) continue;
    const floor = floorFor(policy, categoryByRuleId);
    remoteCategoryAction.set(
      policy.target.category,
      floor !== null && !isActionAtLeast(policy.action, floor) ? floor : policy.action,
    );
  }

  // Local first: it is the trusted side, and first-write-wins within one side
  // reproduces the runtime's own precedence for duplicate targets.
  for (const policy of localPolicies) {
    if (!policy.enabled) {
      disabled.push(policy);
      continue;
    }
    const key = policyKey(policy);
    if (merged.has(key)) continue;
    // Raise a local ruleId policy to whatever the control plane enforces for that
    // rule's category. Without this, every enabled installed pack the user
    // never assigned a policy to — `installed_packs.policy_id` NULL, which
    // `policyIdToAction` coalesces to Monitor, i.e. 'log' — emits a ruleId
    // policy on a key the remote category policy never contends for, and
    // wins at resolution. The device's own untouched packs would silently
    // reduce the remote `secret -> block` to log-only.
    //
    // A local policy already STRONGER than the remote one is left exactly as it
    // is: raising is always allowed, and clamping it down to the remote one's
    // action would be this same bug reversed. Category-targeted local policies
    // need nothing here — they share a key with the remote one and are settled by
    // the stronger-wins comparison below.
    let remoteFloor: ActionTaken | null = null;
    if ('ruleId' in policy.target) {
      const category = categoryByRuleId.get(policy.target.ruleId);
      // An unresolvable ruleId gets no floor rather than a guessed one — same
      // rule as `floorFor`.
      if (category !== undefined) remoteFloor = remoteCategoryAction.get(category) ?? null;
    }
    merged.set(
      key,
      remoteFloor !== null && !isActionAtLeast(policy.action, remoteFloor)
        ? { ...policy, action: remoteFloor }
        : policy,
    );
  }

  // What the LOCAL bundle enforces per category, snapshotted while `merged`
  // still holds local policies ONLY. Raise-only is defined against the local
  // bundle, so a remote policy folded in below must never become another
  // policy's floor — and reading this out of `merged` inside the loop would let
  // exactly that happen, depending on array order.
  const localCategoryAction = new Map<DetectionCategory, ActionTaken>();
  for (const policy of merged.values()) {
    if ('category' in policy.target) localCategoryAction.set(policy.target.category, policy.action);
  }

  for (const policy of remotePolicies) {
    if (!policy.enabled) {
      disabled.push(policy);
      continue;
    }
    const key = policyKey(policy);
    // Clamp the remote policy to the compiled-in floor first — this is what
    // covers a target the local bundle never declared.
    const floor = floorFor(policy, categoryByRuleId);
    // …then raise that floor to whatever the local bundle enforces for the
    // rule's CATEGORY. Only ruleId policies need this: they are the side that
    // wins at resolution time, so they are the side that can override a
    // category policy sitting on a different key. A category policy is already
    // covered by the contended-key comparison below, and a ruleId whose
    // category cannot be resolved gets no local floor rather than a guessed one
    // — same rule as `floorFor`.
    let localFloor: ActionTaken | null = null;
    if ('ruleId' in policy.target) {
      const category = categoryByRuleId.get(policy.target.ruleId);
      if (category !== undefined) localFloor = localCategoryAction.get(category) ?? null;
    }
    const effectiveFloor = strongerOf(floor, localFloor);
    const clamped =
      effectiveFloor !== null && !isActionAtLeast(policy.action, effectiveFloor)
        ? { ...policy, action: effectiveFloor }
        : policy;

    const existing = merged.get(key);
    if (existing === undefined) {
      merged.set(key, clamped);
      continue;
    }
    // Contended target: the STRONGER side wins. This is the raise-only rule
    // stated against the local policy rather than against the default floor,
    // which is the half a floor-only clamp misses.
    if (actionRank(clamped.action) > actionRank(existing.action)) {
      merged.set(key, clamped);
    }
  }

  return [...merged.values(), ...disabled];
}

/**
 * Attached mode: the plugin wired to a control plane, LOCAL-FIRST.
 *
 * This is a decorator over the OSS StandaloneDataGateway, not a replacement for
 * it. Every read and every device-local ledger is served by the inner local
 * gateway, so the device keeps working exactly as standalone does when the
 * control plane is slow, unreachable, or refusing the credential. Every write lands locally
 * FIRST and is then forwarded to the control plane as the organization's copy — bounded,
 * budgeted and breaker-guarded.
 *
 * A FAILED forward is no longer dropped, and this comment used to say it was.
 * It now leaves the row unstamped and the outbox drain offers it again on a
 * later pass. The reason the old stance existed is still worth carrying:
 * `Event.content` is raw prompt/tool text. What makes retaining it acceptable is
 * that the text is ALREADY at rest here — recordCapture writes it on every
 * machine, attached or not — so a queue changes how long delivery may be owed
 * rather than whether plaintext sits on disk, and the deferred send is behind
 * its own consent, whose copy says exactly that.
 *
 * There is still no SPOOL FILE: the queue is `synced_at` on the row that was
 * already written, so nothing is copied anywhere to enqueue it.
 *
 * `getPolicyBundle` composes the local bundle with the out-of-band-pulled
 * control-plane bundle, raise-only — see mergeRaiseOnly.
 */
export class AttachedDataGateway implements DataGateway, LocalStoreMaintenance {
  /**
   * The control plane's OWN resolution of this session's inventory, captured by
   * ensureInventory. Null until the first successful forward — and it stays
   * null for the whole session when the control plane is unreachable, which is fine:
   * reKeyForForward then leaves the event's ids alone and the control plane resolves
   * what it can from the descriptors it already has.
   */
  private remoteInventory: ResolvedInventory | null = null;

  constructor(private readonly deps: AttachedDataGatewayDeps) {}

  // ---------------------------------------------------------------------
  // Writes: local first, then forward.
  // ---------------------------------------------------------------------

  async recordCapture(record: CaptureRecord): Promise<void> {
    // Local is authoritative and must not be skipped or reordered: the findings
    // it writes are what the device's own /health, /audit and exception flows
    // read, and what the posture channel measures.
    await this.deps.local.recordCapture(record);
    // ONLY the event crosses; `record.findings` stays on this machine. There is
    // no field on `IngestBatch`/`Event` that could carry them, and that is the
    // contract rather than an oversight: the plane re-derives its own findings
    // from `Event.content`, so the two sides agree on what was detected without
    // this machine's finding rows having to be trusted or transported.
    //
    // The asymmetry with `recordToolCalls` — which goes out of its way to carry
    // `inspections` — is real and follows from the same rule: a tool call's
    // detected secrets are already MASKED and its target is not re-scannable
    // from the audit event, so there the finding row is the only way the
    // information survives. Here the content itself travels.
    //
    // The consequence to know rather than discover: the posture channel's
    // `findingsTotal` is measured from the LOCAL store, so it counts what this
    // machine detected, not what the plane derived. Those numbers are allowed
    // to differ and are not a reconciliation signal.
    // Decision path: a hook is blocked on this, so it takes the tighter budget.
    const forwarded = await this.deps.forward.run(
      () =>
        this.deps.client.ingestEvents({
          events: [record.event],
          ...(record.dedupe ? { dedupe: record.dedupe } : {}),
        }),
      { decisionPath: true },
    );
    // Delivered ⇒ stamp the row, so the outbox does not offer it again.
    //
    // Every other outcome — timeout, refusal, breaker-open — leaves `synced_at`
    // NULL, which IS the queue: the row stays outstanding and a later drain
    // picks it up. That is the whole of the reversal of G8's no-outbox rule, and
    // it needs no spool file, because the event is already on disk in
    // `audit_events` and always was. What changes is that the local store now
    // records whether the organization's copy was made, not just what this
    // machine saw.
    //
    // `ok` ALONE IS NOT DELIVERY. It says the call completed and the body parsed
    // as an `IngestAck`; the ack itself says what the plane did with the event.
    // `{accepted: 1, duplicates: 0}` and `{accepted: 0, duplicates: 1}` both
    // mean it has the row — a duplicate is the id-dedup recognising a resend,
    // which is a delivery, not a loss. `{accepted: 0, duplicates: 0}` is a 200
    // that took nothing, and stamping on it would remove the row from the
    // outbox for ever.
    //
    // Today's backend cannot produce that for a one-event batch: every return in
    // its ingest repository keeps `accepted + duplicates` equal to the batch
    // size. But that is a server-side invariant the WIRE contract does not
    // express — `IngestAck` constrains both fields only to be non-negative — and
    // this plugin talks to deployments it does not ship. So it is read rather
    // than assumed, and the unread case errs the way everything else on this
    // path errs: toward a redundant resend the receiver's id-dedup absorbs,
    // never toward a row silently dropped from what is owed.
    //
    // The stamp is deliberately NOT part of the local write's transaction. The
    // write is authoritative and must commit whatever the network does; only
    // after the forward settles is there anything true to record. A stamp lost
    // between the two costs one redundant resend, which the receiver's id-dedup
    // absorbs — `captureWireId` derives the wire id from the same tuple the row
    // is keyed on, so the retry arrives under the id the first attempt used.
    if (forwarded.ok && forwarded.value.accepted + forwarded.value.duplicates > 0) {
      this.deps.local.markCaptureDelivered(record.event, Date.now());
    }
  }

  async ensureInventory(ctx: InventoryContext): Promise<ResolvedInventory> {
    // Ordering rule: the FUNCTIONAL call first, telemetry strictly after it
    // settles. Inventory is what the session actually needs — it resolves
    // hostId/projectId — while posture is best-effort telemetry, so posture
    // must never be positioned where its cost can land on inventory. Each
    // step swallows its own failure.
    //
    // The ordering is load-bearing against a specific mechanism, and two
    // earlier shapes each got one half wrong. withTimeout is a Promise.race
    // against a setTimeout, so it can only bound work that yields — and the
    // posture read runs node:sqlite .all()/.get() SYNCHRONOUSLY on the event
    // loop (see the non-preemptible note in posture-snapshot.ts). RACING the
    // arms let that scan starve the inventory timer. Running the scan FIRST
    // fixed the starvation but inverted the priority. Posture AFTER inventory
    // settles fixes both at once.
    //
    // Under local-first the functional half is now the LOCAL resolution, which
    // is what mints the ids the session uses. The forward carries those SAME
    // ids (see below), so the forwarded copy shares the device's id space.
    const resolved = await this.deps.local.ensureInventory(ctx);

    // THE TWO ID SPACES. `InventoryContext` carries no ids at all — it is pure
    // descriptors (host/harness/project) — and each side content-addresses them
    // itself. The local store keys on the descriptors alone; the control plane keys
    // TENANT-SCOPED. So the same laptop resolves to a different hostId on each
    // side, by construction, and neither is wrong.
    //
    // The device's own ids are authoritative for everything local, so `resolved`
    // (the local ones) is what this returns and what the session stamps on its
    // root. But an audit event FORWARDED carrying local ids would reference
    // inventory rows the control plane does not have, orphaning every forwarded root
    // against an inventory it cannot join. So the control plane's own resolution
    // is captured here and used to re-key events on their way out — see
    // reKeyForForward. Nothing about the local write is affected.
    //
    // The result also carries WHY a forward failed (a 403 refusal is not a
    // timeout), and nothing here acts on it: an unresolved remote inventory
    // has one behaviour whatever the cause — leave the event's ids alone and
    // let the control plane resolve what it can from the descriptors. The reason is
    // recorded by the policy itself, into the file `/aka:status` reads, which
    // is where a human sees it.
    const remote = await this.deps.forward.run(() => this.deps.client.ingestInventory(ctx));
    // UNCONDITIONAL, including on failure. One gateway instance serves many
    // sessions — `reconcileHistory` walks them in a loop — so keeping the
    // previous session's resolution when this one's forward fails would stamp
    // THIS session's forwarded events with the PREVIOUS session's host,
    // harness and project. That insert succeeds, silently attributing a whole
    // session's activity to the wrong repository, which is worse than not
    // forwarding it. Clearing is the only safe failure mode.
    //
    // This line and `reKeyForForward`'s null branch are a PAIR, and clearing is
    // only safe because that branch now OMITS the three ids rather than sending
    // the local ones. Retaining was correct while it still sent them — the
    // the control plane rejects a local id, so a cleared resolution orphaned the whole
    // session, which is why this guard read `if (remote.ok)` on its own branch.
    // Change one of the two and this comment is the warning that the other
    // needs the same edit.
    //
    // `ok: false` covers a refusal, a timeout, a transport error and an open
    // breaker alike: an unresolved remote inventory has ONE behaviour whatever
    // the cause, and the cause is recorded by the forward policy for
    // `/aka:status` rather than steering anything here.
    this.remoteInventory = remote.ok ? remote.value : null;

    const snapshot = await (async (): Promise<StorePostureSnapshot | null> => {
      try {
        return (await this.deps.posture?.prepare()) ?? null;
      } catch {
        // posture is best-effort telemetry; the session must never notice
        return null;
      }
    })();
    if (snapshot) {
      try {
        await withTimeout(
          this.deps.posture?.send(snapshot) ?? Promise.resolve(),
          REQUEST_TIMEOUT_MS,
        );
      } catch {
        // posture is best-effort telemetry; the session must never notice
      }
    }
    return resolved;
  }

  // The id is minted CLIENT-side and stored verbatim: the control plane does NOT
  // re-key it. `pgAuditValues` writes `id: event.id` and carries tenancy in
  // its own scoping columns, so the device and the forwarded copy
  // share one id space — which is what makes a re-post idempotent at all.
  //
  // Re-posts collapse via `onConflictDoUpdate` on the `id` PK, guarded by
  // `setWhere eventType = 'session'` (NOT onConflictDoNothing). That guard is
  // what makes an attached retry safe: a capture-stubbed session row can still
  // be HEALED by the authoritative root, while a duplicate non-session event —
  // a retried tool_call, exactly this path — can never stomp a populated row.
  async recordAuditEvent(
    event: AuditEventInput & { inspections?: ToolCallInspection[] },
  ): Promise<void> {
    await this.deps.local.recordAuditEvent(event);
    const forwarded = await this.deps.forward.run(() =>
      this.deps.client.recordAuditEvent(reKeyForForward(event, this.remoteInventory)),
    );
    // The stamp is outside the local write's transaction, for the reason
    // `recordCapture` gives: the write is authoritative and commits whatever the
    // network does; only once the forward settles is there anything true to
    // record. `recordAuditEvent` resolves void, so `ok` IS the settlement — the
    // client throws on any non-2xx and `run` converts that to `ok: false`.
    if (forwarded.ok) this.deps.local.markAuditEventsDelivered([event], Date.now());
  }

  // Attached `llm_call` is written locally by the inner gateway, then routed to
  // the control plane through the existing `recordAuditEvent` ingest (no dedicated
  // client method yet) by pre-building the audit event from the natural key.
  // The forward goes DIRECTLY to the client rather than through this.recordAuditEvent,
  // which would write the event to the local store a second time.
  async recordLlmCall(input: LlmCallInput): Promise<void> {
    await this.deps.local.recordLlmCall(input);
    // Built ONCE and used for both the wire and the stamp. Two calls to
    // `llmAuditEvent` would be two derivations of the same id, which is the
    // drift `markAuditEventsDelivered` takes the event rather than an id to
    // prevent.
    const event = llmAuditEvent(input);
    const forwarded = await this.deps.forward.run(() =>
      this.deps.client.recordAuditEvent(reKeyForForward(event, this.remoteInventory)),
    );
    if (forwarded.ok) this.deps.local.markAuditEventsDelivered([event], Date.now());
  }

  /**
   * Forward one batch, item by item, under ONE aggregate deadline.
   *
   * Per-item budgets bound each request and nothing bounded their sum — see
   * BATCH_FORWARD_BUDGET_MS. When the deadline passes the remainder is dropped
   * rather than sent: the local write has already succeeded, so every caller
   * has a correct result to return, and a drop is the outcome this path is
   * built to accept (G8) where a blown hook timeout is not.
   *
   * Serial rather than concurrent on purpose. Firing N requests at once would
   * trade a latency problem for a burst the plane's own per-key rate limiting
   * would answer with the refusals the breaker then counts.
   *
   * WHAT IS DROPPED IS COUNTED. Every other forward failure ends in
   * `ForwardPolicy.run`'s catch and moves the breaker's file, which is what
   * lets status call the forward unhealthy; this path returns BEFORE `run` is
   * reached, so without the tally in `forward-drops.ts` a slow-but-answering
   * plane produces no failures, keeps the breaker closed, renders a healthy
   * block, and discards the tail of every batch indefinitely.
   */
  private async forwardBatch<T>(
    inputs: readonly T[],
    toEvent: (input: T) => AuditEventInput & { inspections?: ToolCallInspection[] },
  ): Promise<void> {
    const deadline = Date.now() + BATCH_FORWARD_BUDGET_MS;
    // WHAT LANDED IS STAMPED, and stamped once for the whole batch rather than
    // per item: `markSynced` takes the write lock for the set, and a serial loop
    // would take and release it per row on the store's most numerous table. NOT
    // because a hook is waiting — BATCH_FORWARD_BUDGET_MS's docblock retracts
    // that claim explicitly, and this path runs in the detached reconcile child.
    // What it buys is a shorter lock hold against the hooks writing CONCURRENTLY
    // with that child. Accumulated rather than stamped inline because
    // both exits below must settle it — the deadline exit especially, since a
    // batch that drops its tail still delivered its head, and returning without
    // stamping would leave exactly the rows that DID arrive reading as owed.
    const delivered: AuditEventInput[] = [];
    try {
      for (let i = 0; i < inputs.length; i += 1) {
        const now = Date.now();
        if (now >= deadline) {
          // The remainder, not one item: everything from here on is discarded.
          recordForwardDrops(this.deps.dataDir, inputs.length - i, now);
          return;
        }
        const input = inputs[i] as T;
        // Built once per item, then shared by the wire and the stamp — see
        // recordLlmCall for why a second derivation is the thing to avoid.
        const event = toEvent(input);
        const forwarded = await this.deps.forward.run(() =>
          this.deps.client.recordAuditEvent(reKeyForForward(event, this.remoteInventory)),
        );
        if (forwarded.ok) delivered.push(event);
      }
    } finally {
      // `finally`, not a line before each exit: the deadline path RETURNS from
      // inside the try, and a stamp after the loop would be skipped by exactly
      // that return — leaving the rows that DID arrive reading as owed, on the
      // slow-plane machine this all exists for.
      //
      // Caught, because this is now the only call on the path the "never throws"
      // argument does not cover. `forward.run` is contracted not to throw and
      // `toEvent`/`reKeyForForward` sit inside the try; a throw HERE would
      // convert both exits — the deadline return included — into a rejection out
      // of `recordLlmCalls`/`recordToolCalls`, which the reconciler reads as a
      // failed local pass and drops. `deps.local` is typed as the interface, and
      // `LocalStoreMaintenance.markAuditEventsDelivered` promises that it stamps,
      // not that it swallows, so the guarantee has to be structural here rather
      // than inherited from today's implementation.
      try {
        this.deps.local.markAuditEventsDelivered(delivered, Date.now());
      } catch {
        // A lost stamp costs a redundant resend the receiver's id-dedup absorbs.
        // Breaking the pass costs the whole batch.
      }
    }
  }

  // Delegated as a BATCH rather than looped over recordLlmCall: the inner
  // gateway may write the whole batch in one local transaction, and looping
  // here would replace that with N separate local writes.
  async recordLlmCalls(inputs: readonly LlmCallInput[]): Promise<void> {
    await this.deps.local.recordLlmCalls(inputs);
    await this.forwardBatch(inputs, (input) => llmAuditEvent(input));
  }

  // `input.inspections` (secrets detected client-side in the tool's masked
  // target) ride along on the request's `inspections` field — the control plane
  // persists each as an inspection_findings row linked to this audit event
  // (see RecordAuditEventRequest in @akasecurity/schema). The masked
  // `target` already rides `input.attributes`, so no raw secret leaks either
  // way — this only stops the FINDING row itself from being dropped.
  async recordToolCalls(inputs: readonly ToolCallInput[]): Promise<void> {
    await this.deps.local.recordToolCalls(inputs);
    await this.forwardBatch(inputs, (input) => toolAuditEvent(input));
  }

  // Forwarded as a `config_scan` audit event: there is no dedicated
  // config-scan ingest endpoint, and the audit-event door is the one the
  // control plane already opens for client-minted, idempotent records.
  //
  // ONLY `scanEvent` CROSSES, and unlike `recordCapture` the plane cannot
  // re-derive the rest. A `ConfigScanRecord` is four things committed together
  // locally — the inventory `items`, this audit event, and the posture
  // `definitions`/`findings` that reference it — and three of them stay on the
  // device. Say that plainly rather than let the asymmetry with `recordCapture`
  // read as the same argument: there, findings are omitted BECAUSE the plane
  // re-derives them from `Event.content`; here there is no content to re-derive
  // from, so what is omitted is simply not sent.
  //
  // That is the wire contract as it stands rather than an oversight to patch
  // here. `items` has no route at all, and `RecordAuditEventRequest.inspections`
  // is documented as tool-call findings — widening it to carry config-scan
  // findings is an egress change (a posture finding's `maskedMatch` holds the
  // matched command) and a decision about what an attached deployment is
  // entitled to, not a bug fix. An attached machine's config posture therefore
  // reaches the plane as the event only; the dashboard's own view of it is the
  // local store.
  async recordConfigScan(record: ConfigScanRecord): Promise<void> {
    await this.deps.local.recordConfigScan(record);
    const forwarded = await this.deps.forward.run(() =>
      this.deps.client.recordAuditEvent(reKeyForForward(record.scanEvent, this.remoteInventory)),
    );
    // Stamped like the other three, though `config_scan` is in NEITHER drain's
    // type list today, so no read counts it and nothing re-offers it. That is
    // exactly why it is stamped: the rule this class follows is that the write
    // site records what was delivered and the READ decides what it counts, and a
    // call site exempted because it happens to be inert is the one that reads as
    // owed for ever on the day its type joins a lane.
    if (forwarded.ok) this.deps.local.markAuditEventsDelivered([record.scanEvent], Date.now());
  }

  async recordBlockedDetection(entry: BlockedDetectionInput): Promise<void> {
    return this.deps.local.recordBlockedDetection(entry);
  }

  /**
   * Local write first, forward second, LOCAL summary returned.
   *
   * The scanner reads a throw as a FAILED WRITE and withholds its ledger
   * commit, so the local write happens strictly first and its result — never
   * a server-derived one — is what the caller gets back. The forward is
   * built through `toEgressIngestRequest`, the one place that projects the
   * payload onto the wire-boundary-safe shape (no snippet, hashed
   * projectKey), and its result is discarded: `forward.run` never throws or
   * rejects, so there is nothing here to act on.
   */
  async recordProjectEgress(input: RecordProjectEgressInput): Promise<EgressWriteSummary> {
    const summary = await this.deps.local.recordProjectEgress(input);
    await this.deps.forward.run(() =>
      this.deps.client.recordProjectEgress(toEgressIngestRequest(input)),
    );
    return summary;
  }

  // ---------------------------------------------------------------------
  // Reads and device-local ledgers: pure delegation.
  // ---------------------------------------------------------------------

  async configInventoryReport(): Promise<ConfigInventoryReport> {
    return this.deps.local.configInventoryReport();
  }

  async readSessionProvider(sessionId: string): Promise<string | undefined> {
    return this.deps.local.readSessionProvider(sessionId);
  }

  async facets(): Promise<InventoryFacets> {
    return this.deps.local.facets();
  }

  /**
   * Delegated UNMODIFIED — including its refusals.
   *
   * This is a fail-secure boundary: it decides whether an approved exception
   * lets a blocked action through. Under local-first the local store owns the
   * exception ledger, so the honest answer is whatever it says; wrapping this
   * in a fallback (`catch { return true }`, or defaulting on a timeout) would
   * turn a store error into a granted bypass. If the inner gateway rejects,
   * this rejects, and the runtime's own handling decides — which is asserted
   * end-to-end through runtime.capture rather than here.
   */
  async consumeException(id: string): Promise<boolean> {
    return this.deps.local.consumeException(id);
  }

  async recentFindings(opts?: { limit?: number }): Promise<FindingView[]> {
    return this.deps.local.recentFindings(opts);
  }

  async healthSummary(): Promise<HealthSummary> {
    return this.deps.local.healthSummary();
  }

  async activityByDay(days?: number): Promise<DayActivity[]> {
    return this.deps.local.activityByDay(days);
  }

  async tokenReports(): Promise<SessionTokenReport[]> {
    return this.deps.local.tokenReports();
  }

  async knownContentHashes(): Promise<Set<string>> {
    return this.deps.local.knownContentHashes();
  }

  async scanLedger(rulesetHash: string): Promise<Map<string, ScanLedgerState>> {
    return this.deps.local.scanLedger(rulesetHash);
  }

  async recordScanned(entries: ScanLedgerEntry[]): Promise<void> {
    return this.deps.local.recordScanned(entries);
  }

  async getRuleProbeVerdict(ruleKey: string): Promise<RuleProbeVerdictEntry | undefined> {
    return this.deps.local.getRuleProbeVerdict(ruleKey);
  }

  async setRuleProbeVerdict(
    ruleKey: string,
    verdict: RuleProbeVerdict,
    worstProbeMs: number,
  ): Promise<void> {
    return this.deps.local.setRuleProbeVerdict(ruleKey, verdict, worstProbeMs);
  }

  async openAtRestKeysForPath(path: string): Promise<string[]> {
    return this.deps.local.openAtRestKeysForPath(path);
  }

  async resolvedAtRestKeysForPath(path: string): Promise<string[]> {
    return this.deps.local.resolvedAtRestKeysForPath(path);
  }

  async insertResolution(input: ResolutionInput): Promise<void> {
    return this.deps.local.insertResolution(input);
  }

  async close(): Promise<void> {
    return this.deps.local.close();
  }

  // ---------------------------------------------------------------------
  // Policy
  // ---------------------------------------------------------------------

  async getPolicyBundle(): Promise<PolicyBundle> {
    const local = await this.deps.local.getPolicyBundle();
    const cached = await (async (): Promise<PolicyBundle | null> => {
      try {
        return await this.deps.readCachedBundle();
      } catch {
        // A missing or unreadable remote cache degrades to the local bundle,
        // which is exactly standalone behaviour — never to no policy at all.
        return null;
      }
    })();
    if (cached === null) return local;

    // ONE RULE PER ID, and LOCAL WINS.
    //
    // The two sides can name the same rule — an organization's bundle
    // re-shipping a pack the machine already installed is ordinary, not an
    // error — and the concat that stood here kept both copies. What that costs
    // is not a duplicate finding: `recordCapture` already refuses a second
    // finding with the same rule, span and masked value, so the ledger is
    // unaffected. It costs a VAULTED value its recoverability. Two copies of one
    // rule produce two identical spans on every match, `groupSpans` reads any
    // overlap as one group and drops the finding from it, and the region is then
    // destroyed with a one-way `[REDACTED:…]` placeholder instead of being
    // tokenized into a pointer the user can reveal later. Fail-safe in
    // direction, silent, and not what Redact & Vault promises.
    //
    // Local first is the load-bearing half. With the cache winning, a bundle
    // naming a known rule id with a matcher that never matches would REPLACE the
    // detection rather than sit beside it — a remote kill switch for any rule an
    // organization can name. `mergeRaiseOnly` and the `rulesComplete` path
    // already refuse that shape; this keeps the third site consistent with them.
    const byRuleId = new Map<string, NonNullable<PolicyBundle['rules']>[number]>();
    for (const rule of [...(local.rules ?? []), ...(cached.rules ?? [])]) {
      if (!byRuleId.has(rule.id)) byRuleId.set(rule.id, rule);
    }
    const rules = [...byRuleId.values()];
    return {
      ...local,
      // The remote version identifies the composed bundle for the poller.
      version: cached.version,
      rules,
      policies: mergeRaiseOnly(
        local.policies,
        cached.policies,
        ruleCategoryMap(cached.rules, local.rules),
      ),
      customKeywords: [...local.customKeywords, ...cached.customKeywords],
      // TAKEN FROM THE CACHE, unlike the two fields below — and the asymmetry
      // is the point, so it is argued rather than asserted.
      //
      // What makes `rulesComplete` and `reversibleRuleIds` unsafe to honor is
      // that each can only ever RELAX enforcement, so honoring one would hand
      // anything able to write policy-cache.json a kill switch. A prohibition
      // inverts that: it can only ever ADD a refusal, so there is no relaxation
      // to grant. The capability it would give a cache-writer is to block the
      // user's own sessions — available far more cheaply to anyone who can
      // already write into that directory, by deleting the plugin.
      //
      // Local contributes nothing, so this is the organization's list or none:
      // a machine with no control plane has no governance decision to carry,
      // and the spread above would otherwise drop the field silently — which is
      // exactly what it did, leaving the whole control inert on every device
      // while every test around it stayed green.
      prohibitedModels: cached.prohibitedModels,
      // ALSO HONOURED FROM THE CACHE, and not a bundle field at all: each
      // merged policy's own `provenance`. `mergeRaiseOnly` spreads the policies
      // it emits, so an 'authored' policy arriving from the control plane
      // keeps that marker even where the clamp rebuilds it with a stronger
      // action. The device reads it in exactly one direction — the rules such a
      // policy targets are not locally re-assignable — so it sits on the
      // `prohibitedModels` side of the line for the same reason that field
      // does: it can only ever ADD a refusal, never relax one, and an unsigned
      // cache therefore has no relaxation to grant by carrying it. Dropping it
      // would be the silent failure rather than the safe one — the action would
      // still be enforced while the local override the organization authored
      // away quietly came back.
      // `rulesComplete` is a STANDALONE-ONLY signal (the user's local installed
      // snapshot) and is taken from the LOCAL bundle only — never from the wire
      // or the on-disk cache. Honoring a cached one would hand the control plane, or
      // anything able to write policy-cache.json, a kill-switch over the
      // compiled-in bundled packs: `{ rulesComplete: true, rules: [] }` would
      // zero local detection. Spread from `local` above, and deliberately not
      // re-read from `cached` here.
      //
      // THREE MORE OF THE CACHED BUNDLE'S FIELDS ARE DROPPED, each on purpose,
      // and each named here so a reader can tell a decision from an omission:
      //
      //   `exceptions`        — an exception SUPPRESSES a detection, so honoring
      //                         one from an unsigned on-disk cache would let
      //                         anything able to write that file turn rules off.
      //                         Every other field this merge accepts can only
      //                         RAISE enforcement; this is the one that cannot,
      //                         so it stays local-only until the bundle is
      //                         signed. Exceptions remain a device-local ledger.
      //   `reversibleRuleIds` — the Redact & Vault archetype makes a redaction
      //                         recoverable, which is a CUSTODY change: it puts
      //                         the detected value in the local vault instead of
      //                         destroying it. Taking that instruction from the
      //                         cache would let a remote party turn one-way
      //                         redaction into retention. Dropping it keeps the
      //                         one-way behaviour, which the schema itself calls
      //                         "the safe direction to default".
      //   `ruleVersions`      — remote rules fall back to their own spec version.
      //                         Cosmetic rather than protective: it only affects
      //                         how a finding is version-attributed, and the two
      //                         sides may therefore attribute org rules
      //                         differently. Worth carrying once there is a
      //                         reader that needs it; nothing reads it today.
    };
  }

  // ---------------------------------------------------------------------
  // LocalStoreMaintenance — by delegation (D3).
  //
  // Implementing these is what actually closes the skipped-local-maintenance
  // gap: the OSS structural guard `hasLocalStoreMaintenance()` is satisfied by
  // any object carrying them all, so the composite qualifies and SessionStart
  // runs maintenance on the device's real store.
  //
  // ⚠ Several of them are SYNCHRONOUS and must stay that way. `handle-session-start`
  // calls `capWarnEraEnforcement` without `await` and uses `staleBinaryNotice`'s
  // return value directly; declaring them `async` here would hand those call
  // sites a Promise and silently break both.
  // ---------------------------------------------------------------------

  async sweepTerminalExceptions(retentionMs: number): Promise<number> {
    return this.deps.local.sweepTerminalExceptions(retentionMs);
  }

  capWarnEraEnforcement(policyMode: SimpleDetectionPolicy): { capped: number } {
    return this.deps.local.capWarnEraEnforcement(policyMode);
  }

  async recordProjectFiles(projectId: string, scan: ProjectFilesScan): Promise<void> {
    return this.deps.local.recordProjectFiles(projectId, scan);
  }

  async reconcileWorktreeProjects(
    canonicalId: string,
    headRoot: string,
    worktreeRoot: string,
  ): Promise<void> {
    return this.deps.local.reconcileWorktreeProjects(canonicalId, headRoot, worktreeRoot);
  }

  staleBinaryNotice(currentVersion: string): string | null {
    return this.deps.local.staleBinaryNotice(currentVersion);
  }

  // Delegated like the rest, and SYNCHRONOUS for the reason the note above
  // gives: `recordCapture` calls it after the forward has already settled, on a
  // path that has nothing left to await.
  markCaptureDelivered(event: IngestEvent, atMs: number): void {
    this.deps.local.markCaptureDelivered(event, atMs);
  }

  markAuditEventsDelivered(events: readonly AuditEventInput[], atMs: number): void {
    this.deps.local.markAuditEventsDelivered(events, atMs);
  }
}

/**
 * Rewrite an outgoing audit event's inventory ids into the BACKEND's id space.
 *
 * Only ids the control plane actually resolved are substituted; a field it did not
 * resolve is OMITTED rather than left as the local value, so a partial remote
 * resolution degrades field-by-field instead of carrying an id from the wrong
 * space. When no remote resolution has been captured at all, every inventory
 * id is dropped for the same reason.
 *
 * The event does NOT reach the control plane carrying descriptors it could re-resolve
 * from: an AuditEventInput carries ids, and `pgAuditValues` writes them straight
 * into FK columns with no re-resolution step. That is why an unresolved id has
 * to be omitted here rather than passed along hopefully.
 */
function reKeyForForward<T extends AuditEventInput>(event: T, remote: ResolvedInventory | null): T {
  // No remote resolution: DROP the local ids rather than send them. They are a
  // different id space by construction — the device content-addresses
  // `['inventory', …]` while the control plane hashes them under its own scope —
  // so a local id names a row the control plane does not have. The insert
  // is rejected, `forward.run` swallows the rejection to null, and the session
  // root plus every descendant that keys onto it never reaches the forwarded copy.
  // Sending the event with these fields absent costs one degraded join; sending
  // them wrong costs the whole session. All three are `.optional()` on
  // AuditEventInput, so omitting them is valid on the wire.
  if (remote === null) {
    const stripped: T = { ...event };
    delete stripped.hostId;
    delete stripped.harnessId;
    delete stripped.sourceProjectId;
    return stripped;
  }
  // OMIT, then substitute — never override in place. Every member of
  // `ResolvedInventory` is optional, so a PARTIAL answer is representable and
  // valid: a plane that resolves only the host returns `{ hostId }`, and a
  // spread of `...event` would carry this machine's `harnessId` and
  // `sourceProjectId` through in ids the plane has no rows for. In the limit an
  // answer of `{}` is schema-valid and would forward every local id — precisely
  // the outcome the null branch above deletes them to avoid, reached by the
  // path that looks like it succeeded.
  const rekeyed = { ...event };
  delete rekeyed.hostId;
  delete rekeyed.harnessId;
  delete rekeyed.sourceProjectId;
  if (remote.hostId !== undefined) rekeyed.hostId = remote.hostId;
  if (remote.harnessId !== undefined) rekeyed.harnessId = remote.harnessId;
  if (remote.sourceProjectId !== undefined) rekeyed.sourceProjectId = remote.sourceProjectId;
  return rekeyed;
}

/**
 * How long a BATCH of per-item forwards may take in total.
 *
 * Each `forward.run` is bounded on its own, but a loop of them is not: N items
 * against a slow-but-answering plane costs N budgets, and the breaker never
 * helps because it only trips on failures — a plane answering successfully in
 * 600ms produces none. Forty tool calls is ~24s that way.
 *
 * NOT a hook deadline, though an earlier version of this comment said so. The
 * batch path is reached only from the transcript reconcilers, which run in the
 * DETACHED reconcile child and in `aka backfill` — nothing is blocking on
 * either. What the ceiling buys is that a slow plane cannot keep a detached
 * worker alive indefinitely, or hang a backfill; it is not standing between a
 * user and a tool call.
 *
 * So the batch gets one ceiling and the remainder is dropped when it is spent.
 * That is the same trade the whole forward path already makes (G8: local write
 * first, drops accepted and surfaced in status) — and it is surfaced HERE only
 * because `forward-drops.ts` counts it; the breaker's file cannot, since this
 * path never reaches `run`.
 *
 * The real ceiling is this plus one item's budget, not this alone: the deadline
 * is checked BEFORE the await, so the last item admitted can start at
 * `deadline - 1ms` and run its own `FORWARD_BUDGET_MS`. 3,000 + 1,500 = ~4.5s.
 */
const BATCH_FORWARD_BUDGET_MS = 3_000;

function llmAuditEvent(input: LlmCallInput): AuditEventInput {
  return {
    id: llmCallId(input.sessionId, input.messageId),
    eventType: 'llm_call',
    startedAt: input.startedAt,
    parentId: input.parentId,
    rootSessionId: input.rootSessionId,
    attributes: input.attributes,
  };
}

function toolAuditEvent(
  input: ToolCallInput,
): AuditEventInput & { inspections?: ToolCallInspection[] } {
  return {
    id: toolCallId(input.sessionId, input.toolUseId),
    eventType: 'tool_call',
    startedAt: input.startedAt,
    parentId: input.parentId,
    rootSessionId: input.rootSessionId,
    attributes: input.attributes,
    inspections: input.inspections,
  };
}
