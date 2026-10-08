import type { BlockedDetectionInput, ResolutionInput } from '@akasecurity/persistence';
import {
  canonicalRepoUrl,
  llmCallId,
  scopeKeyOfProjectKey,
  toEgressIngestRequest,
  toolCallId,
} from '@akasecurity/persistence';
import type {
  CaptureRecord,
  CaptureStatusReader,
  DataGateway,
  LocalStoreMaintenance,
  ProjectEgressContext,
  RuleProbeVerdictEntry,
  ScanLedgerEntry,
  ScanLedgerState,
} from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type {
  AuditEventBatchAck,
  AuditEventInput,
  ConfigInventoryReport,
  ConfigScanRecord,
  DayActivity,
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
  PolicyBundle,
  ProjectFilesScan,
  RecordProjectEgressInput,
  ReportedCaptureDocument,
  ResolvedAttachmentScope,
  ResolvedInventory,
  Rule,
  RuleProbeVerdict,
  ScopeVerdict,
  SessionTokenReport,
  SimpleDetectionPolicy,
  StorePostureSnapshot,
  ToolCallInput,
  ToolCallInspection,
  ToolCallInspectionInput,
} from '@akasecurity/schema';
import {
  AUDIT_EVENT_BATCH_MAX,
  mergeRaiseOnly,
  ruleCategoryMap,
  scopeVerdict,
} from '@akasecurity/schema';

import type { GovernanceScope } from '../governance-scope.ts';
import type { StoredRootKeyReader } from '../session-root-key.ts';
import { sessionToolIsKeyed } from '../session-root-key.ts';
import { recordForwardDrops } from './forward-drops.ts';
import type { ForwardPolicy } from './forward-policy.ts';
import { withoutScopeKey } from './scope-strip.ts';
import { withScopedRepo } from './scoped-repo.ts';
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
  // The SAME upsert, up to AUDIT_EVENT_BATCH_MAX at a time in one transaction.
  // Declared here because the object `createRemoteClient` hands this class has
  // carried it all along — only this interface did not say so, which is the
  // whole reason `forwardBatch` sent one request per event.
  //
  // A deployment that predates the route answers 404, and this caller DOES have
  // to know which it spoke to. The client raises `RemoteRouteAbsent`,
  // `ForwardPolicy` classifies it as `route-absent`, and `forwardBatch` re-sends
  // that chunk one at a time. It must NOT be absorbed inside the client here:
  // the fallback is 50 sequential round trips, and every one of them would be
  // charged to the single FORWARD_BUDGET_MS wrapping this call.
  recordAuditEvents(
    events: readonly (AuditEventInput & { inspections?: ToolCallInspection[] })[],
  ): Promise<AuditEventBatchAck>;
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
   *
   * `CaptureStatusReader` for the same reason: `readCaptureStatuses` below
   * delegates to it, so a `local` that cannot answer would make the
   * delegation a lie too.
   *
   * `StoredRootKeyReader` because a scoped attachment decides a session root by
   * the key the local store holds for it, read back after the local write (see
   * `rootVerdict`). A `local` that could not answer would leave every root, and
   * so every leaf under one, refused.
   */
  local: DataGateway & LocalStoreMaintenance & CaptureStatusReader & StoredRootKeyReader;
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
  /**
   * What this gateway may forward: the attachment's mode, and for a scoped
   * attachment the enrolled keys. The factory resolves it ONCE per gateway,
   * from the credential it just read and the settings already in hand.
   *
   * Every forwarding method asks it (through `verdictFor`) AFTER its local
   * write and BEFORE `forward.run`. So a row it refuses is written, never
   * offered, and never stamped owed or delivered. Machine mode answers
   * `'forward'` without reading a key, which is what keeps a machine
   * attachment's traffic exactly what it was.
   *
   * It also answers `governanceAppliesTo`, the question of where the
   * organization's model policy applies.
   *
   * REQUIRED, for the reason `local` and `dataDir` are. An optional member
   * would let a construction site omit it, and neither default is safe to
   * reach by leaving a line out: scoped-with-no-keys silently stops a machine
   * attachment forwarding, and machine silently forwards everything from a
   * scoped one.
   */
  attachment: ResolvedAttachmentScope;
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

// WHY EVERY COMPARISON `mergeRaiseOnly` MAKES EXISTS: the cached organization
// bundle is read from disk with no signature or provenance check — so a
// compromised control plane or a tampered cache file must not be able to use a
// policy to REDUCE enforcement, either below the compiled-in default for its
// category or below what the user's own local bundle already enforces. Raising
// is unaffected. `mergeRaiseOnly` and `ruleCategoryMap` both live in
// `@akasecurity/schema`, beside the policy shapes and `DEFAULT_ACTIONS` they
// are built from; that package cannot reach `bundledDetections()`
// (`@akasecurity/plugin-sdk`), so this module supplies its rules, flattened,
// as `ruleCategoryMap`'s compiled-in tier — required now, not optional, so a
// call site that forgot it fails to compile rather than clamping nothing.

// Lazily memoised at module scope: `bundledDetections()` already caches the
// pack array itself, but the flatten below was repeated on every
// `getPolicyBundle()` call regardless — one allocation and one pass per
// process, not one per cache hit.
let bundledRulesFlatCache: readonly Rule[] | undefined;
function bundledRulesFlat(): readonly Rule[] {
  bundledRulesFlatCache ??= bundledDetections().flatMap((pack) => pack.rules);
  return bundledRulesFlatCache;
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
 * control-plane bundle, raise-only — see mergeRaiseOnly. It is the same bundle
 * on either attachment mode. Where the organization's model policy applies is a
 * separate question, answered per event by `governanceAppliesTo`.
 */
export class AttachedDataGateway implements DataGateway, LocalStoreMaintenance, GovernanceScope {
  /**
   * The control plane's OWN resolution of this session's inventory, captured by
   * ensureInventory. Null until the first successful forward — and it stays
   * null for the whole session when the control plane is unreachable, which is fine:
   * reKeyForForward then leaves the event's ids alone and the control plane resolves
   * what it can from the descriptors it already has.
   */
  private remoteInventory: ResolvedInventory | null = null;

  /**
   * The verdict this instance reached for each session ROOT it recorded, keyed
   * by root id, from the key the local store holds for that root (see
   * `rootVerdict`). It is what a child row is held to (see `auditVerdict`).
   *
   * Per instance on purpose. An instance is resolved per hook process, per
   * native-host request, and per reconcile or backfill pass, and the
   * reconcilers record each session's root before its leaves. Never written in
   * machine mode, where nothing reads it.
   */
  private readonly rootVerdicts = new Map<string, ScopeVerdict>();

  constructor(private readonly deps: AttachedDataGatewayDeps) {}

  // ---------------------------------------------------------------------
  // The scope verdict: whether a row written locally may also be forwarded.
  // ---------------------------------------------------------------------

  /**
   * The one question every forward asks, answered TOTALLY: `'forward'` or
   * `'local'`, never a throw.
   *
   * The key is read INSIDE the guard, through a thunk, because reading it is
   * part of what can fail: a damaged bag, or a canonicalizer meeting an input
   * it never expected. A throw out of here would not be neutral. It would
   * reject `recordCapture` into the runtime's swallow, make the scanner read a
   * failed write and withhold its ledger commit, or drop a whole reconcile
   * pass. So a throw is answered `'local'`: the direction that degrades to
   * standalone behaviour, never to over-forwarding.
   *
   * Machine mode answers before any key is read, so a machine attachment pays
   * nothing for scoping and forwards exactly what it always has.
   *
   * `governanceAppliesTo` answers from this same verdict, so it agrees with
   * forwarding key for key.
   */
  private verdictFor(keyOf: () => string | undefined): ScopeVerdict {
    try {
      if (this.deps.attachment.mode === 'machine') return 'forward';
      return scopeVerdict(this.deps.attachment, keyOf());
    } catch {
      return 'local';
    }
  }

  /**
   * The verdict for an audit row, with the session-root rule on top.
   *
   * A session ROOT has two halves. What the rows that hang off it are held to is
   * the key its row holds in the local store, recorded per root (see
   * `rootVerdict`), not the key on the root event just handed in: roots are
   * first-write-wins in the store, so when two producers record a root for one
   * session (the session-start hook, then a reconcile pass) the second leaves
   * the stored row as it was, and the history drain decides that row, not this
   * event. Whether this root EVENT is itself sent takes both keys: the stored
   * one AND its own. The event's attributes (cwd, project, repo) describe where
   * it was recorded from, so a root event keyed to a personal directory is never
   * sent under an enrolled stored root, though the enrolled leaves still forward
   * under it: the instance that wrote the stored root is expected to have
   * forwarded it. If it did not (the root was written while standalone or under
   * another attachment, or its forward failed), the plane refuses those leaves
   * and the history drain ships the root first. Any other row with a root
   * reference (`rootSessionId`, else `parentId`) forwards only when its own key
   * is in scope AND this instance recorded an in-scope verdict for that root.
   * The audit-event route has real foreign keys on both columns and stubs no
   * missing root, so a leaf sent after its root was kept local is refused
   * there, and a refused forward counts toward the breaker that guards every
   * other one. A root this instance never recorded is therefore `'local'`: the
   * only answer that cannot orphan a row. A row with no root reference at all
   * has nothing to orphan, and is decided by its own key.
   *
   * What this costs is stated rather than discovered. A session whose stored
   * root is not keyed to an enrolled repository keeps its token and tool
   * records local, even the ones that ran inside one. A row recorded by an
   * instance that did not record its root cannot see the root's verdict, so it
   * stays local on a scoped attachment. Captures are not held to this: their
   * route plants a missing root itself, so they decide per event.
   */
  private auditVerdict(event: AuditEventInput): ScopeVerdict {
    try {
      if (this.deps.attachment.mode === 'machine') return 'forward';
      if (event.eventType !== 'session') {
        return this.leafVerdict(event.attributes, rootReferenceOf(event));
      }
      // The stored root's verdict is recorded FIRST and whatever this event's own
      // key says, since it is what the leaves are held to. The event is sent only
      // when its own key is in scope too.
      if (this.rootVerdict(event.id) === 'local') return 'local';
      return this.verdictFor(() => scopeKeyOf(event.attributes));
    } catch {
      return 'local';
    }
  }

  /**
   * A session root's verdict, from the key the local store holds for it.
   *
   * Read back ONCE per root per instance, after the local write, and recorded.
   * The write comes first so the row exists and a stub a leaf planted ahead of
   * it has been healed; the read is the store's answer, which is the first
   * authoritative root the session ever had. No key, a row that is not a root,
   * and a store that cannot answer all mean `'local'`: the read happens inside
   * `verdictFor`'s guard, so a throw is an answer and never a rejection.
   *
   * Scoped mode only: `auditVerdict` answers a machine attachment before it
   * gets here, so a machine attachment pays no store read.
   */
  private rootVerdict(rootId: string): ScopeVerdict {
    const recorded = this.rootVerdicts.get(rootId);
    if (recorded !== undefined) return recorded;
    const verdict = this.verdictFor(() => this.deps.local.readSessionScopeKey(rootId));
    this.rootVerdicts.set(rootId, verdict);
    return verdict;
  }

  /** A child row's verdict: its own key in scope AND its root's recorded verdict. */
  private leafVerdict(
    attributes: Record<string, unknown> | undefined,
    rootId: string | undefined,
  ): ScopeVerdict {
    try {
      if (this.deps.attachment.mode === 'machine') return 'forward';
      if (this.verdictFor(() => scopeKeyOf(attributes)) === 'local') return 'local';
      if (rootId === undefined) return 'forward';
      return this.rootVerdicts.get(rootId) === 'forward' ? 'forward' : 'local';
    } catch {
      return 'local';
    }
  }

  /**
   * The leaves of a batch that may be forwarded, filtered BEFORE `forwardBatch`
   * and never inside it. That loop tallies everything it does not deliver as a
   * forward drop, and a row this attachment may not send is not a lost one. Each
   * leaf is held to its root by the same reference `auditVerdict` uses
   * (`rootReferenceOf`).
   * Machine mode hands back the batch itself, so the batch path is exactly what
   * it was. A throw forwards nothing.
   */
  private forwardableLeaves<T extends LlmCallInput | ToolCallInput>(
    inputs: readonly T[],
  ): readonly T[] {
    try {
      if (this.deps.attachment.mode === 'machine') return inputs;
      return inputs.filter(
        (input) => this.leafVerdict(input.attributes, rootReferenceOf(input)) === 'forward',
      );
    } catch {
      return [];
    }
  }

  /**
   * The verdict for the repositories nested in a scanned project, answered
   * TOTALLY: `'forward'` or `'local'`, never a throw.
   *
   * A walk descends into a nested clone or submodule and folds its files into
   * the project it is walking, so one register can carry several
   * repositories' call sites under one project key. Each of them must be in
   * scope for it to forward. One key out of scope, or a nested repository with
   * no remote (an `undefined` key), keeps the whole register local.
   *
   * An ABSENT list is `'local'` too. Only the code that walked the tree can say
   * what is nested in it, and every scan passes the list, empty when nothing
   * is nested. A register nobody vouched for is not one a scoped attachment
   * may send.
   *
   * Machine mode answers before reading the context, so a machine attachment
   * forwards exactly what it always has.
   */
  private nestedVerdict(context: ProjectEgressContext | undefined): ScopeVerdict {
    try {
      if (this.deps.attachment.mode === 'machine') return 'forward';
      const keys = context?.nestedScopeKeys;
      if (keys === undefined) return 'local';
      for (const key of keys) {
        if (this.verdictFor(() => key) === 'local') return 'local';
      }
      return 'forward';
    } catch {
      return 'local';
    }
  }

  /**
   * The register a scoped attachment sends, once the project and the repositories
   * nested in it are in scope: the register itself, with `reconcile.deletedFiles`
   * cut to the deleted paths whose own repository is in scope. `undefined` sends
   * nothing. TOTAL, like `verdictFor`, and for its reasons.
   *
   * The deletion sweep takes its paths from the scan ledger, not from the walk,
   * and the ledger holds every file the scanner ever read under the root, nested
   * clones' included. So a clone that was removed, or one an ignore file now
   * hides, is in no walk and never reaches `nestedVerdict`, yet its ledgered
   * paths come back as deleted. The scan names the repository of each deleted
   * path (`context.deletedFileKeys`, one entry per path in the register's order)
   * and each is held to the same verdict as any other key. A path whose key is
   * absent, or out of scope, is not sent.
   *
   * The list is asked for here, and only here: it is an async read of the scan
   * ledger that the scan makes on being called, so a machine attachment, which
   * returns before this, and a register already kept local never cause it.
   *
   * Anything the scan did not vouch for sends no deleted path, and the register
   * itself still goes: no list, a list that throws or whose read is rejected, or a
   * list whose length is not the register's. Deleting is the only thing a dropped
   * path could have done on the server, so the cost of a refusal is a stored row
   * that stays, never a path that leaves.
   *
   * Machine mode returns `input` itself, the same object and unread, so a machine
   * attachment's request is exactly what it was. A register that lists no deleted
   * path, or that is not a ledger register, has nothing to cut and is returned
   * as it came, with the list unread.
   */
  private async registerForWire(
    input: RecordProjectEgressInput,
    context: ProjectEgressContext | undefined,
  ): Promise<RecordProjectEgressInput | undefined> {
    try {
      if (this.deps.attachment.mode === 'machine') return input;
      const { reconcile } = input;
      if (reconcile.mode !== 'ledger' || reconcile.deletedFiles.length === 0) return input;
      const deleted = reconcile.deletedFiles;
      let kept: string[] = [];
      try {
        const keys = await context?.deletedFileKeys?.();
        if (keys?.length === deleted.length) {
          kept = deleted.filter((_path, at) => this.verdictFor(() => keys[at]) === 'forward');
        }
      } catch {
        kept = [];
      }
      return { ...input, reconcile: { ...reconcile, deletedFiles: kept } };
    } catch {
      return undefined;
    }
  }

  /**
   * The event `recordCapture` sends for a capture the verdict let through, or
   * `undefined` to send nothing. TOTAL, like `verdictFor`, and for its reasons.
   *
   * Machine mode sends `record.event` itself, the same object, so a machine
   * attachment's body is exactly what it was. A scoped attachment sends a COPY
   * whose `metadata.repo` names the repository of the capture's own key
   * (`withScopedRepo`). A hook's slug names the session's directory, while a
   * capture that names a file is keyed by that file's repository, so on a
   * scoped attachment the slug could otherwise label an enrolled repository's
   * capture with a personal repository's name. The key here is the one the
   * verdict just admitted, so the name sent is always an enrolled
   * repository's.
   *
   * A throw sends nothing and leaves the row unmarked, the direction every
   * fault on this path takes: toward standalone behaviour, never toward
   * forwarding something unchecked.
   */
  private captureForWire(record: CaptureRecord): IngestEvent | undefined {
    try {
      if (this.deps.attachment.mode === 'machine') return record.event;
      const key = record.scopeKey;
      return key === undefined ? undefined : withScopedRepo(record.event, key);
    } catch {
      return undefined;
    }
  }

  // ---------------------------------------------------------------------
  // Writes: local first, then forward.
  // ---------------------------------------------------------------------

  async recordCapture(record: CaptureRecord): Promise<void> {
    // Local is authoritative and must not be skipped or reordered: the findings
    // it writes are what the device's own /health, /audit and exception flows
    // read, and what the posture channel measures.
    await this.deps.local.recordCapture(record);
    // THE SCOPE VERDICT, after the local write and before anything that could
    // stamp the row. A refused capture returns HERE, which keeps it out of the
    // owed branch below. That branch marks every non-delivery owed, and an owed
    // capture is sent later, text included, by the drain. A refusal is not a
    // non-delivery: it is a row this attachment must never send.
    if (this.verdictFor(() => record.scopeKey) === 'local') return;
    // WHAT IS SENT: the event itself in machine mode, and on a scoped
    // attachment a copy naming its key's repository (see `captureForWire`).
    // `record.event` is untouched, and it is what both stamps below are handed:
    // the row id they derive reads the session, content hash and file path,
    // never the slug.
    const wireEvent = this.captureForWire(record);
    if (wireEvent === undefined) return;
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
          events: [wireEvent],
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
    } else {
      // NOT delivered, so the organization's copy was not made and the drain
      // owes this row. Marked HERE because this is the only place that knows:
      // being attached, having run the forward, and having no confirmation are
      // all facts of this call, and none of them can be recovered later from a
      // timestamp. A capture recorded while DETACHED never reaches this method,
      // which is exactly why the drain can stop reasoning about time windows —
      // and why it can no longer ship a detached machine's three weeks of
      // prompts on its next re-attach.
      //
      // Every non-delivery outcome takes this branch on purpose — timeout,
      // refusal, breaker-open, and a 200 that took nothing. The row is owed in
      // all four; what differs is only how soon a retry is worth making.
      this.deps.local.markCaptureOwed(record.event);
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
    //
    // ON A SCOPED ATTACHMENT this call is the one thing here the scope verdict
    // gates. `InventoryContext.project` is the session's repository url and
    // name, so it is sent only when that repository is enrolled and the
    // session's tool is one whose root is ever keyed. The key is the same
    // canonicalization of the same url the session root's key is stamped from
    // (`inventoryKey`), and a tool the root rule never keys is never sent: a web
    // chat session, whose stand-in home directory may itself be a checkout.
    //
    // WHAT THIS CANNOT SEE is the working directory. A root is keyed only from
    // an ABSOLUTE directory, and the context does not carry the directory, so a
    // session whose relative directory resolved its project from the hook's own
    // process directory is still judged by that project here, while its root
    // stays local.
    //
    // The posture report below is NOT gated: it is the device's liveness
    // channel, and a scoped machine whose sessions are all personal must still
    // report, or it reads as silent.
    if (this.verdictFor(() => inventoryKey(ctx)) === 'forward') {
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
    } else {
      // A REFUSED inventory clears too, for the reason a failed one does: the
      // next session this instance serves must not inherit an earlier session's
      // resolution. It is the same pair as above (this line and
      // `reKeyForForward`'s null branch), so a forward after a refusal carries
      // no inventory ids rather than another session's.
      this.remoteInventory = null;
    }

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
    // The scope verdict, with the root rule on top (see `auditVerdict`). A
    // refusal returns before the stamp, deliberately: a stamp claims delivery.
    // The history drain must make that decision itself, from the row's stored
    // key; this call's verdict is held only in this instance's memory (a session
    // root's, for the rows recorded after it), not on the row.
    if (this.auditVerdict(event) === 'local') return;
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
    if (this.auditVerdict(event) === 'local') return;
    const forwarded = await this.deps.forward.run(() =>
      this.deps.client.recordAuditEvent(reKeyForForward(event, this.remoteInventory)),
    );
    if (forwarded.ok) this.deps.local.markAuditEventsDelivered([event], Date.now());
  }

  /**
   * Forward one batch in CHUNKS of AUDIT_EVENT_BATCH_MAX, under ONE aggregate deadline.
   *
   * This used to send one HTTP request per event, which is what made the batch
   * budget bite: at 200ms round-trip a 3s budget admitted ~15 events and threw
   * away everything after them. The same rows now cross 50 at a time over
   * `POST /v1/audit-events/batch` — the route the attach-time drain has always
   * used — so the same budget admits ~750. The wire cap is the server's own
   * constant, sized against server cost, and the client REFUSES a longer array
   * client-side, so the chunking here is not a convention.
   *
   * Still serial, and still for the original reason: firing N requests at once
   * would trade a latency problem for a burst the plane's per-key rate limiting
   * answers with the refusals the breaker then counts. Fewer, fuller requests is
   * the fix; more concurrent ones is not.
   *
   * When the deadline passes the remainder is dropped rather than sent: the
   * local write has already succeeded, so every caller has a correct result to
   * return. What is dropped is COUNTED, everywhere it can happen — this path
   * returns BEFORE `ForwardPolicy.run` is reached, so without the tally in
   * `forward-drops.ts` a slow-but-answering plane produces no failures, keeps
   * the breaker closed, renders a healthy block, and discards the tail of every
   * batch indefinitely. The SAME tally also covers a single that fails inside
   * the per-item retry below — the breaker opening mid-retry is a failure the
   * breaker's own state DOES capture, but the events still in this chunk once
   * that happens are neither delivered nor otherwise counted anywhere, which is
   * the same invisibility with a different cause.
   *
   * `ok` ALONE IS NOT DELIVERY, the same rule `recordCapture` states for the
   * single-event ack and at fifty times the blast radius here:
   * `AuditEventBatchAck.accepted` is an aggregate count the wire contract does
   * not tie to the chunk's own length, so a 2xx answering `{accepted: 30}` for
   * fifty events is well-formed. Trusting `ok` alone would stamp all fifty as
   * delivered and never re-offer the twenty the plane did not take. So success
   * is checked against `chunk.length`; anything short of it falls into the same
   * per-item pass as a refused chunk, which is the only way to recover the
   * rows that did not land, since the ack carries no per-row verdict to
   * resend by.
   *
   * That fallback ASSUMES a re-send of an already-landed row is a harmless
   * no-op rather than a second cost — an assumption this file cannot verify.
   * `AuditEventBatchAck` carries only `accepted`, unlike its sibling
   * `IngestAck` (`accepted` + `duplicates`, with `accepted + duplicates ==`
   * the batch size as the invariant `recordCapture` reads), so whether a
   * duplicate counts toward THIS route's `accepted` is not expressed
   * anywhere in this repo. If it follows its sibling's convention and does
   * NOT, a chunk containing even one already-delivered row — the ordinary
   * consequence of a lost stamp, which this file already treats as cheap —
   * answers short forever and enters the per-item pass on every pass it is
   * offered again. The cost of that is bounded rather than silent: the
   * pass converges (every row lands and stamps), so it is one wasted round
   * of singles rather than a stall, and it errs toward an extra resend
   * rather than toward the lost row the alternative risks.
   *
   * BATCH-ATOMIC SETTLEMENT is otherwise the rule: the receiver wraps a chunk in
   * one transaction, so a full 2xx settles every event in it and a non-2xx
   * settles none — which is why the whole chunk is stamped together on a FULL
   * accept and none of it otherwise. THREE reasons do not deserve whole-chunk
   * treatment, alongside a short accept, and all are re-sent one event at a
   * time:
   *
   *   `invalid-request` a chunk the client refused to send at all. One malformed
   *                     event would otherwise cost the 49 good ones beside it —
   *                     a new way to lose data introduced by the very change
   *                     meant to stop losing it.
   *   `route-absent`    a deployment that predates the batch route. The
   *                     single-event route is the one it serves, and re-sending
   *                     here rather than inside the client is what gives each
   *                     request its own budget instead of 50 inside one.
   *   `rejected`        the deployment's SERVER-side twin of `invalid-request` —
   *                     a 4xx body refusal from schema drift on the other side
   *                     of the wire. Settlement is batch-atomic on this reason
   *                     exactly as on the others, so leaving it out would cost
   *                     the whole chunk for one event the DEPLOYMENT considers
   *                     malformed, where the per-item form cost only that one.
   *
   * Every other reason (breaker-open, a refusal, a timeout) applies to the whole
   * chunk, and re-sending it item by item would just spend the budget failing 50
   * more times — for those, the blast radius stays exactly what it was before
   * batching.
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
      for (let i = 0; i < inputs.length; i += AUDIT_EVENT_BATCH_MAX) {
        const now = Date.now();
        if (now >= deadline) {
          // The remainder, not one chunk: everything from here on is discarded.
          recordForwardDrops(this.deps.dataDir, inputs.length - i, now);
          return;
        }
        // Built once per item, then shared by the wire and the stamp — see
        // recordLlmCall for why a second derivation is the thing to avoid. The
        // re-keyed copy goes on the wire; the ORIGINAL is what gets stamped,
        // because `reKeyForForward` rewrites inventory ids and the row is keyed
        // on neither.
        const chunk = inputs.slice(i, i + AUDIT_EVENT_BATCH_MAX).map((input) => toEvent(input));
        const forwarded = await this.deps.forward.run(() =>
          this.deps.client.recordAuditEvents(
            chunk.map((event) => reKeyForForward(event, this.remoteInventory)),
          ),
        );
        if (forwarded.ok) {
          if (forwarded.value.accepted === chunk.length) {
            delivered.push(...chunk);
            continue;
          }
          // A well-formed ack claiming fewer accepted than sent. `ok` is not
          // delivery here any more than it is for a single capture — fall
          // through to the per-item pass below, which is the only way to find
          // out which of the fifty actually landed. Bounded rather than
          // free, per the docblock above: this assumes a re-send of a
          // row that already landed costs an extra round trip, not a
          // second write.
        } else if (
          // THREE reasons are worth a second pass, one at a time, and they are
          // the three settled BEFORE the control plane refused anything, or
          // (for `rejected`) refused the BODY rather than the connection.
          //
          // `invalid-request` — the CLIENT refused the body before any request
          // went out: a defect in one event, not an outage. Re-sending singly
          // isolates the bad one instead of charging its 49 neighbours for it.
          //
          // `route-absent` — the deployment predates the batch route and serves
          // only the single-event one. The retry IS the compatibility path, and
          // it has to live HERE rather than inside the client: each single gets
          // its own FORWARD_BUDGET_MS through `run`, whereas the client's own
          // fallback would spend 50 sequential round trips inside the ONE
          // budget wrapping this call — turning a working older deployment into
          // a timeout, three of those into an open breaker, and every row into
          // a silent drop while the status surface called an answering
          // deployment down.
          //
          // `rejected` — the deployment's own 4xx refusal of the body, the
          // server-side twin of `invalid-request`: isolating it the same way
          // costs one event instead of the whole chunk for a defect the
          // deployment considers local to one row.
          //
          // Every other reason (breaker-open, a refusal, a timeout) applies to
          // the whole chunk; re-sending it item by item would just spend the
          // budget failing 50 more times.
          forwarded.reason !== 'invalid-request' &&
          forwarded.reason !== 'route-absent' &&
          forwarded.reason !== 'rejected'
        ) {
          continue;
        }
        for (const [j, event] of chunk.entries()) {
          const at = Date.now();
          if (at >= deadline) {
            // Counted from HERE, not from the next chunk boundary. The outer
            // loop's tally starts at `i + AUDIT_EVENT_BATCH_MAX` and would miss
            // everything this chunk still had — up to 49 events, on exactly the
            // machine the tally exists for. `return` rather than `break`, so the
            // outer deadline check cannot count that remainder a second time.
            recordForwardDrops(this.deps.dataDir, inputs.length - i - j, at);
            return;
          }
          const single = await this.deps.forward.run(() =>
            this.deps.client.recordAuditEvent(reKeyForForward(event, this.remoteInventory)),
          );
          if (single.ok) {
            delivered.push(event);
            continue;
          }
          if (single.reason === 'breaker-open') {
            // The breaker is now open for every route this gateway forwards
            // through, not just the rest of THIS chunk — so the next chunk's
            // own batch attempt would ALSO come back breaker-open, and that
            // reason is not one of the three the outer gate retries per item
            // (`:788-790`), so it falls straight into the `continue` beside
            // them. That `continue` records nothing. Left as a `break`, every
            // chunk after this one — not merely the rest of this one —
            // vanishes with no tally anywhere: the exact failure mode the
            // deadline exit fourteen lines up already solves, for the
            // identical reason. So this counts the FULL remainder, from here
            // to the end of the whole batch, and returns from the whole pass
            // rather than merely breaking this loop.
            recordForwardDrops(this.deps.dataDir, inputs.length - i - j, at);
            return;
          }
          // Any other single-level failure — this one event's own
          // invalid-request or rejected, a refusal, a timeout that has not yet
          // opened the breaker — is isolated to THIS row. The rest of the
          // chunk still deserves its own attempt, which is the whole point of
          // retrying one at a time, so the loop continues rather than
          // aborting. Counted individually: each is its own verdict, not part
          // of a remainder abandoned together.
          recordForwardDrops(this.deps.dataDir, 1, at);
        }
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
    // Refusals leave BEFORE the batch, never inside it: see `forwardableLeaves`.
    await this.forwardBatch(this.forwardableLeaves(inputs), (input) => llmAuditEvent(input));
  }

  // `input.inspections` (secrets detected client-side in the tool's masked
  // target) ride along on the request's `inspections` field — the control plane
  // persists each as an inspection_findings row linked to this audit event
  // (see RecordAuditEventRequest in @akasecurity/schema). The masked
  // `target` already rides `input.attributes`, so no raw secret leaks either
  // way — this only stops the FINDING row itself from being dropped.
  async recordToolCalls(inputs: readonly ToolCallInput[]): Promise<void> {
    await this.deps.local.recordToolCalls(inputs);
    await this.forwardBatch(this.forwardableLeaves(inputs), (input) => toolAuditEvent(input));
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
    // NO KEY, BY DESIGN, so a scoped attachment keeps every config scan local.
    // Its counts and failing sources describe user-scope configuration (skills,
    // hooks and servers under the home directory), which no enrolled repository
    // owns. The key is passed as absent rather than read off the event, so a
    // scan event that ever did carry one would still stay local.
    if (this.verdictFor(() => undefined) === 'local') return;
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
   *
   * `context.nestedScopeKeys` is what the scanner knows and the register does
   * not say: the key of every repository nested below the scan root, whose
   * files the walk folded into this register. On a scoped attachment the
   * register is forwarded only when the project's own key AND every one of
   * those is in scope (see `nestedVerdict`), and its deleted paths are cut to the
   * ones whose own repository is in scope (`context.deletedFileKeys`, see
   * `registerForWire`). Machine mode never reads either, and the local write
   * never receives the context and gets the register whole.
   */
  async recordProjectEgress(
    input: RecordProjectEgressInput,
    context?: ProjectEgressContext,
  ): Promise<EgressWriteSummary> {
    const summary = await this.deps.local.recordProjectEgress(input);
    // Keyed by the scan's own project key BEFORE it is hashed. A `git:<remote>`
    // key canonicalizes to the repository key; a `path:` key (a project with no
    // remote) has none, and stays local on a scoped attachment. The local
    // summary is returned either way, since the scanner reads a throw as a
    // failed write.
    if (this.verdictFor(() => scopeKeyOfProjectKey(input.projectKey)) === 'local') return summary;
    // Then every repository nested in it. Decided after the project's own key,
    // so a project already out of scope is refused without reading the list.
    if (this.nestedVerdict(context) === 'local') return summary;
    // Last, once the register is known to be sendable at all: which of its
    // deleted paths are.
    const register = await this.registerForWire(input, context);
    if (register === undefined) return summary;
    await this.deps.forward.run(() =>
      this.deps.client.recordProjectEgress(toEgressIngestRequest(register)),
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

  async readCaptureStatuses(): Promise<ReportedCaptureDocument[]> {
    return this.deps.local.readCaptureStatuses();
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

  async scanLedgerPaths(): Promise<string[]> {
    return this.deps.local.scanLedgerPaths();
  }

  // Delegated, like the path list. An inner gateway that cannot say answers an
  // empty map, which gives every deleted path no key.
  async scanLedgerPathKeys(): Promise<Map<string, string | undefined>> {
    return (await this.deps.local.scanLedgerPathKeys?.()) ?? new Map();
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
        ruleCategoryMap(cached.rules, local.rules, bundledRulesFlat()),
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
      //
      // WHOLE ON EVERY ATTACHMENT. A scoped attachment does not narrow the list
      // here: the port's `getPolicyBundle()` takes no event, and the runtime
      // reads this bundle once to build detection, so the detections it carries
      // apply to every event on the machine. Where a prohibition applies is
      // answered per event by `governanceAppliesTo` below.
      prohibitedModels: cached.prohibitedModels,
      // NAMED for the same reason as the line above, and it is the same defect
      // if it is not: `...local` above spreads the DEVICE's bundle, so a field
      // only the cache carries is dropped in silence. That is what left
      // `prohibitedModels` inert on every attached device with every test
      // around it green.
      //
      // Taken from the cache rather than merged here, because merging it needs
      // the device's own SETTING — which is not a bundle field and is not in
      // scope at this seam. The runtime does that merge, raise-only, where both
      // values are in hand (createPluginRuntime's ensureInitialized).
      redactFallback: cached.redactFallback,
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
  // GovernanceScope — where the organization's model policy applies
  // ---------------------------------------------------------------------

  /**
   * Whether the organization's governance applies to an event keyed `scopeKey`:
   * the question a model-guard site asks once it has decided to refuse.
   *
   * THE FORWARD VERDICT, through `verdictFor`: the answer is whether a capture
   * with the same key would be forwarded. A machine-wide attachment governs
   * every event, keyless included, exactly as before. A scoped one governs an
   * event only when its key names an enrolled repository. An event in a
   * personal repository, in no repository, with an empty key, or met by a fault
   * is not governed.
   *
   * The event's OWN key, never its session root's. The root rule in
   * `auditVerdict` decides whether a row can be forwarded without orphaning it;
   * this decides whether a refusal applies, which is a question about where the
   * event happened.
   *
   * Answered from memory: no store read, no bundle read, nothing sent.
   */
  governanceAppliesTo(scopeKey: string | undefined): boolean {
    return this.verdictFor(() => scopeKey) === 'forward';
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
  markCaptureOwed(event: IngestEvent): void {
    this.deps.local.markCaptureOwed(event);
  }

  markCaptureDelivered(event: IngestEvent, atMs: number): void {
    this.deps.local.markCaptureDelivered(event, atMs);
  }

  markAuditEventsDelivered(events: readonly AuditEventInput[], atMs: number): void {
    this.deps.local.markAuditEventsDelivered(events, atMs);
  }
}

/**
 * Rewrite an outgoing audit event's inventory ids into the BACKEND's id space,
 * and drop the local scope key.
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
 *
 * THE SCOPE KEY GOES ON BOTH BRANCHES, and before either. `attributes.scope_key`
 * is a local-only fact a producer stamps in every attachment mode, and the
 * request's attributes member is an open record, so this is the one place on the
 * LIVE path between a stamped row and the receiving side's storage. Every live
 * audit-event route passes through here: the single route, the batch, the
 * batch's per-item fallback and config scans. That is why the strip lives here
 * rather than at each call site. The history drain is the other path: its
 * `attributesOf` strips the key from a stored row's bag. See `scope-strip.ts`.
 */
function reKeyForForward<T extends AuditEventInput>(event: T, remote: ResolvedInventory | null): T {
  const outbound = withoutScopeKey(event);
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
    const stripped: T = { ...outbound };
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
  const rekeyed = { ...outbound };
  delete rekeyed.hostId;
  delete rekeyed.harnessId;
  delete rekeyed.sourceProjectId;
  if (remote.hostId !== undefined) rekeyed.hostId = remote.hostId;
  if (remote.harnessId !== undefined) rekeyed.harnessId = remote.harnessId;
  if (remote.sourceProjectId !== undefined) rekeyed.sourceProjectId = remote.sourceProjectId;
  return rekeyed;
}

/**
 * The session root a row hangs off: its `rootSessionId`, else its `parentId`.
 *
 * ONE RULE for the single-row verdict (`auditVerdict`) and the batch filter
 * (`forwardableLeaves`), so the two cannot hold a leaf to different roots. The
 * parameter admits both references as optional because an audit event does,
 * though a batch input carries both today.
 */
function rootReferenceOf(row: {
  readonly rootSessionId?: string | undefined;
  readonly parentId?: string | undefined;
}): string | undefined {
  return row.rootSessionId ?? row.parentId;
}

/**
 * The scope key a structural producer stamped into an attributes bag, or
 * undefined. Read with `Object.hasOwn`, and only a string counts: the bag is
 * free-form JSON on its way back out of the store, and anything else under that
 * name is no key at all, which the verdict answers `'local'`. The spelling is
 * the one `withoutScopeKey` strips (`scope-strip.ts`).
 */
function scopeKeyOf(attributes: Record<string, unknown> | undefined): string | undefined {
  if (attributes == null || !Object.hasOwn(attributes, 'scope_key')) return undefined;
  const key = attributes.scope_key;
  return typeof key === 'string' ? key : undefined;
}

/**
 * The key a session's inventory is held to: the canonical repository of the
 * context's project, for a tool whose root is ever keyed, and none otherwise.
 *
 * The harness identity IS the tool (`resolveInventoryContext` sets it from the
 * session's own), so it is what tells a web chat session from a coding one. A
 * context that names no harness cannot be shown to be the second, and gets no
 * key. A throw is the verdict's to answer: this runs inside its guard.
 */
function inventoryKey(ctx: InventoryContext): string | undefined {
  const tool = ctx.harness?.identityKey;
  if (tool === undefined || !sessionToolIsKeyed(tool)) return undefined;
  return canonicalRepoUrl(ctx.project?.url ?? '');
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
    inspections: input.inspections.map(toWireInspection),
  };
}

// The wire inspection, named field by field. A local inspection also carries
// where the hit sits and its masked excerpt (ToolCallInspectionInput); those
// stay on this machine, so they are left out here rather than relying on the
// client's schema to strip them.
export function toWireInspection(insp: ToolCallInspectionInput): ToolCallInspection {
  return {
    ruleId: insp.ruleId,
    ruleName: insp.ruleName,
    ruleVersion: insp.ruleVersion,
    category: insp.category,
    severity: insp.severity,
    span: insp.span,
    maskedMatch: insp.maskedMatch,
    actionTaken: insp.actionTaken,
    confidence: insp.confidence,
  };
}
