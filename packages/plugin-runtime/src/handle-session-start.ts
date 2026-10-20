import { randomUUID } from 'node:crypto';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import {
  claimSessionStart,
  configPostureDefinitions,
  evaluateConfigPosture,
  loadConfig,
  offersMaintenance,
  resolveConfigInventory,
  resolveGitBranch,
  resolveHeadRoot,
  resolveInventoryContext,
  resolveProjectFiles,
  resolveRepoNwo,
  resolveWorktreeRoot,
  sessionRootScopeKey,
} from '@akasecurity/plugin-sdk';
import type {
  AccountBasis,
  AuditEventInput,
  ConfigScanResult,
  InventoryContext,
  ResolvedInventory,
  SourceTool,
} from '@akasecurity/schema';
import {
  configInventoryInputs,
  harnessFromTool,
  parseAgentKey,
  SOURCE_TOOL,
} from '@akasecurity/schema';

import type { AccountScope, StampedScopeKey } from './account-scope.ts';
import { accountScopeOf } from './account-scope.ts';
import { forwardingLine, workSubscriptionOptOutOffered } from './attached/forwarding-line.ts';
import { triggerHistorySync } from './attached/history-sync-trigger.ts';
import type { PluginBuildInfo } from './attached/plugin-block.ts';
import { triggerPolicySync } from './attached/sync-trigger.ts';
import { triggerContentRetention } from './content-retention-trigger.ts';
import { syncModPolicySnapshot } from './mod-policy-sync.ts';
import { pluginRecordedBy } from './recorder.ts';
import { resolveDataGateway } from './resolve.ts';
import { sessionToolIsKeyed } from './session-root-key.ts';

// How long TERMINAL exception rows (revoked / expired / use-budget exhausted)
// are retained before the SessionStart sweep purges them — 90 days, aligned
// with the finding-retention story. Active grants are never swept; evaluation
// ignores terminal rows by predicate, so correctness never depends on this.
export const EXCEPTION_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * What a SessionStart hook threads in from its stdin payload (+ the manifest the
 * adapter reads): the Claude Code session id (the audit-tree root id and the
 * dedupe key), the cwd (for project resolution), and the harness build version /
 * interface (descriptive — they ride in the bag, never the hashed identity).
 */
export interface SessionStartInput {
  sessionId: string | undefined;
  cwd: string;
  // The wire id, typed to the registry rather than left open. This one value
  // becomes the harness row's content-addressed `identityKey` AND its `title`,
  // which the read side sniffs to resolve a harness card — so an unmapped
  // string here mints an inventory row nothing can classify. Typing it checks
  // every adapter at compile time instead.
  tool: SourceTool;
  harnessVersion?: string | undefined;
  harnessInterface?: string | undefined;
  // The calling artifact's package identity, for the attached posture
  // self-report (see DataGatewayFactory on `meta.pluginBuild`). Composed by
  // the adapter — the runtime knows neither the npm package name nor where
  // the installed manifest lives. Optional: without it the report goes out
  // with no plugin block, exactly as an older adapter's did.
  pluginBuild?: PluginBuildInfo | undefined;
  // Injectable for tests only (keeps the config scan off the test machine's
  // real ~/.claude); adapters omit it and the scanner resolves os.homedir().
  homeDir?: string | undefined;
  // False for a session whose activity this machine must not record: a web chat
  // on a personal device. The inventory pass still runs, and with it the device
  // report an attached gateway sends from it, and so do the maintenance passes
  // and the background policy refresh. The session root and the config scan
  // hung off it are not written, so nothing marks that the session happened.
  // Omitted, the root is recorded as it always has been.
  recordSession?: boolean | undefined;
  // True to leave this session's root unwritten: this session start writes no
  // root row. The config scan is still recorded, under a local stub of the
  // root. Honoured only by a gateway that stamps account keys, and only when the
  // session's own repository is not in its scope: a root in an enrolled
  // repository is written now, keyed by it.
  rootAwaitsAccount?: boolean | undefined;
  // The basis the adapter's session-start login view reached, given only for a
  // login that is a work subscription. It picks the forwarding line's work
  // wording and the command that stops it.
  accountBasis?: AccountBasis | undefined;
  // The key to stamp the root with when it is not the working directory's
  // repository key: a coding-agent key, for a session whose account is known at
  // session start. Honoured only when it is exactly the key the gateway's own
  // account scope stamps for that account in this directory; any other value
  // keys the root as if it were absent. An honoured key is also the key the
  // session's inventory may be sent under.
  rootScopeKey?: StampedScopeKey | undefined;
  // An account key with the binding hash it was validated against: admitted on
  // this session start's own gateway before the root is keyed, under the same
  // rules as any admission (the hash must be the scope's, and work subscriptions
  // must be on), so a root keyed by it is honoured. It writes nothing to the
  // identity record.
  admitAccount?: { accountKey: string; bindingHash: string } | undefined;
  // True for a Codex thread whose ChatGPT account the adapter could not decide
  // because its first record was not on disk. The forwarding line then says what
  // the thread's next check can change.
  threadAccountPending?: boolean | undefined;
}

/**
 * What a session start hands back for its adapter to show the user, once per
 * session. Each is null when there is nothing to say.
 *
 * `forwardingLine` says where this session's activity goes (see
 * `forwardingLine`); `staleBinaryNotice` says a newer AKA binary is on the
 * machine than this session's plugin; `warnEraNotice` says this session start
 * capped a warn-era store's block and redact categories to warn.
 */
export interface SessionStartResult {
  staleBinaryNotice: string | null;
  forwardingLine: string | null;
  warnEraNotice: string | null;
}

/**
 * What a session start shows the user, one notice per line, or undefined when
 * there is nothing to show. The forwarding line comes first; the stale-session
 * notice keeps its `[aka]` prefix; the warn-era notice follows, then
 * `adapterNotices`, the adapter's own once-per-session notices (the
 * store-redirect warning), each with any trailing newline trimmed. Adapters put
 * it on the host's user-facing channel, never stderr, which a SessionStart
 * hook's host does not show — except where the host's session-start event
 * offers no user-facing channel at all, where stderr is the only place left:
 * the Copilot adapter writes this whole notice there, and the Antigravity
 * adapter (whose session start rides PreInvocation) writes the stale-session
 * and warn-era notices there.
 */
export function sessionStartNotice(
  result: SessionStartResult,
  adapterNotices: readonly string[] = [],
): string | undefined {
  const lines = [
    result.forwardingLine,
    result.staleBinaryNotice === null ? null : `[aka] ${result.staleBinaryNotice}`,
    result.warnEraNotice,
    ...adapterNotices.map((notice) => notice.trimEnd()),
  ].filter((line): line is string => line !== null && line !== '');
  return lines.length === 0 ? undefined : lines.join('\n');
}

/**
 * The once-per-session inventory pass: resolve this session's host / harness /
 * account / project, upsert them (idempotent, content-addressed), and open the
 * Session audit-event root that descendant events will hang off via
 * `root_session_id`. Claimed once per session (SessionStart can fire repeatedly)
 * and fully fail-open — a locked store or missing id drops the telemetry, never
 * breaks the session.
 *
 * This populates the meta tables only; the live capture path writes
 * events/findings independently.
 */
export async function handleSessionStart(
  input: SessionStartInput,
  config: PluginConfig = loadConfig(),
): Promise<SessionStartResult> {
  // What the adapter shows once per session; every guarded/early path stays
  // silent.
  const silent: SessionStartResult = {
    staleBinaryNotice: null,
    forwardingLine: null,
    warnEraNotice: null,
  };
  try {
    // No session id → nothing to key the root on or dedupe against.
    if (!input.sessionId) return silent;
    // Run once per session; a later SessionStart for the same session no-ops
    // (and the notice rides the claim, so it can never repeat mid-session).
    if (!claimSessionStart(config.dataDir, input.sessionId)) return silent;

    // SessionStart is the one hook that knows the plugin's own version (the
    // manifest path rides its argv), so it stamps the inventory recording.
    // `pluginBuild` rides beside it into the attached posture self-report.
    const meta = {
      ...(input.harnessVersion !== undefined
        ? { recordedBy: pluginRecordedBy(input.harnessVersion) }
        : {}),
      ...(input.pluginBuild !== undefined ? { pluginBuild: input.pluginBuild } : {}),
    };
    const gateway = resolveDataGateway(config, meta);
    let line: string | null = null;
    let rootDeferred = false;
    let staleBinaryNotice: string | null = null;
    let warnEraNotice: string | null = null;
    try {
      // Machine/repo facts only; the writer adds the local user account.
      const ctx = resolveInventoryContext({
        cwd: input.cwd,
        tool: input.tool,
        harnessVersion: input.harnessVersion,
        harnessInterface: input.harnessInterface,
      });
      // An offered account joins this gateway's scope before the root is keyed,
      // so a root keyed by it is honoured below.
      if (input.admitAccount !== undefined) {
        const { accountKey, bindingHash } = input.admitAccount;
        accountScopeOf(gateway)?.admit(accountKey, bindingHash);
      }
      // How the root is keyed, and whether it is written now: decided once, from
      // the gateway's account scope. A gateway without one keys the root with the
      // repository key and writes it now.
      const root = rootPlan(input, accountScopeOf(gateway));
      rootDeferred = root.deferred && input.recordSession !== false;
      const resolved = await (root.inventoryKey === undefined
        ? gateway.ensureInventory(ctx)
        : gateway.ensureInventory(ctx, { scopeKey: root.inventoryKey }));
      if (input.recordSession !== false) {
        if (!root.deferred) {
          // The current branch, read from this worktree's HEAD (pure file I/O, no
          // git spawn) — the one session-display fact not already on `ctx`.
          const branch = resolveGitBranch(input.cwd);
          await gateway.recordAuditEvent(
            buildSessionRoot(
              input.sessionId,
              input,
              ctx,
              resolved,
              config.provider,
              branch,
              root.scopeKey,
            ),
          );
        }
        // The config-inventory pass (skills + hooks), under the same once-per-
        // session claim. Guarded separately: a scanner bug must not take the
        // just-written session root down with it. Skipped with the session when it
        // is not recorded; kept when only the root is left unwritten, and then
        // recorded under the local stub the local store plants for it.
        await recordConfigInventory(gateway, input, ctx);
      }
      // Best-effort store maintenance. Each pass is gated on ITS OWN member
      // rather than on the whole capability: they are unrelated, so a gateway
      // supplying only some of them must still get those run — gating
      // the group would drop the retention purge because some unrelated member
      // is absent, and every pass here is swallowed, so nothing would say so.
      //
      // Purge terminal exception rows past retention. Swallowed — a failed
      // sweep must never break SessionStart, and evaluation never depends on it.
      if (offersMaintenance(gateway, 'sweepTerminalExceptions')) {
        try {
          await gateway.sweepTerminalExceptions(EXCEPTION_RETENTION_MS);
        } catch {
          // best-effort
        }
      }
      // The warn-era enforcement cap: caps existing block/redact category
      // rows to warn once for a warn-policy store. A redact-policy store
      // is a no-op.
      if (offersMaintenance(gateway, 'capWarnEraEnforcement')) {
        try {
          const { capped } = gateway.capWarnEraEnforcement(config.settings.policy);
          if (capped > 0) {
            warnEraNotice =
              'AKA: the global "warn only" handling was retired; your existing ' +
              'block/redact categories were kept at warn. Re-run /aka:setup to ' +
              'adopt per-category enforcement.';
          }
        } catch {
          // Fail-open: a failed cap drops the migration, never the session.
        }
      }
      // The Claude Code mod's policy snapshot, from the effective bundle. The
      // store writes it on every local change; this is the first one an existing
      // install gets, and where an attached machine's organization policy lands.
      // Only the Claude Code plugin ships the mod. Never throws.
      if (input.tool === SOURCE_TOOL.ClaudeCode) {
        await syncModPolicySnapshot(gateway, config.dataDir);
      }
      // The project-file inventory pass (the Inventory page's file tree).
      // Guarded separately: a walk bug must never take the session root or
      // config scan down with it.
      if (offersMaintenance(gateway, 'recordProjectFiles')) {
        try {
          if (resolved.sourceProjectId) {
            const filesScan = resolveProjectFiles(input.cwd);
            if (filesScan) await gateway.recordProjectFiles(resolved.sourceProjectId, filesScan);
          }
        } catch {
          // Fail-open: a failed walk drops the tree update, never the session.
        }
      }
      // Self-heal ghost projects the pre-worktree-fix resolver minted for
      // checkout paths — one fixed-plugin session clears them for good.
      if (offersMaintenance(gateway, 'reconcileWorktreeProjects')) {
        try {
          const headRoot = resolveHeadRoot(input.cwd);
          const worktreeRoot = resolveWorktreeRoot(input.cwd);
          if (resolved.sourceProjectId && headRoot && worktreeRoot) {
            await gateway.reconcileWorktreeProjects(
              resolved.sourceProjectId,
              headRoot,
              worktreeRoot,
            );
          }
        } catch {
          // Fail-open: ghosts linger until the next session, nothing breaks.
        }
      }
      // The organization's policy, refreshed in a detached child. Placed here
      // rather than in each harness's entry because every harness reaches
      // SessionStart — Antigravity through its first PreInvocation, the browser
      // host through its own handler — so one call covers all of them, and a
      // harness added later gets it without a second edit. Never throws, never
      // awaited: see triggerPolicySync.
      triggerPolicySync(config);
      // The backlog of already-recorded activity, drained in its own detached
      // child. Separate from the policy pull above because the two have
      // different windows and different reasons to be skipped, and one marker
      // covering both would let whichever ran first suppress the other. Never
      // throws, never awaited: see triggerHistorySync.
      triggerHistorySync(config);
      // Local body expiry, in its own detached child. Unlike the two above it
      // is not gated on attachment — it is disk hygiene every machine wants —
      // and it carries its own hourly window, because what it bounds is the
      // store's size rather than how stale a deployment's view is. Off by
      // default, so on most machines this returns without spawning anything.
      // Never throws, never awaited: see triggerContentRetention.
      triggerContentRetention(config);
      // The stale-session check: only meaningful when this session knows its
      // own version. Its own guard, so a throw costs this notice alone.
      try {
        if (input.harnessVersion !== undefined && offersMaintenance(gateway, 'staleBinaryNotice')) {
          staleBinaryNotice = gateway.staleBinaryNotice(input.harnessVersion);
        }
      } catch {
        staleBinaryNotice = null;
      }
    } catch {
      // Fail-open: a fault in the pass drops its telemetry and any notice it
      // had not reached yet, never the forwarding line below.
    } finally {
      // Where this session's activity goes, from the gateway this session start
      // wrote through, after the pass whatever it reached: the root, if the pass
      // wrote one, was decided by that gateway, and the line reads its verdict.
      // A root the pass left to the reconcile reads as pending. A pass that
      // faulted before the root leaves no verdict on a scoped attachment and
      // prints no line: the history reconcile writes a missing root later and may
      // forward the session's records under it, so neither answer would be known
      // to be true. The adapter's basis picks the work wording and its stop
      // sentence. Never throws, and read before the store handle closes.
      line = forwardingLine(gateway, input.sessionId, {
        rootDeferred,
        basis: input.accountBasis,
        managed:
          input.accountBasis !== undefined || rootDeferred
            ? !workSubscriptionOptOutOffered(config.settingsDir)
            : false,
        threadAccountPending: input.threadAccountPending === true,
      });
      try {
        await gateway.close();
      } catch {
        // A failing close cannot take back what was already computed.
      }
    }
    return { staleBinaryNotice, forwardingLine: line, warnEraNotice };
  } catch {
    // Fail-open: SessionStart inventory must never break a session.
  }
  return silent;
}

// Scan the machine's Claude Code config surface and commit it as one atomic
// record: the skill/hook inventory upserts + the `config_scan` audit event they
// were seen by, hung off the session root. Fail-open like everything on this
// path.
//
// The record names the session's harness only when the scan read that harness's
// configuration; an attached gateway stages the items under that harness for
// the sync child to report, and stages none for a record without one.
async function recordConfigInventory(
  gateway: DataGateway,
  input: SessionStartInput,
  ctx: InventoryContext,
): Promise<void> {
  try {
    if (!input.sessionId) return;
    const scan = resolveConfigInventory({ cwd: input.cwd, homeDir: input.homeDir });
    // Pure posture pass over the scan (hook conflicts / unknown hooks /
    // external egress). Findings reference their rule by (ruleId, version)
    // natural key; persistence resolves the definition ids — so definitions
    // ride the same atomic record (idempotent content-addressed upserts).
    const findings = evaluateConfigPosture(scan);
    await gateway.recordConfigScan({
      items: configInventoryInputs(scan),
      scanEvent: buildConfigScanEvent(input.sessionId, scan),
      definitions: configPostureDefinitions(),
      findings,
      ...(scan.sourceTool === input.tool && ctx.harness !== undefined
        ? { harness: ctx.harness }
        : {}),
      ...(scan.projectKey === undefined ? {} : { projectKey: scan.projectKey }),
      complete: scan.errors.length === 0,
    });
  } catch {
    // Fail-open: a failed config scan drops telemetry, never the session.
  }
}

// The per-scan audit fact: a random id
// (scans are facts, never deduped), parented on the session root, snapshotting
// the counts + per-source parse failures true at scan time.
function buildConfigScanEvent(sessionId: string, scan: ConfigScanResult): AuditEventInput {
  return {
    id: randomUUID(),
    eventType: 'config_scan',
    startedAt: scan.scannedAt,
    parentId: sessionId,
    rootSessionId: sessionId,
    attributes: {
      skills: scan.skills.length,
      hooks: scan.hooks.length,
      mcp_servers: scan.mcpServers.length,
      config_files: scan.configFiles.length,
      errors: scan.errors.length,
      // The failed sources themselves (path + reason) — small, and the only
      // trace of a parse failure once the scanner has failed open past it.
      ...(scan.errors.length > 0 ? { error_sources: scan.errors } : {}),
    },
  };
}

// The repository key a session root is stamped with, or undefined: a web chat
// session's root is never keyed (sessionToolIsKeyed), and a cwd in no
// repository with a usable remote yields none.
function sessionRootKeyOf(input: SessionStartInput): string | undefined {
  return sessionToolIsKeyed(input.tool) ? sessionRootScopeKey(input.cwd) : undefined;
}

/**
 * How a session start keys its root, and whether it writes it at all.
 *
 *   - no account scope (standalone, machine-wide, no identity record), or a tool
 *     whose root is never keyed: the repository key, written now;
 *   - the repository key in scope: that key, written now (repository first);
 *   - `rootAwaitsAccount`: no root is written here; the config scan is still
 *     recorded under a local stub;
 *   - `rootScopeKey` equal to what the scope stamps for its account here: that
 *     agent key, written now, and the inventory may be sent under it;
 *   - anything else: the repository key, written now.
 *
 * Total: a throw keys the root with the repository key and writes it now.
 */
function rootPlan(
  input: SessionStartInput,
  account: AccountScope | undefined,
): { scopeKey: string | undefined; deferred: boolean; inventoryKey: string | undefined } {
  const repoKey = sessionRootKeyOf(input);
  const repoRoot = { scopeKey: repoKey, deferred: false, inventoryKey: undefined };
  try {
    if (account === undefined || !sessionToolIsKeyed(input.tool)) return repoRoot;
    if (repoKey !== undefined && account.inScope(repoKey)) return repoRoot;
    if (input.rootAwaitsAccount === true) {
      return { scopeKey: repoKey, deferred: true, inventoryKey: undefined };
    }
    const offered = input.rootScopeKey;
    const parsed = parseAgentKey(offered);
    if (offered === undefined || parsed === undefined) return repoRoot;
    if (account.stamp(repoKey, parsed.accountKey) !== offered) return repoRoot;
    return { scopeKey: offered, deferred: false, inventoryKey: offered };
  } catch {
    return repoRoot;
  }
}

// The Session root audit event: keyed on the Claude Code session id (so a repeat
// SessionStart conflicts harmlessly), stamped with the resolved inventory FKs,
// and carrying the volatile attrs (os_version, harness_version, provider) true at
// session start snapshotted onto the fact so a later upgrade — or a provider
// switch — can't rewrite the past. The reconciler reads `provider` back off this
// root rather than re-resolving live env, so it must land here.
//
// It ALSO stamps the session-DISPLAY attributes the Activity page reads directly
// off the root — `harness` (mapped tool id), `cwd`, `version`, `host`, `project`,
// `repo`, `branches` — sourced from the already-resolved `ctx` (host/harness/
// project inventory) + `input` (cwd/tool/version) + the branch read. Without
// these the reconstructed session shows blank (no title/project/cwd/branch) —
// the read side derives model/turns/tools from the leaves, but these facts are
// only known at capture time.
function buildSessionRoot(
  sessionId: string,
  input: SessionStartInput,
  ctx: InventoryContext,
  resolved: ResolvedInventory,
  provider: PluginConfig['provider'],
  branch: string | undefined,
  scopeKey: string | undefined,
): AuditEventInput {
  const attributes: Record<string, unknown> = {};
  const osVersion = ctx.host?.attributes.os_version;
  const harnessVersion = ctx.harness?.attributes.harness_version;
  const harnessInterface = ctx.harness?.attributes.interface;
  if (typeof osVersion === 'string') attributes.os_version = osVersion;
  if (typeof harnessVersion === 'string') attributes.harness_version = harnessVersion;
  // Snapshotted onto the session's OWN attributes for the same reason as
  // harness_version above: the shared harness inventory row is keyed only on
  // `tool` (e.g. 'codex'), so a later session's ensureInventory() upsert would
  // silently overwrite it there — a durable per-session fact needs to live on
  // the fact itself. Distinguishes e.g. a Codex session run inside the
  // ChatGPT desktop app ('codex_desktop') from one run in a terminal
  // ('codex_cli_rs'/'codex-tui'/'codex_exec') without forking the harness/
  // sourceTool dimension — see plugins/codex/src/hooks/session-start.ts.
  if (typeof harnessInterface === 'string') attributes.harness_interface = harnessInterface;
  attributes.provider = provider.provider;
  if (provider.gatewayHost !== undefined) attributes.gateway_host = provider.gatewayHost;

  // Activity-display attributes (read verbatim by the Activity page).
  attributes.harness = harnessFromTool(input.tool);
  attributes.cwd = input.cwd;
  if (input.harnessVersion !== undefined) attributes.version = input.harnessVersion;
  const hostName = ctx.host?.attributes.host_name;
  if (typeof hostName === 'string') attributes.host = hostName;
  // `project` is the bare slug; `repo` the owner/repo NWO (only when a remote
  // exists) — kept distinct so the detail pane doesn't show the same string twice.
  if (ctx.project) attributes.project = ctx.project.name;
  const nwo = resolveRepoNwo(input.cwd);
  if (nwo !== undefined) attributes.repo = nwo;
  if (branch !== undefined) attributes.branches = [branch];
  // The session's scope key, as rootPlan chose it: the canonical `host/owner/repo`
  // of the repository the session's own cwd sits in (sessionRootScopeKey), or,
  // for a coding-agent session signed in to a recognised work account outside any
  // repository in scope, that account's agent key. A local-only attribute that
  // every forward path strips. A scoped attachment forwards a structural leaf
  // only when its own key AND its root's are both in scope; the attached
  // gateway's verdict makes that check, not this hook.
  // A relative or empty cwd gets no key, however the project resolved: the
  // project is found by walking from the cwd by name, so a relative one is read
  // against this hook's own process directory and would borrow whatever
  // repository that is. A repository with no remote, or a remote that names a
  // path on this machine, yields no key rather than a machine-local one. A
  // path-less capture in the same cwd carries the same key, because both read
  // it from resolveRepoAttribution; a capture keyed by a file or search root it
  // names may differ from its root's. The config_scan row (buildConfigScanEvent)
  // is deliberately never keyed: it describes the machine, not a repository.
  //
  // A web chat session's root is never keyed (sessionToolIsKeyed). It has no
  // working directory: the browser host passes the home directory as a stand-in
  // so that no project resolves. A home directory that is itself a checkout does
  // resolve one, and the root would then carry that repository's key though the
  // session is not in it. Only the key is withheld; every other attribute
  // resolves as before.
  if (scopeKey !== undefined) attributes.scope_key = scopeKey;

  const event: AuditEventInput = {
    id: sessionId,
    eventType: 'session',
    startedAt: new Date().toISOString(),
  };
  if (resolved.hostId) event.hostId = resolved.hostId;
  if (resolved.harnessId) event.harnessId = resolved.harnessId;
  if (resolved.sourceProjectId) event.sourceProjectId = resolved.sourceProjectId;
  if (Object.keys(attributes).length > 0) event.attributes = attributes;
  return event;
}
