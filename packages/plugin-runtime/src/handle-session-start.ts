import { randomUUID } from 'node:crypto';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import {
  claimSessionStart,
  configPostureDefinitions,
  evaluateConfigPosture,
  loadConfig,
  resolveConfigInventory,
  resolveGitBranch,
  resolveHeadRoot,
  resolveInventoryContext,
  resolveProjectFiles,
  resolveRepoNwo,
  resolveWorktreeRoot,
} from '@akasecurity/plugin-sdk';
import type {
  AuditEventInput,
  ConfigScanResult,
  InventoryContext,
  ResolvedInventory,
} from '@akasecurity/schema';
import { configInventoryInputs, harnessFromTool } from '@akasecurity/schema';

import { pluginRecordedBy } from './recorder.ts';
import { resolveDataGateway } from './resolve.ts';
import { StandaloneDataGateway } from './standalone-gateway.ts';

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
  tool: string;
  harnessVersion?: string | undefined;
  harnessInterface?: string | undefined;
  // Injectable for tests only (keeps the config scan off the test machine's
  // real ~/.claude); adapters omit it and the scanner resolves os.homedir().
  homeDir?: string | undefined;
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
): Promise<{ staleBinaryNotice: string | null }> {
  // The stale-session notice (prevention P2), surfaced by the adapter once
  // per session; every guarded/early path stays silent.
  const silent = { staleBinaryNotice: null };
  try {
    // No session id → nothing to key the root on or dedupe against.
    if (!input.sessionId) return silent;
    // Run once per session; a later SessionStart for the same session no-ops
    // (and the notice rides the claim, so it can never repeat mid-session).
    if (!claimSessionStart(config.dataDir, input.sessionId)) return silent;

    // SessionStart is the one hook that knows the plugin's own version (the
    // manifest path rides its argv), so it stamps the inventory recording.
    const gateway = resolveDataGateway(
      config,
      input.harnessVersion !== undefined
        ? { recordedBy: pluginRecordedBy(input.harnessVersion) }
        : undefined,
    );
    try {
      // Machine/repo facts only; the writer adds the local user account.
      const ctx = resolveInventoryContext({
        cwd: input.cwd,
        tool: input.tool,
        harnessVersion: input.harnessVersion,
        harnessInterface: input.harnessInterface,
      });
      const resolved = await gateway.ensureInventory(ctx);
      // The current branch, read from this worktree's HEAD (pure file I/O, no
      // git spawn) — the one session-display fact not already on `ctx`.
      const branch = resolveGitBranch(input.cwd);
      await gateway.recordAuditEvent(
        buildSessionRoot(input.sessionId, input, ctx, resolved, config.provider, branch),
      );
      // The config-inventory pass (skills + hooks), under the same once-per-
      // session claim. Guarded separately: a scanner bug must not take the
      // just-written session root down with it.
      await recordConfigInventory(gateway, input.sessionId, input.cwd, input.homeDir);
      // Best-effort store maintenance, standalone only: purge terminal
      // exception rows past retention. Swallowed — a failed sweep must never
      // break SessionStart, and evaluation never depends on it.
      if (gateway instanceof StandaloneDataGateway) {
        try {
          await gateway.sweepTerminalExceptions(EXCEPTION_RETENTION_MS);
        } catch {
          // best-effort
        }
        // The project-file inventory pass (the Inventory page's file tree),
        // standalone-only like the sweep. Guarded separately: a walk bug must
        // never take the session root or config scan down with it.
        try {
          if (resolved.sourceProjectId) {
            const filesScan = resolveProjectFiles(input.cwd);
            if (filesScan) await gateway.recordProjectFiles(resolved.sourceProjectId, filesScan);
          }
        } catch {
          // Fail-open: a failed walk drops the tree update, never the session.
        }
        // Self-heal ghost projects the pre-worktree-fix resolver minted for
        // checkout paths — one fixed-plugin session clears them for good.
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
        // The stale-session check (P2): only meaningful when this session
        // knows its own version; internally fail-open (null on any error).
        if (input.harnessVersion !== undefined) {
          return { staleBinaryNotice: gateway.staleBinaryNotice(input.harnessVersion) };
        }
      }
    } finally {
      await gateway.close();
    }
  } catch {
    // Fail-open: SessionStart inventory must never break a session.
  }
  return silent;
}

// Scan the machine's Claude Code config surface and commit it as one atomic
// record: the skill/hook inventory upserts + the `config_scan` audit event they
// were seen by, hung off the session root. Fail-open like everything on this
// path.
async function recordConfigInventory(
  gateway: DataGateway,
  sessionId: string,
  cwd: string,
  homeDir?: string,
): Promise<void> {
  try {
    const scan = resolveConfigInventory({ cwd, homeDir });
    // Pure posture pass over the scan (hook conflicts / unknown hooks /
    // external egress). Findings reference their rule by (ruleId, version)
    // natural key; persistence resolves the definition ids — so definitions
    // ride the same atomic record (idempotent content-addressed upserts).
    const findings = evaluateConfigPosture(scan);
    await gateway.recordConfigScan({
      items: configInventoryInputs(scan),
      scanEvent: buildConfigScanEvent(sessionId, scan),
      definitions: configPostureDefinitions(),
      findings,
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
): AuditEventInput {
  const attributes: Record<string, unknown> = {};
  const osVersion = ctx.host?.attributes.os_version;
  const harnessVersion = ctx.harness?.attributes.harness_version;
  if (typeof osVersion === 'string') attributes.os_version = osVersion;
  if (typeof harnessVersion === 'string') attributes.harness_version = harnessVersion;
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
