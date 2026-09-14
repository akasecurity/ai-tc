/**
 * The native-messaging host — the one Node-side process Chrome spawns (per
 * `aka extension install`'s manifest) to bridge background.ts's requests into
 * the same @akasecurity/plugin-runtime entry points the CLI-hook plugins use
 * (handleSessionStart, handleCapture). Speaks Chrome's length-prefixed-JSON
 * framing (./wire.ts) over stdin/stdout instead of the hooks' bare
 * JSON-over-stdin, but the persistence wiring underneath is identical.
 *
 * Long-lived (one process serves every message for as long as the extension
 * keeps the native-messaging port open), unlike the short-lived hook scripts —
 * so config is reloaded fresh per request rather than once at startup, same
 * rationale as loadConfig()'s own doc comment (a hook process is short-lived;
 * this process is long-lived, but settings.json can still change under it).
 *
 * Fail-open like every other AKA entry point: a malformed or unrecognized
 * frame is skipped rather than crashing the host, and any request that throws
 * gets an `error` response instead of taking the process down.
 */
import { randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import type { Readable, Writable } from 'node:stream';

import { handleCapture, handleSessionStart, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type {
  PluginConfig,
  ResolvedCodexProvider,
  ResolvedProvider,
} from '@akasecurity/plugin-sdk';
import {
  deriveWebCaptureState,
  loadConfig,
  offersCaptureStatusReader,
  scanText,
} from '@akasecurity/plugin-sdk';
import type { ActionTaken, SourceTool, StoredCaptureStatus } from '@akasecurity/schema';
import {
  isWebChatCaptureConsentValid,
  pickReportedCaptureStatus,
  SOURCE_TOOL,
  toCaptureStatusAttributes,
  WebCaptureStatus,
  webChatCaptureOf,
  WebExchange,
} from '@akasecurity/schema';

// Named imports, not a default import: esbuild tree-shakes named JSON exports
// down to the two strings, while a default import inlines the whole manifest —
// scripts and dependency lists included — into the shipped bundle.
import { name as pkgName, version as pkgVersion } from '../../package.json';
import { capResponseText, toLlmCallInput, toToolCallInputs } from './exchange.ts';
import type { HostRequest, HostResponse, WebSourceTool } from './protocol.ts';
import { isHostRequest } from './protocol.ts';
import { readMessages, writeMessage } from './wire.ts';

const WEB_TOOL_TO_SOURCE: Record<WebSourceTool, SourceTool> = {
  [SOURCE_TOOL.ChatGpt]: SOURCE_TOOL.ChatGpt,
  [SOURCE_TOOL.ClaudeAi]: SOURCE_TOOL.ClaudeAi,
};

// Every site this host serves, in the schema's own declared order — derived
// from the map above rather than re-listed, so the two cannot drift.
const WEB_SOURCE_TOOLS = Object.keys(WEB_TOOL_TO_SOURCE) as WebSourceTool[];

// The build identity the attached posture report stamps (see
// `resolveDataGateway`'s `meta.pluginBuild`). Read from this package's own
// manifest at bundle time — the installed host ships as a single script with
// no package.json beside it, so a runtime lookup has nothing to find.
const PLUGIN_BUILD = { package: pkgName, version: pkgVersion };

// The most sessions whose last reported capture status this process keeps.
// Slack, not a budget: one host process serves one browser, and a tab that is
// closed never reports again.
const MAX_TRACKED_SESSIONS = 32;

export interface TrackedCaptureStatus {
  tool: WebSourceTool;
  status: WebCaptureStatus;
  // When the host received it, ISO-8601.
  observedAt: string;
}

// In memory, per host process — a write-through CACHE rather than the system
// of record. The durable home is the `capture_status` audit_events row the
// `capture_status` case below writes on every report; this map exists only as
// a fail-open fallback for `capture_state`, so a contended or unopenable store
// still answers this process's own recent reports.
const captureStatuses = new Map<string, TrackedCaptureStatus>();

/** The last capture status this PROCESS was told about for a session. */
export function readCaptureStatus(sessionId: string): TrackedCaptureStatus | undefined {
  return captureStatuses.get(sessionId);
}

function recordCaptureStatus(sessionId: string, record: TrackedCaptureStatus): void {
  // Move to the most-recently-used end on a repeat report, then evict the
  // oldest entries once the bound is exceeded.
  captureStatuses.delete(sessionId);
  captureStatuses.set(sessionId, record);
  while (captureStatuses.size > MAX_TRACKED_SESSIONS) {
    const oldest = captureStatuses.keys().next().value;
    if (oldest === undefined) break;
    captureStatuses.delete(oldest);
  }
}

// The fail-open fallback `capture_state` reaches for: this process's own
// reports for a site, newest first. Not gated on consent — it reads back what
// was already recorded, and the response's own `consented` field is what says
// whether anything new is being recorded at all.
function trackedFor(tool: WebSourceTool): TrackedCaptureStatus[] {
  return [...captureStatuses.values()]
    .filter((record) => record.tool === tool)
    .sort((a, b) => (a.observedAt < b.observedAt ? 1 : a.observedAt > b.observedAt ? -1 : 0));
}

// chatgpt.com / claude.ai are each single-backend web apps — there's no local
// env signal to read (unlike the CLI resolvers, which sniff env vars a
// terminal session actually has), so this is a fixed tool → provider map
// rather than a resolver in the CLI sense. 'ping' has no tool, so it falls
// through to the default.
function resolveWebProvider(
  tool: WebSourceTool | undefined,
): () => ResolvedProvider | ResolvedCodexProvider {
  return () => (tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' });
}

// Injectable so tests can point at a scratch dataDir instead of the real
// ~/.aka, mirroring the DI seam every hook/handler in this repo already uses
// (resolveProviderFn, gatewayFactory, homeDir, …).
export type ConfigForTool = (tool: WebSourceTool | undefined) => PluginConfig;

const defaultConfigForTool: ConfigForTool = (tool) =>
  loadConfig(undefined, resolveWebProvider(tool));

export async function handleRequest(
  request: HostRequest,
  configForTool: ConfigForTool = defaultConfigForTool,
): Promise<HostResponse> {
  switch (request.type) {
    case 'ping': {
      const config = configForTool(undefined);
      return {
        type: 'ping',
        requestId: request.requestId,
        ok: true,
        dbPath: config.dbPath,
        onboarded: config.onboarded,
      };
    }
    case 'session_start': {
      const config = configForTool(request.tool);
      // Browser sessions have no cwd/git repo to resolve a project from;
      // os.homedir() stands in so resolveInventoryContext's
      // resolveRepoIdentity(cwd) simply finds nothing and ctx.project stays
      // unset — the same outcome a non-repo CLI session already produces.
      await handleSessionStart(
        {
          sessionId: request.sessionId,
          cwd: homedir(),
          // Mapped, exactly as the capture branch below maps it. The two ids are
          // identical today, so passing `request.tool` raw here worked — but the
          // session root's `harness` is derived from THIS value and its captures'
          // `source_tool` from that one, so the first web provider whose web id
          // differs from its wire id would split a session from its own events.
          tool: WEB_TOOL_TO_SOURCE[request.tool],
          harnessInterface: request.hostname,
          pluginBuild: PLUGIN_BUILD,
        },
        config,
      );
      return { type: 'session_start', requestId: request.requestId, ok: true };
    }
    case 'health': {
      const config = configForTool(undefined);
      const gateway = resolveDataGateway(config);
      try {
        const summary = await gateway.healthSummary();
        return {
          type: 'health',
          requestId: request.requestId,
          ok: true,
          findings: summary.findings,
          bySeverity: summary.bySeverity,
        };
      } finally {
        await gateway.close();
      }
    }
    case 'capture': {
      const config = configForTool(request.tool);
      const result = await handleCapture(
        {
          kind: request.kind,
          sourceTool: WEB_TOOL_TO_SOURCE[request.tool],
          text: request.text,
          metadata: { sessionId: request.sessionId },
        },
        config,
      );
      const ruleIds = [...new Set(result.findings.map((f) => f.ruleId))];
      // `text` rides back only when the content script needs it (see
      // CaptureResponse in protocol.ts): the masked rewrite for redact, null
      // for block. Chrome caps host→Chrome messages at 1 MB, so a redact of
      // a prompt whose masked form exceeds that will kill the port — the
      // extension then fails open and sends the ORIGINAL text, the same
      // degradation as an unreachable host.
      const text =
        result.action === 'block'
          ? { text: null }
          : result.action === 'redact' && result.text !== null
            ? { text: result.text }
            : {};
      return {
        type: 'capture',
        requestId: request.requestId,
        ok: true,
        action: result.action,
        ...text,
        ruleIds,
        ...(result.blockedReferences ? { blockedReferences: result.blockedReferences } : {}),
      };
    }
    case 'exchange': {
      const config = configForTool(request.tool);
      const webChat = webChatCaptureOf(config.settings);
      // Read live, every call: settings.json can change under this long-lived
      // process, and a revocation must apply to the very next exchange frame.
      // No module-level snapshot, no memoisation, no hoisting this check out
      // of the switch.
      if (!isWebChatCaptureConsentValid(webChat.consent)) {
        return {
          type: 'exchange',
          requestId: request.requestId,
          ok: true,
          accepted: false,
          skipped: 'no-consent',
          llmCalls: 0,
          toolCalls: 0,
          ruleIds: [],
        };
      }

      const parsed = WebExchange.safeParse(request.exchange);
      if (!parsed.success) {
        return {
          type: 'error',
          requestId: request.requestId,
          ok: false,
          message: 'malformed exchange payload',
        };
      }
      const exchange = capResponseText(parsed.data);

      const llm = toLlmCallInput(exchange, request.sessionId, request.tool);
      if (llm === null) {
        return {
          type: 'exchange',
          requestId: request.requestId,
          ok: true,
          accepted: false,
          skipped: 'unkeyable',
          llmCalls: 0,
          toolCalls: 0,
          ruleIds: [],
        };
      }

      let llmCalls = 0;
      let toolCalls = 0;
      const gateway = resolveDataGateway(config);
      try {
        // FK-safety: audit_events.parent_id/root_session_id are enforced FKs
        // and INSERT OR IGNORE does not suppress a foreign-key violation, so a
        // leaf written before the root raises and rolls its transaction back.
        // An attribute-less stub: a real root arriving later heals it in
        // place, and a stub never overwrites one that is already populated.
        await gateway.recordAuditEvent({
          id: request.sessionId,
          eventType: 'session',
          startedAt: exchange.startedAt,
        });
        await gateway.recordLlmCall(llm);
        llmCalls = 1;
        // Per-rule installed-pack versions, so a tool-call finding cites the
        // pack version that actually fired instead of the rule file's format
        // version. The definition row id hashes (ruleId, version), so without
        // this the same rule firing on a CLI tool call and on a web one mints
        // two rows. Best-effort: an unreadable bundle leaves the map undefined
        // and scanText falls back to the less precise string — never a missed
        // detection.
        let ruleVersions: Record<string, string> | undefined;
        try {
          ruleVersions = (await gateway.getPolicyBundle()).ruleVersions;
        } catch {
          ruleVersions = undefined;
        }
        const tools = toToolCallInputs(exchange, request.sessionId, (text) =>
          scanText(text, ruleVersions),
        );
        if (tools.length > 0) {
          await gateway.recordToolCalls(tools);
          toolCalls = tools.length;
        }
      } catch {
        // Fail-open: a contended or refused write costs this exchange's
        // leaves and nothing else. The counts above say how many leaves this
        // host submitted, which a deterministic id may collapse onto a row
        // that is already there.
      } finally {
        await gateway.close();
      }

      const text = exchange.responseText;
      let responseAction: { responseAction?: ActionTaken } = {};
      let ruleIds: string[] = [];
      if (text !== undefined && text.length > 0 && webChat.responses !== 'never') {
        const result = await handleCapture(
          {
            kind: 'response',
            sourceTool: WEB_TOOL_TO_SOURCE[request.tool],
            text,
            occurredAt: exchange.startedAt,
            metadata: {
              sessionId: request.sessionId,
              // Read off the leaf's OWN attributes, which are already
              // trimmed — deriving them again here would let the capture and
              // the leaf disagree about the trimmed form.
              ...(llm.attributes.model !== undefined ? { model: llm.attributes.model } : {}),
              messageId: llm.messageId,
              ...(llm.attributes.site_conversation_id !== undefined
                ? { conversationId: llm.attributes.site_conversation_id as string }
                : {}),
              ...(exchange.turnIndex !== undefined ? { turnIndex: exchange.turnIndex } : {}),
            },
          },
          config,
          // No rewritable: false. Nothing about a response is rewritable in
          // the sense that field means (a host input it must not mutate) —
          // saying so here would degrade a resolved redact to
          // settings.redactFallback, trading a meaningless decision for a
          // real leak at rest. No dedupe, no preAuthorizedGrantIds either.
          { persist: webChat.responses === 'always' ? 'always' : 'with-findings' },
        );
        responseAction = { responseAction: result.action };
        ruleIds = [...new Set(result.findings.map((f) => f.ruleId))];
      }

      return {
        type: 'exchange',
        requestId: request.requestId,
        ok: true,
        accepted: true,
        llmCalls,
        toolCalls,
        ...responseAction,
        ruleIds,
      };
    }
    case 'capture_status': {
      const config = configForTool(request.tool);
      const webChat = webChatCaptureOf(config.settings);
      if (!isWebChatCaptureConsentValid(webChat.consent)) {
        return {
          type: 'capture_status',
          requestId: request.requestId,
          ok: true,
          accepted: false,
          skipped: 'no-consent',
        };
      }
      const parsed = WebCaptureStatus.safeParse(request.status);
      if (!parsed.success) {
        return {
          type: 'error',
          requestId: request.requestId,
          ok: false,
          message: 'malformed capture status payload',
        };
      }
      const observedAt = new Date().toISOString();
      recordCaptureStatus(request.sessionId, {
        tool: request.tool,
        status: parsed.data,
        observedAt,
      });
      // The durable home: a `capture_status` audit_events row, so a restarted
      // host and a separate process (`aka extension status`) both have
      // somewhere to read the same answer from. No explicit session-root stub
      // — recordAuditEvent ensures the root itself whenever rootSessionId !==
      // id (see StandaloneDataGateway.recordAuditEvent).
      const gateway = resolveDataGateway(config);
      try {
        await gateway.recordAuditEvent({
          id: randomUUID(),
          eventType: 'capture_status',
          startedAt: observedAt,
          parentId: request.sessionId,
          rootSessionId: request.sessionId,
          attributes: toCaptureStatusAttributes(parsed.data, request.tool),
        });
      } catch {
        // Fail-open: a contended store costs this report and nothing else.
        // The in-memory copy above still answers this process's own popup
        // queries.
      } finally {
        await gateway.close();
      }
      return { type: 'capture_status', requestId: request.requestId, ok: true, accepted: true };
    }
    case 'capture_state': {
      const config = configForTool(undefined);
      const webChat = webChatCaptureOf(config.settings);
      let stored: StoredCaptureStatus[] = [];
      const gateway = resolveDataGateway(config);
      try {
        if (offersCaptureStatusReader(gateway)) stored = await gateway.readCaptureStatuses();
      } catch {
        stored = [];
      } finally {
        await gateway.close();
      }
      const sites = WEB_SOURCE_TOOLS.map((tool) => {
        // Both sources in one preference order, newest first, then the same
        // pick the store's own read makes. A stored row is not preferred for
        // being stored: under a fault that permits reads but refuses writes it
        // is the older answer, and preferring it positionally would report a
        // state this process has already been told is out of date. On an exact
        // tie the stored row leads, being the system of record.
        const storedRecord = stored.find((s) => s.tool === tool);
        const candidates: (StoredCaptureStatus | TrackedCaptureStatus)[] = [
          ...(storedRecord === undefined ? [] : [storedRecord]),
          ...trackedFor(tool),
        ].sort((a, b) => (a.observedAt < b.observedAt ? 1 : a.observedAt > b.observedAt ? -1 : 0));
        const record = pickReportedCaptureStatus(candidates);
        return {
          tool,
          state: deriveWebCaptureState(record?.status),
          ...(record !== undefined
            ? { enforcement: record.status.enforcement, observedAt: record.observedAt }
            : {}),
        };
      });
      return {
        type: 'capture_state',
        requestId: request.requestId,
        ok: true,
        consented: isWebChatCaptureConsentValid(webChat.consent),
        sites,
      };
    }
    default: {
      // A request type this contract does not define at all — every type it
      // DOES define now has a case above. Answered rather than dropped:
      // background.ts holds a pending entry per requestId, so a silent drop
      // leaves its caller waiting for the relay deadline instead of learning
      // at once. `isHostRequest` refuses these before runHost ever reaches
      // here, so the reply a real extension sees is that validator's — this
      // branch answers a direct caller (or a future HostRequest member no
      // case here has been extended to handle yet).
      const unrecognized = request as { type: string; requestId: string };
      return {
        type: 'error',
        requestId: unrecognized.requestId,
        ok: false,
        message: `unsupported request type: ${unrecognized.type}`,
      };
    }
  }
}

export async function runHost(
  stdin: Readable,
  stdout: Writable,
  configForTool: ConfigForTool = defaultConfigForTool,
): Promise<void> {
  for await (const raw of readMessages(stdin)) {
    if (!isHostRequest(raw)) {
      // A well-formed frame this host version doesn't recognize (extension/
      // host version skew) still gets an error reply when it carries a
      // requestId — background.ts holds a pending entry per requestId, and a
      // silent drop would leave the content script's already-intercepted
      // send hanging forever instead of failing open.
      if (typeof raw === 'object' && raw !== null && 'requestId' in raw) {
        const requestId = (raw as Record<string, unknown>).requestId;
        if (typeof requestId === 'string') {
          await writeMessage(stdout, {
            type: 'error',
            requestId,
            ok: false,
            message: 'unrecognized request',
          });
        }
      }
      continue;
    }
    try {
      const response = await handleRequest(raw, configForTool);
      await writeMessage(stdout, response);
    } catch (error) {
      await writeMessage(stdout, {
        type: 'error',
        requestId: raw.requestId,
        ok: false,
        message: error instanceof Error ? error.message : 'unknown error',
      });
    }
  }
}

async function main(): Promise<void> {
  await runHost(process.stdin, process.stdout);
}

// Native-messaging hosts run detached from the terminal, so there's no
// "user's session" left to protect the way the CLI hooks' fail-open exit
// guards it — but a crash here should still never do more than end the
// bridge (the extension just sees the port disconnect and can reconnect).
main().catch(() => {
  process.exit(0);
});
