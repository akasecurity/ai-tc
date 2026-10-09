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

import { recordDetectedWebAccount, webChatWithholding } from '@akasecurity/persistence';
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
  reportedCaptureDocumentForSite,
  scanText,
} from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  AuditEventInput,
  ReportedCaptureDocument,
  SourceTool,
  WebChatWithholding,
} from '@akasecurity/schema';
import {
  harnessFromTool,
  isScopeKeyEnrolled,
  isWebChatAccountGrantValid,
  isWebChatCaptureConsentValid,
  pickReportedCaptureStatus,
  SOURCE_TOOL,
  toCaptureStatusAttributes,
  webAccountKey,
  WebCaptureStatus,
  webChatCaptureOf,
  WebExchange,
} from '@akasecurity/schema';

// Named imports, not a default import: esbuild tree-shakes named JSON exports
// down to the two strings, while a default import inlines the whole manifest —
// scripts and dependency lists included — into the shipped bundle.
import { name as pkgName, version as pkgVersion } from '../../package.json';
import { capResponseText, toLlmCallInput, toToolCallInputs, trimmed } from './exchange.ts';
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

// The account each tab session's requests last named, in this process's memory
// only. It is what the popup shows, so the account can be enrolled without
// anything being stored; the detected-account record is the stored half, and is
// written only under the account grant. Bounded like the map above.
interface SessionAccount {
  tool: WebSourceTool;
  account: string;
  // When the host last received an exchange naming it, ISO-8601.
  seenAt: string;
}

const sessionAccounts = new Map<string, SessionAccount>();

/** The account this PROCESS last saw a session's requests name. */
export function readSessionAccount(sessionId: string): SessionAccount | undefined {
  return sessionAccounts.get(sessionId);
}

function recordSessionAccount(sessionId: string, record: SessionAccount): void {
  sessionAccounts.delete(sessionId);
  sessionAccounts.set(sessionId, record);
  while (sessionAccounts.size > MAX_TRACKED_SESSIONS) {
    const oldest = sessionAccounts.keys().next().value;
    if (oldest === undefined) break;
    sessionAccounts.delete(oldest);
  }
}

/** The account most recently seen on `tool` by this process, across its sessions. */
function latestAccountFor(tool: WebSourceTool): SessionAccount | undefined {
  let latest: SessionAccount | undefined;
  for (const record of sessionAccounts.values()) {
    if (record.tool !== tool) continue;
    if (latest === undefined || record.seenAt > latest.seenAt) latest = record;
  }
  return latest;
}

/**
 * Whether this machine records a web chat in `account`.
 *
 * Where web chats are not withheld, every account is recorded, as before. On a
 * personal device only an account enrolled with `aka enroll --account` is, read
 * live from the settings. A machine whose credential cannot be read records none,
 * whatever is enrolled: what it was attached as is unknown. Capture consent is a
 * separate check, made by the caller; both must pass.
 */
function recordsAccount(
  config: PluginConfig,
  withholding: WebChatWithholding | null,
  account: string | undefined,
): boolean {
  if (withholding === null) return true;
  return withholding === 'personal-device' && isScopeKeyEnrolled(config.settings, account);
}

/**
 * The session root an enrolled account's first recorded exchange writes on a
 * personal device, where the session start wrote none.
 *
 * It carries the account as its scope key, which is what the attached gateway
 * decides the session's leaves by, and only what identifies the chat: the
 * harness and the provider. No working directory, project, repository or host
 * name: those describe this machine, and the root is sent with the account's
 * records. Roots are first-write-wins, so a session's later exchanges leave it
 * as the first one wrote it.
 */
function accountSessionRoot(
  sessionId: string,
  startedAt: string,
  tool: WebSourceTool,
  account: string,
  config: PluginConfig,
): AuditEventInput {
  return {
    id: sessionId,
    eventType: 'session',
    startedAt,
    attributes: {
      scope_key: account,
      harness: harnessFromTool(WEB_TOOL_TO_SOURCE[tool]),
      provider: config.provider.provider,
    },
  };
}

// The fail-open fallback `capture_state` reaches for: this process's own
// reports for a site, one per document. Not gated on consent — it reads back
// what was already recorded, and the response's own `consented` field is what
// says whether anything new is being recorded at all.
//
// The map's KEY is the document's grouping id: the host writes each
// `capture_status` row with `rootSessionId === sessionId`, so these line up
// with the stored half of the merge below on the same id. Unsorted, because
// the fold this feeds is order-independent by construction.
function trackedFor(tool: WebSourceTool): ReportedCaptureDocument[] {
  return [...captureStatuses.entries()]
    .filter(([, record]) => record.tool === tool)
    .map(([sessionId, record]) => ({
      tool: record.tool,
      observedAt: record.observedAt,
      status: record.status,
      rootSessionId: sessionId,
      // One entry per session and every report overwrites it, so this IS the
      // document's last word — there is no older row here to pick between.
      lastReportAt: record.observedAt,
      closed: record.status.closed,
    }));
}

/**
 * The two halves of `capture_state`'s answer as one document list.
 *
 * Grouped by document rather than concatenated, because the fold downstream
 * takes the worst of a site's documents and a document appearing twice would
 * vote twice — harmless for the worst-of itself, but it moves the tiebreaks.
 * The two halves overlap by construction: the durable row and the in-memory
 * copy are written from the same report.
 *
 * Within a document the same within-document pick the store's own read makes,
 * so a watching-only report does not replace a verdict merely for being newer.
 * A stored row is not preferred for BEING stored: under a fault that permits
 * reads but refuses writes it is the older answer, and preferring it
 * positionally would report a state this process has already been told is out
 * of date. On an exact `observedAt` tie the stored row leads, being the system
 * of record — it comes first below and the sort is stable.
 */
function mergeCaptureDocuments(
  stored: readonly ReportedCaptureDocument[],
  tracked: readonly ReportedCaptureDocument[],
): ReportedCaptureDocument[] {
  const byDocument = new Map<string | undefined, ReportedCaptureDocument[]>();
  for (const document of [...stored, ...tracked]) {
    const group = byDocument.get(document.rootSessionId);
    if (group === undefined) byDocument.set(document.rootSessionId, [document]);
    else group.push(document);
  }
  const merged: ReportedCaptureDocument[] = [];
  for (const group of byDocument.values()) {
    const ordered = [...group].sort((a, b) =>
      a.observedAt < b.observedAt ? 1 : a.observedAt > b.observedAt ? -1 : 0,
    );
    const picked = pickReportedCaptureStatus(ordered);
    if (picked === undefined) continue;
    // Whether the document is still around comes from its newest report in
    // EITHER half, not from the row the pick landed on.
    let lastReportAt = picked.lastReportAt;
    let closed = picked.closed;
    for (const document of group) {
      if (document.lastReportAt > lastReportAt) {
        lastReportAt = document.lastReportAt;
        closed = document.closed;
      }
    }
    merged.push({ ...picked, lastReportAt, closed });
  }
  return merged;
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

/**
 * Why this host keeps nothing from a web chat, or null when it records one.
 *
 * On a personal device a web chat is never in scope. What a scoped attachment
 * forwards is decided per enrolled repository, a chat belongs to none, and
 * nothing yet recognizes a work account in a chat. A machine whose credential
 * cannot be read withholds too, since what it was attached as is unknown (see
 * `webChatWithholding`, the one reading every surface makes).
 *
 * Withheld, a prompt is still checked and its decision enforced, but no event
 * is recorded (a value it blocks or masks still leaves the masked, day-long
 * ledger entry `aka exception` approves from). An exchange is dropped on
 * arrival. A capture status is kept in this process's memory only, so the
 * popup can still say when a site is not being checked, and is never stored.
 * A session start opens no session root. What is never recorded cannot be sent
 * later either, including by a history sync after the machine is attached
 * again machine-wide.
 *
 * Read per request, since `aka attach` and `aka detach` change it under this
 * long-lived process. Never throws.
 */
function withheld(config: PluginConfig): WebChatWithholding | null {
  return webChatWithholding(config.settingsDir, config.settings);
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
      // Run even when chats are withheld, because the session start is what
      // refreshes the organization's policy and sends the device report for
      // someone who only uses web chat. Withheld, it records no session root
      // (see withheld).
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
          recordSession: withheld(config) === null,
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
      // Withheld, the prompt is checked and enforced exactly as anywhere else,
      // and recorded nowhere (see withheld).
      const result = await handleCapture(
        {
          kind: request.kind,
          sourceTool: WEB_TOOL_TO_SOURCE[request.tool],
          text: request.text,
          metadata: { sessionId: request.sessionId },
        },
        config,
        withheld(config) === null ? {} : { persist: 'never' },
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
      // Both read live, every call: settings.json and the attachment can change
      // under this long-lived process, and a revocation must apply to the very
      // next exchange frame. No module-level snapshot, no memoisation, no
      // hoisting either check out of the switch.
      //
      // The account the request's own URL named, or undefined. Kept in memory
      // for the popup whatever happens below, and written to the
      // detected-account record only under the account grant: neither is a
      // capture, so neither waits on the capture consent.
      const account = webAccountKey(request.tool, request.workspace);
      if (account !== undefined) {
        recordSessionAccount(request.sessionId, {
          tool: request.tool,
          account,
          seenAt: new Date().toISOString(),
        });
        if (isWebChatAccountGrantValid(webChat)) {
          recordDetectedWebAccount(config.dataDir, account, request.tool);
        }
      }
      // Withheld, the exchange goes no further than this unless its account is
      // enrolled (see recordsAccount): `isHostRequest` has already validated
      // the payload in `runHost`, and nothing past this point runs, so no leaf
      // is written and the reply is not scanned (see withheld).
      const withholding = withheld(config);
      const skipped = !isWebChatCaptureConsentValid(webChat.consent)
        ? ('no-consent' as const)
        : !recordsAccount(config, withholding, account)
          ? ('out-of-scope' as const)
          : undefined;
      if (skipped !== undefined) {
        return {
          type: 'exchange',
          requestId: request.requestId,
          ok: true,
          accepted: false,
          skipped,
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

      const llm = toLlmCallInput(exchange, request.sessionId, request.tool, account);

      let llmCalls = 0;
      let toolCalls = 0;
      // An exchange with no usable message id writes no LEAVES — the row id
      // hashes on that id, so a blank one would collapse every turn of a
      // conversation onto one row — but its REPLY is still scanned and
      // audited below. The reply is where a secret would be, and `messageId`
      // is only correlation metadata on that capture, so returning here cost
      // the one thing that cannot be recovered afterwards: the record that a
      // secret was sent. The response block needs no key.
      if (llm !== null) {
        // Resolved INSIDE the try, because opening the store is itself a way
        // for it to be unavailable: `openLocalDatabase` runs the migrations, so
        // an unopenable home throws here rather than on the first write.
        // Outside the try that escaped the whole case and cost the response
        // scan below with it — the one part of this that cannot be recovered
        // afterwards.
        let gateway: ReturnType<typeof resolveDataGateway> | undefined;
        try {
          gateway = resolveDataGateway(config);
          // FK-safety: audit_events.parent_id/root_session_id are enforced FKs
          // and INSERT OR IGNORE does not suppress a foreign-key violation, so a
          // leaf written before the root raises and rolls its transaction back.
          // An attribute-less stub: a real root arriving later heals it in
          // place, and a stub never overwrites one that is already populated.
          //
          // Withheld, this is an enrolled account's exchange (anything else
          // stopped above), and no session start wrote a root, so the account's
          // own root is written instead. Written on every exchange, like the
          // stub: the gateway decides a session's leaves by the root it records
          // on THIS request, and a later write leaves the first one as it was.
          await gateway.recordAuditEvent(
            withholding !== null && account !== undefined
              ? accountSessionRoot(
                  request.sessionId,
                  exchange.startedAt,
                  request.tool,
                  account,
                  config,
                )
              : { id: request.sessionId, eventType: 'session', startedAt: exchange.startedAt },
          );
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
          const tools = toToolCallInputs(
            exchange,
            request.sessionId,
            (text) => scanText(text, ruleVersions, { locate: true }),
            account,
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
          await gateway?.close();
        }
      }

      const text = exchange.responseText;
      let responseAction: { responseAction?: ActionTaken } = {};
      let ruleIds: string[] = [];
      // Read off the leaf's OWN attributes where there is one, which are
      // already trimmed — deriving them again would let the capture and the
      // leaf disagree about the trimmed form. With no leaf there is nothing to
      // disagree with, so the projection's own `trimmed` is applied here.
      const model = llm === null ? trimmed(exchange.model) : llm.attributes.model;
      const conversationId =
        llm === null
          ? trimmed(exchange.conversationId)
          : (llm.attributes.site_conversation_id as string | undefined);
      if (text !== undefined && text.length > 0 && webChat.responses !== 'never') {
        const result = await handleCapture(
          {
            kind: 'response',
            sourceTool: WEB_TOOL_TO_SOURCE[request.tool],
            text,
            occurredAt: exchange.startedAt,
            // The account as the capture's scope key, as on the leaves above.
            ...(account === undefined ? {} : { scopeKey: account }),
            metadata: {
              sessionId: request.sessionId,
              ...(model !== undefined ? { model } : {}),
              // Omitted for an unkeyable exchange rather than blanked: this is
              // correlation metadata, and an empty id correlates to nothing
              // while reading as an id that exists.
              ...(llm !== null ? { messageId: llm.messageId } : {}),
              ...(conversationId !== undefined ? { conversationId } : {}),
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
        // `accepted` is about the LEAVES, which an unkeyable exchange writes
        // none of — the response capture above may still have recorded a
        // finding, which `ruleIds` and `responseAction` report either way.
        accepted: llm !== null,
        ...(llm === null ? { skipped: 'unkeyable' as const } : {}),
        llmCalls,
        toolCalls,
        ...responseAction,
        ruleIds,
      };
    }
    case 'capture_status': {
      const config = configForTool(request.tool);
      const webChat = webChatCaptureOf(config.settings);
      // The one refusal shape, for both reasons below.
      const refused = (skipped: 'no-consent' | 'out-of-scope'): HostResponse => ({
        type: 'capture_status',
        requestId: request.requestId,
        ok: true,
        accepted: false,
        skipped,
      });
      // Read once: it decides both whether consent is asked and where the
      // report may go.
      const withholding = withheld(config);
      // Consent governs recording, and a withholding machine records nothing,
      // so there it has nothing to authorize: the report is still kept in
      // memory below, which is how the popup names a site that is not being
      // checked on a personal device that never granted capture.
      if (withholding === null && !isWebChatCaptureConsentValid(webChat.consent)) {
        return refused('no-consent');
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
      // Withheld, the report stays in this process's memory and goes no
      // further: the popup reads it to say when a site is not being checked,
      // and nothing stores or sends it (see withheld).
      if (withholding !== null) return refused('out-of-scope');
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
      const withholding = withheld(config);
      let stored: ReportedCaptureDocument[] = [];
      // Resolved INSIDE the try for the reason the exchange case gives:
      // opening the store runs the migrations, so an unopenable home throws
      // here rather than on the read, and outside the try that escaped into
      // runHost's generic error — turning the popup's whole reply into a
      // failure when this process's own in-memory map could have answered it.
      let gateway: ReturnType<typeof resolveDataGateway> | undefined;
      try {
        // Withheld, only this process's own reports answer: a stored row was
        // written before the machine stopped recording and describes reports it
        // no longer keeps.
        gateway = withholding === null ? resolveDataGateway(config) : undefined;
        if (gateway !== undefined && offersCaptureStatusReader(gateway)) {
          stored = await gateway.readCaptureStatuses();
        }
      } catch {
        stored = [];
      } finally {
        await gateway?.close();
      }
      const sites = WEB_SOURCE_TOOLS.map((tool) => {
        // Both halves merged per document, then the same per-site fold every
        // other surface makes — the popup is where a user looks first, and
        // taking the newest document's report here would hide a drifting tab
        // behind a healthy one exactly as the store read used to.
        const record = reportedCaptureDocumentForSite(
          mergeCaptureDocuments(
            stored.filter((s) => s.tool === tool),
            trackedFor(tool),
          ),
        );
        // The account this process last saw the site's requests name, whether
        // it is enrolled here, and whether this machine records chats in it:
        // consented, and either not withheld or enrolled on a personal device.
        const seen = latestAccountFor(tool);
        return {
          tool,
          // Withheld, the network path records nothing, so no site has a state
          // to report, whatever this process's memory says the tab saw. A popup
          // older than `withheld` renders this word rather than a stale live
          // one. The enforcement half is still this process's own report.
          state: deriveWebCaptureState(withholding === null ? record?.status : undefined),
          ...(record !== undefined
            ? { enforcement: record.status.enforcement, observedAt: record.observedAt }
            : {}),
          ...(seen === undefined
            ? {}
            : {
                account: {
                  identity: seen.account,
                  enrolled: isScopeKeyEnrolled(config.settings, seen.account),
                  recorded:
                    isWebChatCaptureConsentValid(webChat.consent) &&
                    recordsAccount(config, withholding, seen.account),
                },
              }),
        };
      });
      return {
        type: 'capture_state',
        requestId: request.requestId,
        ok: true,
        consented: isWebChatCaptureConsentValid(webChat.consent),
        ...(withholding === null ? {} : { withheld: withholding }),
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
