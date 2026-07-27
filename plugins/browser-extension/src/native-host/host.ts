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
import { homedir } from 'node:os';

import { handleCapture, handleSessionStart, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig, ResolvedCodexProvider, ResolvedProvider } from '@akasecurity/plugin-sdk';
import { loadConfig } from '@akasecurity/plugin-sdk';
import type { SourceTool } from '@akasecurity/schema';

import type { HostRequest, HostResponse, WebSourceTool } from './protocol.ts';
import { isHostRequest } from './protocol.ts';
import { readMessages, writeMessage } from './wire.ts';

const WEB_TOOL_TO_SOURCE: Record<WebSourceTool, SourceTool> = {
  chatgpt: 'chatgpt',
  'claude-ai': 'claude-ai',
};

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
          tool: request.tool,
          harnessInterface: request.hostname,
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
  }
}

async function main(): Promise<void> {
  for await (const raw of readMessages(process.stdin)) {
    if (!isHostRequest(raw)) {
      // A well-formed frame this host version doesn't recognize (extension/
      // host version skew) still gets an error reply when it carries a
      // requestId — background.ts holds a pending entry per requestId, and a
      // silent drop would leave the content script's already-intercepted
      // send hanging forever instead of failing open.
      if (typeof raw === 'object' && raw !== null && 'requestId' in raw) {
        const requestId = (raw as Record<string, unknown>).requestId;
        if (typeof requestId === 'string') {
          await writeMessage(process.stdout, {
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
      const response = await handleRequest(raw);
      await writeMessage(process.stdout, response);
    } catch (error) {
      await writeMessage(process.stdout, {
        type: 'error',
        requestId: raw.requestId,
        ok: false,
        message: error instanceof Error ? error.message : 'unknown error',
      });
    }
  }
}

// Native-messaging hosts run detached from the terminal, so there's no
// "user's session" left to protect the way the CLI hooks' fail-open exit
// guards it — but a crash here should still never do more than end the
// bridge (the extension just sees the port disconnect and can reconnect).
main().catch(() => {
  process.exit(0);
});
