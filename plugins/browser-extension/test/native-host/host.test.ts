import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { setDefaultGatewayFactory, standaloneGatewayFactory } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections, contentHashOf } from '@akasecurity/plugin-sdk';
import type {
  BuiltinPolicyId,
  WebCaptureStatus,
  WebChatCapture,
  WebChatResponseCapture,
  WebExchange,
} from '@akasecurity/schema';
import { RESPONSE_TEXT_MAX_BYTES, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { ConfigForTool } from '../../src/native-host/host.ts';
import { handleRequest, readCaptureStatus } from '../../src/native-host/host.ts';
import type { HostRequest, WebSourceTool } from '../../src/native-host/protocol.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// The canonical AWS example key id, composed at runtime so the repo's own
// secret scanning doesn't flag this file (see handle-capture.test.ts).
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-native-host-'));
});

afterEach(() => {
  removeTree(dir);
});

function config(tool: WebSourceTool | undefined, webChat?: WebChatCapture): PluginConfig {
  return {
    settings: {
      specVersion: 3,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
      ...(webChat !== undefined ? { webChatCapture: webChat } : {}),
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

// A granted, unexpired web-chat capture consent — the settings block a
// consented `configForTool` carries.
function webChatSettings(
  responses: WebChatResponseCapture = 'with-findings',
  version: number = WEB_CHAT_CAPTURE_CONSENT_VERSION,
): WebChatCapture {
  return {
    responses,
    account: false,
    consent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', version },
  };
}

function consentedConfig(responses: WebChatResponseCapture = 'with-findings'): ConfigForTool {
  return (tool) => config(tool, webChatSettings(responses));
}

// A minimal, schema-shaped exchange. Not passed through WebExchange.parse() —
// most of these cases exercise the handler's own logic, not the schema's.
function baseExchange(over: Partial<WebExchange> = {}): WebExchange {
  return {
    messageId: 'msg_1',
    startedAt: '2026-01-01T00:00:00.000Z',
    usageSource: 'none',
    toolCalls: [],
    truncated: false,
    ...over,
  };
}

function open(): DatabaseSync {
  return new DatabaseSync(join(dir, 'aka.db'));
}

// Every byte the store wrote under `dir`, so an at-rest leak is caught
// wherever it landed rather than only in the one row a test happened to
// query. Walks the directory rather than a hardcoded aka.db/-wal/-shm list.
function storeBytes(root: string): string {
  const walk = (from: string, prefix = ''): string[] =>
    readdirSync(from, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory()
        ? walk(join(from, entry.name), `${prefix}${entry.name}/`)
        : entry.isFile()
          ? [`${prefix}${entry.name}`]
          : [],
    );
  const parts: Buffer[] = [];
  for (const name of walk(root)) {
    try {
      parts.push(readFileSync(join(root, name)));
    } catch (err) {
      const code = typeof err === 'object' && err !== null && 'code' in err ? err.code : undefined;
      // Only an ENOENT on a SIBLING is tolerated (an atomic write's tmp file
      // vanishing mid-scan); the main store file is never atomically rewritten,
      // and any other failure is a real fault.
      if (name === DB_FILENAME || code !== 'ENOENT') throw err;
    }
  }
  return Buffer.concat(parts).toString('latin1');
}

describe('handleRequest (native-messaging host)', () => {
  it('answers ping with the resolved store path', async () => {
    const response = await handleRequest({ type: 'ping', requestId: 'r1' }, config);
    expect(response).toEqual({
      type: 'ping',
      requestId: 'r1',
      ok: true,
      dbPath: join(dir, 'aka.db'),
      onboarded: true,
    });
  });

  it('answers a request type it does not know at all, rather than dropping it', async () => {
    // `exchange` and `capture_status` now have handlers below; this exercises
    // the `default` branch for a type the wire contract does not define at
    // all. background.ts holds a pending entry per requestId, so a silent
    // drop leaves its caller waiting out the relay deadline instead of
    // learning at once. In a real extension `isHostRequest` refuses this
    // first — this is the direct caller's path.
    const response = await handleRequest(
      { type: 'shutdown', requestId: 'u1' } as unknown as HostRequest,
      config,
    );
    expect(response).toEqual({
      type: 'error',
      requestId: 'u1',
      ok: false,
      message: 'unsupported request type: shutdown',
    });
  });

  it('opens a session root for session_start, stamping the tab hostname as harness_interface', async () => {
    const response = await handleRequest(
      {
        type: 'session_start',
        requestId: 'r2',
        sessionId: 'browser-s1',
        tool: 'claude-ai',
        hostname: 'claude.ai',
      },
      config,
    );
    expect(response).toEqual({ type: 'session_start', requestId: 'r2', ok: true });

    const db = open();
    const session = db
      .prepare("SELECT * FROM audit_events WHERE event_type = 'session' AND id = 'browser-s1'")
      .get() as Record<string, unknown>;
    const attrs = JSON.parse(session.attributes as string) as Record<string, unknown>;
    db.close();

    expect(attrs.harness).toBe('claudeai');
    expect(attrs.harness_interface).toBe('claude.ai');
    expect(attrs.provider).toBe('anthropic');
  });

  it('resolves the session_start gateway with this package as pluginBuild', async () => {
    // The host is one of the callers whose posture report must carry the build
    // identity — a session_start resolved without it clears the control
    // plane's plugin columns whenever this path wins the hourly throttle.
    // Captured at the gateway-factory seam, through the real handleSessionStart.
    let captured: unknown = 'never-resolved';
    const restore = setDefaultGatewayFactory((cfg, meta) => {
      captured = meta;
      return standaloneGatewayFactory(cfg, meta);
    });
    try {
      const response = await handleRequest(
        {
          type: 'session_start',
          requestId: 'r-meta',
          sessionId: 'browser-s-meta',
          tool: 'claude-ai',
          hostname: 'claude.ai',
        },
        config,
      );
      expect(response).toEqual({ type: 'session_start', requestId: 'r-meta', ok: true });
    } finally {
      restore();
    }
    const pkg = JSON.parse(
      readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
    ) as { name: string; version: string };
    expect(captured).toStrictEqual({
      pluginBuild: { package: pkg.name, version: pkg.version },
    });
  });

  it('records a capture and returns its action + rule ids', async () => {
    const text = `here is ${AWS_EXAMPLE_KEY} value`;
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'r3',
        sessionId: 'browser-s2',
        tool: 'chatgpt',
        kind: 'prompt',
        text,
      },
      config,
    );
    expect(response.type).toBe('capture');
    if (response.type !== 'capture') throw new Error('unreachable');
    // The bundled secrets pack is unassigned by default, so it monitors (log),
    // and at-rest masking follows that decision — same as handleCapture's own test.
    expect(response.action).toBe('log');
    expect(response.ruleIds).toContain('secrets/aws-access-key');
    // No composer rewrite needed for a log outcome, so the (possibly large)
    // prompt text is NOT echoed back over the 1 MB-capped host→Chrome pipe.
    expect(response.text).toBeUndefined();

    const db = open();
    const row = db.prepare('SELECT source_tool, content, metadata FROM events').get() as {
      source_tool: string;
      content: string;
      metadata: string;
    };
    db.close();

    expect(row.source_tool).toBe('chatgpt');
    // Monitored, so the row holds the capture verbatim: the unflagged text AND
    // the matched span, with no placeholder standing in for a value enforcement
    // was never going to strip.
    expect(row.content).toContain('here is');
    expect(row.content).toContain('value');
    expect(row.content).toBe(text);
    expect(row.content).not.toContain('[REDACTED:SECRET]');
    expect(JSON.parse(row.metadata) as Record<string, unknown>).toMatchObject({
      sessionId: 'browser-s2',
    });
  });

  it('answers health with the store-wide findings tally after a capture lands a finding', async () => {
    await handleRequest(
      {
        type: 'capture',
        requestId: 'h1',
        sessionId: 'browser-s4',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `key: ${AWS_EXAMPLE_KEY}`,
      },
      config,
    );

    const response = await handleRequest({ type: 'health', requestId: 'h2' }, config);
    expect(response.type).toBe('health');
    if (response.type !== 'health') throw new Error('unreachable');
    expect(response.findings).toBeGreaterThanOrEqual(1);
    expect(response.bySeverity.critical).toBeGreaterThanOrEqual(1);
  });

  it('is fail-open: an unusable data dir degrades capture to log + original text, never throws', async () => {
    // Point dataDir at a regular file so opening the store throws while resolving —
    // same setup as handleCapture's own fail-open test.
    const filePath = join(dir, 'blocker');
    writeFileSync(filePath, 'x');
    const broken = (tool: WebSourceTool | undefined): PluginConfig => ({
      ...config(tool),
      dataDir: filePath,
      dbPath: join(filePath, 'aka.db'),
    });

    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'r4',
        sessionId: 'browser-s3',
        tool: 'claude-ai',
        kind: 'prompt',
        text: 'SECRET_MARKER',
      },
      broken,
    );
    expect(response).toEqual({
      type: 'capture',
      requestId: 'r4',
      ok: true,
      action: 'log',
      ruleIds: [],
    });
  });
});

// The capture text-shaping contract against a seeded per-detection policy —
// the same installed_packs.policy_id assignment the Detections dashboard
// writes. The secret value comes from the bundled rule's own `examples`
// fixture so no secret-shaped literal lives in this file.
const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}
const { pack: SECRET_PACK, example: SECRET_EXAMPLE } = secretFixture();

// A second value that fires the SAME rule — so masking is exercised
// identically — without being the rule's own literal `examples` entry, which
// `seedSecretPolicy` legitimately stores verbatim in installed_packs.rules_json.
// A whole-store byte scan (see storeBytes) against the example itself would
// misreport that legitimate copy as a leak of this exchange's own data.
// Matches the rule's `\bAC[A-Za-z0-9]{32}\b` pattern (same "AC" prefix, 32
// more alnum characters) but an all-LETTER body where the example is all
// digits, so no 8-character run of one can appear in the other — a mutation
// like flipping a single trailing digit would still share the same repeating
// "1234567890" cycle the example is built from, and would still collide.
const SECRET_AT_REST = `ACQWERTYUIOPASDFGHJKLZXCVBNMqwerty`;

// Install the bundled packs the way the gateway does on open, then assign the
// secrets pack the policy under test — per-rule pack policies are what the
// runtime's action resolution prefers.
function seedSecretPolicy(policyId: BuiltinPolicyId): void {
  const db = openLocalDatabase(dir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, policyId);
  } finally {
    db.close();
  }
}

async function captureSecret(): Promise<
  Extract<Awaited<ReturnType<typeof handleRequest>>, { type: 'capture' }>
> {
  const response = await handleRequest(
    {
      type: 'capture',
      requestId: 'p1',
      sessionId: 'browser-p1',
      tool: 'chatgpt',
      kind: 'prompt',
      text: `deploy with ${SECRET_EXAMPLE} now`,
    },
    config,
  );
  if (response.type !== 'capture') throw new Error('expected a capture response');
  return response;
}

describe('capture response text shaping (per-detection policy)', () => {
  it('block: the response carries text: null so the composer sends nothing', async () => {
    seedSecretPolicy('block');
    const response = await captureSecret();

    expect(response.action).toBe('block');
    expect(response.text).toBeNull();
    expect(response.ruleIds).toContain(RULE_ID);
  });

  it('redact: the response text is the masked rewrite, never the raw value', async () => {
    seedSecretPolicy('redact');
    const response = await captureSecret();

    expect(response.action).toBe('redact');
    expect(response.text).toBeTypeOf('string');
    expect(response.text).toContain('[REDACTED:SECRET]');
    // Same positive control as the stored-row case above.
    expect(response.text).toContain('deploy with');
    expect(response.text).not.toContain(SECRET_EXAMPLE);
    expect(response.ruleIds).toContain(RULE_ID);
  });
});

describe('exchange (recording a web-chat turn)', () => {
  it('lands one llm_call, one tool_call and one masked response row', async () => {
    seedSecretPolicy('redact');
    const originalText = `the answer is ${SECRET_EXAMPLE} ok`;
    const exchange = baseExchange({
      messageId: 'msg_e1',
      model: 'gpt-4o',
      usage: { inputTokens: 11, outputTokens: 22 },
      usageSource: 'site',
      conversationId: 'conv_e1',
      turnIndex: 2,
      toolCalls: [{ toolUseId: 'tu_e1', toolName: 'web_search', target: 'weather in paris' }],
      responseText: originalText,
    });

    const response = await handleRequest(
      { type: 'exchange', requestId: 'e1', sessionId: 'browser-e1', tool: 'chatgpt', exchange },
      consentedConfig(),
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    expect(response.accepted).toBe(true);
    expect(response.llmCalls).toBe(1);
    expect(response.toolCalls).toBe(1);
    expect(response.responseAction).toBe('redact');
    expect(response.ruleIds).toContain(RULE_ID);

    const db = open();
    const llm = db
      .prepare(
        "SELECT attributes FROM audit_events WHERE event_type = 'llm_call' AND root_session_id = 'browser-e1'",
      )
      .get() as { attributes: string } | undefined;
    const tool = db
      .prepare(
        "SELECT attributes FROM audit_events WHERE event_type = 'tool_call' AND root_session_id = 'browser-e1'",
      )
      .get() as { attributes: string } | undefined;
    const resp = db
      .prepare(
        "SELECT content, content_hash, attributes FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-e1'",
      )
      .get() as { content: string; content_hash: string; attributes: string } | undefined;
    db.close();

    if (llm === undefined) throw new Error('expected an llm_call row');
    const llmAttrs = JSON.parse(llm.attributes) as Record<string, unknown>;
    expect(llmAttrs.model).toBe('gpt-4o');
    expect(llmAttrs.provider).toBe('chatgpt');
    expect(llmAttrs.message_id).toBe('msg_e1');
    expect(llmAttrs.run_key).toBe('conv_e1');
    expect(llmAttrs.usage_source).toBe('site');
    expect(llmAttrs.input_tokens).toBe(11);
    expect(llmAttrs.output_tokens).toBe(22);

    if (tool === undefined) throw new Error('expected a tool_call row');
    const toolAttrs = JSON.parse(tool.attributes) as Record<string, unknown>;
    expect(toolAttrs.tool_name).toBe('web_search');
    expect(toolAttrs.tool_use_id).toBe('tu_e1');

    if (resp === undefined) throw new Error('expected a response row');
    // Positive control first, so the absence check below is not passing on
    // empty bytes.
    expect(resp.content).toContain('the answer is');
    expectNoEchoOf(resp.content, SECRET_EXAMPLE);
    const respAttrs = JSON.parse(resp.attributes) as Record<string, unknown>;
    expect(respAttrs.message_id).toBe('msg_e1');
    expect(respAttrs.conversation_id).toBe('conv_e1');
    expect(respAttrs.model).toBe('gpt-4o');
    expect(respAttrs.turn_index).toBe(2);

    // The dedup fingerprint is the hash of the ORIGINAL text, not the masked
    // form stored at rest — the two differ because the stored content is not
    // the original.
    expect(resp.content_hash).toBe(contentHashOf(originalText));
    expect(resp.content_hash).not.toBe(contentHashOf(resp.content));
  });

  it('cites the INSTALLED pack version on a tool-call inspection, not the rule format version', async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_rv',
      toolCalls: [{ toolUseId: 'tu_rv', toolName: 'search', target: `look up ${SECRET_EXAMPLE}` }],
    });

    await handleRequest(
      { type: 'exchange', requestId: 'rv1', sessionId: 'browser-rv', tool: 'chatgpt', exchange },
      consentedConfig(),
    );

    const db = open();
    const def = db
      .prepare(
        `SELECT d.version AS version FROM inspection_definitions d
           JOIN inspection_findings f ON f.inspection_definition_id = d.id
          WHERE d.rule_id = ? AND f.audit_event_id IN (
            SELECT id FROM audit_events WHERE root_session_id = 'browser-rv'
          )`,
      )
      .get(RULE_ID) as { version: string } | undefined;
    db.close();

    if (def === undefined) throw new Error('expected an inspection definition for the tool target');
    // Derived from the pack the gateway installed, never a literal: the point
    // is that the finding cites the version that actually fired. Rule.specVersion
    // is the z.literal(1) format marker scanText falls back to, so a bare
    // scanText here would write '1' and split this rule across two definition
    // rows — one per producer.
    expect(SECRET_PACK.version).not.toBe('1');
    expect(def.version).toBe(SECRET_PACK.version);
  });

  it('de-duplicates ruleIds when one rule fires more than once in a reply', async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_dup',
      // The SAME rule, twice: every bundled regex rule carries the `g` flag, so
      // the engine emits one finding per span with no per-rule collapse.
      responseText: `first ${SECRET_EXAMPLE} then ${SECRET_EXAMPLE} done`,
    });

    const response = await handleRequest(
      { type: 'exchange', requestId: 'dup1', sessionId: 'browser-dup', tool: 'chatgpt', exchange },
      consentedConfig(),
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    // Positive control: the rule really did fire, so the absence of duplicates
    // below is not the absence of findings.
    expect(response.ruleIds).toContain(RULE_ID);
    // Duplicate-free rather than an exact array, which would couple this case
    // to whatever else the bundled ruleset matches in the surrounding words.
    expect(response.ruleIds).toEqual([...new Set(response.ruleIds)]);
  });

  it('de-duplicates ruleIds on the capture branch too', async () => {
    seedSecretPolicy('redact');
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'dup2',
        sessionId: 'browser-dup2',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `deploy ${SECRET_EXAMPLE} and ${SECRET_EXAMPLE}`,
      },
      consentedConfig(),
    );
    if (response.type !== 'capture') throw new Error('expected a capture response');
    expect(response.ruleIds).toContain(RULE_ID);
    expect(response.ruleIds).toEqual([...new Set(response.ruleIds)]);
  });

  it('answers a malformed exchange frame with a fixed message, echoing nothing', async () => {
    // `usageSource` is a three-member enum, so this fails WebExchange.safeParse
    // inside the handler. handleRequest is exported and called directly, so
    // isHostRequest's own refusal is not the only route to this branch.
    const badExchange = {
      ...baseExchange({ responseText: `leaked ${SECRET_EXAMPLE}` }),
      usageSource: 'sometimes',
    } as unknown as WebExchange;

    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'bad1',
        sessionId: 'browser-bad1',
        tool: 'chatgpt',
        exchange: badExchange,
      },
      consentedConfig(),
    );
    expect(response.type).toBe('error');
    if (response.type !== 'error') throw new Error('expected an error response');
    // Positive control first: the message is really the fixed string.
    expect(response.message).toBe('malformed exchange payload');
    expectNoEchoOf(JSON.stringify(response), SECRET_EXAMPLE);
  });
});

describe('masking proof (both surfaces reach the store masked)', () => {
  it('masks a secret in a tool-call target and in the reply text, in neither at rest', async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_m1',
      toolCalls: [
        { toolUseId: 'tu_m1', toolName: 'search', target: `search for ${SECRET_AT_REST}` },
      ],
      responseText: `the answer is ${SECRET_AT_REST} ok`,
    });
    await handleRequest(
      { type: 'exchange', requestId: 'm1', sessionId: 'browser-m1', tool: 'chatgpt', exchange },
      consentedConfig(),
    );

    const db = open();
    const tool = db
      .prepare(
        "SELECT attributes FROM audit_events WHERE event_type = 'tool_call' AND root_session_id = 'browser-m1'",
      )
      .get() as { attributes: string };
    const resp = db
      .prepare(
        "SELECT content FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-m1'",
      )
      .get() as { content: string };
    db.close();

    const toolAttrs = JSON.parse(tool.attributes) as Record<string, unknown>;
    expect(toolAttrs.target).toContain('search for');
    expectNoEchoOf(toolAttrs.target as string, SECRET_AT_REST);

    expect(resp.content).toContain('the answer is');
    expectNoEchoOf(resp.content, SECRET_AT_REST);

    // Also walk every file the store wrote — not only the two rows queried
    // above. SECRET_AT_REST (not SECRET_EXAMPLE) is what this checks: the
    // rule's own example is legitimately stored verbatim in
    // installed_packs.rules_json by seedSecretPolicy, which a whole-store scan
    // would otherwise misreport as a leak of THIS exchange's data.
    const bytes = storeBytes(dir);
    expect(bytes).toContain('search for');
    expectNoEchoOf(bytes, SECRET_AT_REST);
  });

  it('masks the tool-call target even with no policy seeded', async () => {
    // Target masking is scanText's unconditional redaction, not a policy
    // outcome — no seedSecretPolicy call here.
    const exchange = baseExchange({
      messageId: 'msg_m2',
      toolCalls: [
        { toolUseId: 'tu_m2', toolName: 'search', target: `search for ${SECRET_EXAMPLE}` },
      ],
    });
    await handleRequest(
      { type: 'exchange', requestId: 'm2', sessionId: 'browser-m2', tool: 'chatgpt', exchange },
      consentedConfig(),
    );

    const db = open();
    const tool = db
      .prepare(
        "SELECT attributes FROM audit_events WHERE event_type = 'tool_call' AND root_session_id = 'browser-m2'",
      )
      .get() as { attributes: string };
    db.close();
    const toolAttrs = JSON.parse(tool.attributes) as Record<string, unknown>;
    expect(toolAttrs.target).toContain('search for');
    expectNoEchoOf(toolAttrs.target as string, SECRET_EXAMPLE);
  });
});

describe('the webChatCapture consent gate', () => {
  it('records nothing for an exchange without consent, and still enforces on a prompt', async () => {
    // Seed the policy first (opens and migrates the store) so the row-count
    // queries below run against a real schema rather than "no such table".
    seedSecretPolicy('block');

    const exchange = baseExchange({
      messageId: 'msg_c1',
      responseText: `the secret is ${SECRET_AT_REST}`,
    });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'c1', sessionId: 'browser-c1', tool: 'chatgpt', exchange },
      config, // un-consented
    );
    expect(response).toEqual({
      type: 'exchange',
      requestId: 'c1',
      ok: true,
      accepted: false,
      skipped: 'no-consent',
      llmCalls: 0,
      toolCalls: 0,
      ruleIds: [],
    });

    const db1 = open();
    const rows = db1
      .prepare(
        "SELECT COUNT(*) as n FROM audit_events WHERE root_session_id = 'browser-c1' OR id = 'browser-c1'",
      )
      .get() as { n: number };
    db1.close();
    expect(rows.n).toBe(0);

    // Same un-consented config; enforcement on a PROMPT is not gated by the
    // same consent.
    const captureResponse = await handleRequest(
      {
        type: 'capture',
        requestId: 'c2',
        sessionId: 'browser-c1-prompt',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `deploy with ${SECRET_AT_REST} now`,
      },
      config,
    );
    if (captureResponse.type !== 'capture') throw new Error('expected a capture response');
    expect(captureResponse.action).toBe('block');
    expect(captureResponse.text).toBeNull();
    expect(captureResponse.ruleIds).toContain(RULE_ID);

    const db2 = open();
    const promptRow = db2
      .prepare(
        "SELECT id FROM audit_events WHERE event_type = 'prompt' AND root_session_id = 'browser-c1-prompt'",
      )
      .get() as { id: string } | undefined;
    if (promptRow === undefined) throw new Error('expected a prompt row');
    const findingRow = db2
      .prepare('SELECT id FROM inspection_findings WHERE audit_event_id = ?')
      .get(promptRow.id) as { id: string } | undefined;
    db2.close();
    expect(findingRow).toBeDefined();

    // The raw secret is nowhere on disk: not in the (never-written) exchange
    // rows, and not in the blocked prompt, which is stored masked. SECRET_AT_REST
    // rather than SECRET_EXAMPLE, for the same reason as the masking-proof
    // test above — the rule's own example is legitimately in installed_packs.
    const bytes = storeBytes(dir);
    expect(bytes).toContain('[REDACTED:SECRET]');
    expectNoEchoOf(bytes, SECRET_AT_REST);
  });

  it('reads a stale consent version as revoked', async () => {
    const staleConfig: ConfigForTool = (tool) =>
      config(tool, webChatSettings('with-findings', WEB_CHAT_CAPTURE_CONSENT_VERSION - 1));
    const exchange = baseExchange({ messageId: 'msg_stale' });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'st1', sessionId: 'browser-stale', tool: 'chatgpt', exchange },
      staleConfig,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'no-consent' });
  });

  it('reads the grant live, so a revocation applies to the very next exchange', async () => {
    let consented = true;
    const seam: ConfigForTool = (tool) => config(tool, consented ? webChatSettings() : undefined);

    const first = await handleRequest(
      {
        type: 'exchange',
        requestId: 'lv1',
        sessionId: 'browser-live',
        tool: 'chatgpt',
        exchange: baseExchange({ messageId: 'msg_live1' }),
      },
      seam,
    );
    expect(first).toMatchObject({ accepted: true });

    consented = false;
    const second = await handleRequest(
      {
        type: 'exchange',
        requestId: 'lv2',
        sessionId: 'browser-live',
        tool: 'chatgpt',
        exchange: baseExchange({ messageId: 'msg_live2' }),
      },
      seam,
    );
    expect(second).toMatchObject({ accepted: false, skipped: 'no-consent' });

    const db = open();
    const count = db
      .prepare(
        "SELECT COUNT(*) as n FROM audit_events WHERE event_type = 'llm_call' AND root_session_id = 'browser-live'",
      )
      .get() as { n: number };
    db.close();
    expect(count.n).toBe(1);
  });
});

describe('response persistence mode', () => {
  it("'never' writes the leaves and no response row", async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_never',
      toolCalls: [{ toolUseId: 'tu_never', toolName: 'x' }],
      responseText: `the secret is ${SECRET_AT_REST}`,
    });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'pn1', sessionId: 'browser-pn1', tool: 'chatgpt', exchange },
      consentedConfig('never'),
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    expect(response.accepted).toBe(true);
    expect(response.llmCalls).toBe(1);
    expect(response.toolCalls).toBe(1);
    expect(response.responseAction).toBeUndefined();
    expect(response.ruleIds).toEqual([]);

    const db = open();
    const counts = db
      .prepare(
        "SELECT event_type, COUNT(*) as n FROM audit_events WHERE root_session_id = 'browser-pn1' GROUP BY event_type",
      )
      .all() as { event_type: string; n: number }[];
    db.close();
    const byType = Object.fromEntries(counts.map((c) => [c.event_type, c.n]));
    expect(byType.llm_call).toBe(1);
    expect(byType.tool_call).toBe(1);
    expect(byType.response).toBeUndefined();

    // SECRET_AT_REST rather than SECRET_EXAMPLE — see the masking-proof test.
    expectNoEchoOf(storeBytes(dir), SECRET_AT_REST);
  });

  it("'with-findings' writes no response row for a benign reply, and does write the leaves", async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_wf',
      responseText: 'a perfectly benign reply',
    });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'pn2', sessionId: 'browser-pn2', tool: 'chatgpt', exchange },
      consentedConfig('with-findings'),
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    expect(response.llmCalls).toBe(1);
    expect(response.responseAction).toBe('log');
    expect(response.ruleIds).toEqual([]);

    const db = open();
    const resp = db
      .prepare(
        "SELECT id FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-pn2'",
      )
      .get() as { id: string } | undefined;
    db.close();
    expect(resp).toBeUndefined();
  });

  it("'always' writes a response row for a benign reply", async () => {
    seedSecretPolicy('redact');
    const exchange = baseExchange({
      messageId: 'msg_always',
      responseText: 'a perfectly benign reply',
    });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'pn3', sessionId: 'browser-pn3', tool: 'chatgpt', exchange },
      consentedConfig('always'),
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    expect(response.responseAction).toBe('log');

    const db = open();
    const resp = db
      .prepare(
        "SELECT content FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-pn3'",
      )
      .get() as { content: string } | undefined;
    db.close();
    if (resp === undefined) throw new Error('expected a response row');
    expect(resp.content).toBe('a perfectly benign reply');
  });
});

describe('exchange refusals and fail-open', () => {
  it('a whitespace message id is unkeyable: nothing is recorded, not even a root stub', async () => {
    // A benign session_start first, so the store exists and is migrated —
    // otherwise a query below would fail on a store that has never been
    // opened, rather than on the property under test.
    await handleRequest(
      {
        type: 'session_start',
        requestId: 's0',
        sessionId: 'unrelated-session',
        tool: 'chatgpt',
        hostname: 'chatgpt.com',
      },
      config,
    );

    const exchange = baseExchange({ messageId: '   ' });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'uk1', sessionId: 'browser-uk1', tool: 'chatgpt', exchange },
      consentedConfig(),
    );
    expect(response).toEqual({
      type: 'exchange',
      requestId: 'uk1',
      ok: true,
      accepted: false,
      skipped: 'unkeyable',
      llmCalls: 0,
      toolCalls: 0,
      ruleIds: [],
    });

    const db = open();
    const rows = db
      .prepare(
        "SELECT COUNT(*) as n FROM audit_events WHERE root_session_id = 'browser-uk1' OR id = 'browser-uk1'",
      )
      .get() as { n: number };
    db.close();
    expect(rows.n).toBe(0);
  });

  it('an unkeyable exchange still scans and audits its reply', async () => {
    // The reply is where a secret would be, and the row id hashes only on the
    // message id — so returning early on an unkeyable exchange threw away the
    // scan along with the join, and the one thing that cannot be recovered
    // afterwards is the record that a secret was sent.
    seedSecretPolicy('block');
    const exchange = baseExchange({
      messageId: '   ',
      responseText: `the answer is ${SECRET_AT_REST} ok`,
    });

    const response = await handleRequest(
      { type: 'exchange', requestId: 'uk2', sessionId: 'browser-uk2', tool: 'chatgpt', exchange },
      consentedConfig(),
    );

    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    // The leaves are still refused, and `accepted` still says so.
    expect(response.accepted).toBe(false);
    expect(response.skipped).toBe('unkeyable');
    expect(response.llmCalls).toBe(0);
    expect(response.toolCalls).toBe(0);
    // And the reply was read: the rule fired and is reported.
    expect(response.ruleIds).toContain(RULE_ID);
    expect(response.responseAction).toBe('block');

    // AUDITED, not merely scanned — the title claims the record, so the row is
    // what proves it. Without this, a mutation that keeps the scan and never
    // persists the reply (`persist: 'never'` here) stays green on the two
    // assertions above.
    const db = open();
    const rows = db
      .prepare(
        "SELECT content FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-uk2'",
      )
      .all() as { content: string | null }[];
    db.close();
    expect(rows).toHaveLength(1);
    // Masked at rest, with the surrounding reply intact — so this is the
    // reply that was stored rather than some other row.
    expect(rows[0]?.content).toContain('[REDACTED:SECRET]');
    expect(rows[0]?.content).toContain('the answer is');
    expectNoEchoOf(storeBytes(dir), SECRET_AT_REST);
  });

  it('is fail-open on the leaf write, and still scans the reply', async () => {
    // The `catch` around the leaf writes is the only thing keeping a contended
    // store from turning this into runHost's generic error — and the response
    // scan below it must survive the same fault, for the reason the case above
    // gives. Point dataDir at a regular file so opening the store throws, the
    // same setup the capture path's own fail-open case uses.
    const filePath = join(dir, 'exchange-blocker');
    writeFileSync(filePath, 'x');
    const broken: ConfigForTool = (tool) => ({
      ...config(tool, webChatSettings()),
      dataDir: filePath,
      dbPath: join(filePath, 'aka.db'),
    });

    const exchange = baseExchange({
      messageId: 'msg_failopen',
      responseText: `the answer is ${SECRET_AT_REST} ok`,
    });

    const response = await handleRequest(
      { type: 'exchange', requestId: 'fo1', sessionId: 'browser-fo1', tool: 'chatgpt', exchange },
      broken,
    );

    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    // Keyable, so `accepted` is true even though the write landed nowhere —
    // the count below is what says how little was written.
    expect(response.accepted).toBe(true);
    expect(response.llmCalls).toBe(0);
    expect(response.toolCalls).toBe(0);
  });

  it('an exchange with no toolCalls key records the leaf and zero tool calls, without throwing', async () => {
    const exchange = {
      messageId: 'msg_notc',
      startedAt: '2026-01-01T00:00:00.000Z',
      usageSource: 'none',
    } as unknown as WebExchange;
    const response = await handleRequest(
      { type: 'exchange', requestId: 'ntc1', sessionId: 'browser-ntc1', tool: 'chatgpt', exchange },
      consentedConfig(),
    );
    expect(response).toMatchObject({ accepted: true, llmCalls: 1, toolCalls: 0 });
  });

  it('caps a response over the ceiling and marks the leaf response_truncated', async () => {
    const big = 'r'.repeat(RESPONSE_TEXT_MAX_BYTES + 1000);
    const exchange = baseExchange({ messageId: 'msg_big', responseText: big });
    const response = await handleRequest(
      { type: 'exchange', requestId: 'big1', sessionId: 'browser-big1', tool: 'chatgpt', exchange },
      consentedConfig('always'),
    );
    expect(response).toMatchObject({ accepted: true });

    const db = open();
    const resp = db
      .prepare(
        "SELECT content FROM audit_events WHERE event_type = 'response' AND root_session_id = 'browser-big1'",
      )
      .get() as { content: string };
    const llm = db
      .prepare(
        "SELECT attributes FROM audit_events WHERE event_type = 'llm_call' AND root_session_id = 'browser-big1'",
      )
      .get() as { attributes: string };
    db.close();

    expect(new TextEncoder().encode(resp.content).byteLength).toBeLessThanOrEqual(
      RESPONSE_TEXT_MAX_BYTES,
    );
    const attrs = JSON.parse(llm.attributes) as Record<string, unknown>;
    expect(attrs.response_truncated).toBe(true);
  });

  it('a repeated identical exchange is idempotent', async () => {
    const exchange = baseExchange({
      messageId: 'msg_idem',
      toolCalls: [{ toolUseId: 'tu_idem', toolName: 'x' }],
      responseText: 'benign',
    });
    const req = {
      type: 'exchange' as const,
      requestId: 'idem1',
      sessionId: 'browser-idem',
      tool: 'chatgpt' as const,
      exchange,
    };
    await handleRequest(req, consentedConfig('always'));
    await handleRequest({ ...req, requestId: 'idem2' }, consentedConfig('always'));

    const db = open();
    const counts = db
      .prepare(
        "SELECT event_type, COUNT(*) as n FROM audit_events WHERE root_session_id = 'browser-idem' GROUP BY event_type",
      )
      .all() as { event_type: string; n: number }[];
    db.close();
    const byType = Object.fromEntries(counts.map((c) => [c.event_type, c.n]));
    expect(byType.llm_call).toBe(1);
    expect(byType.tool_call).toBe(1);
    expect(byType.response).toBe(1);
  });
});

const VALID_STATUS: WebCaptureStatus = {
  patched: true,
  live: false,
  blind: false,
  sendsSeenDom: 0,
  exchangesSeenNet: 0,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
};

describe('capture_status', () => {
  it('remembers a consented status, readable via readCaptureStatus', async () => {
    const status: WebCaptureStatus = {
      patched: true,
      live: true,
      blind: false,
      sendsSeenDom: 3,
      exchangesSeenNet: 3,
      parseFailures: 0,
      unparsedBodies: 0,
      shapeMisses: ['adapter.model'],
    };
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'cs1',
        sessionId: 'browser-cs1',
        tool: 'chatgpt',
        status,
      },
      consentedConfig(),
    );
    expect(response).toEqual({
      type: 'capture_status',
      requestId: 'cs1',
      ok: true,
      accepted: true,
    });

    const tracked = readCaptureStatus('browser-cs1');
    expect(tracked?.tool).toBe('chatgpt');
    expect(tracked?.status).toEqual(status);
    expect(tracked?.observedAt).toBeTypeOf('string');
  });

  it('does not remember an unconsented status', async () => {
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'cs2',
        sessionId: 'browser-cs2',
        tool: 'chatgpt',
        status: VALID_STATUS,
      },
      config,
    );
    expect(response).toEqual({
      type: 'capture_status',
      requestId: 'cs2',
      ok: true,
      accepted: false,
      skipped: 'no-consent',
    });
    expect(readCaptureStatus('browser-cs2')).toBeUndefined();
  });

  it('replaces the earlier status for the same session', async () => {
    const sessionId = 'browser-cs3';
    const first: WebCaptureStatus = { ...VALID_STATUS, sendsSeenDom: 1 };
    const second: WebCaptureStatus = { ...VALID_STATUS, sendsSeenDom: 2, live: true };
    await handleRequest(
      { type: 'capture_status', requestId: 'cs3a', sessionId, tool: 'chatgpt', status: first },
      consentedConfig(),
    );
    await handleRequest(
      { type: 'capture_status', requestId: 'cs3b', sessionId, tool: 'chatgpt', status: second },
      consentedConfig(),
    );
    expect(readCaptureStatus(sessionId)?.status).toEqual(second);
  });

  it('bounds the tracked-session map, evicting the oldest', async () => {
    for (let i = 0; i < 33; i += 1) {
      const n = String(i);
      await handleRequest(
        {
          type: 'capture_status',
          requestId: `cs-bound-${n}`,
          sessionId: `browser-bound-${n}`,
          tool: 'chatgpt',
          status: VALID_STATUS,
        },
        consentedConfig(),
      );
    }
    expect(readCaptureStatus('browser-bound-0')).toBeUndefined();
    expect(readCaptureStatus('browser-bound-32')).toBeDefined();
  });

  it('answers a malformed capture_status frame with a fixed message, echoing nothing', async () => {
    const badStatus = {
      ...VALID_STATUS,
      sendsSeenDom: -1,
      shapeMisses: [SECRET_EXAMPLE],
    };
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'cs4',
        sessionId: 'browser-cs4',
        tool: 'chatgpt',
        status: badStatus,
      },
      consentedConfig(),
    );
    expect(response.type).toBe('error');
    if (response.type !== 'error') throw new Error('expected an error response');
    // Positive control first: the message is really the fixed string.
    expect(response.message).toBe('malformed capture status payload');
    expectNoEchoOf(JSON.stringify(response), SECRET_EXAMPLE);
  });
});
