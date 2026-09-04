import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { setDefaultGatewayFactory, standaloneGatewayFactory } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { handleRequest } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

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

function config(tool: WebSourceTool | undefined): PluginConfig {
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
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

function open(): DatabaseSync {
  return new DatabaseSync(join(dir, 'aka.db'));
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
