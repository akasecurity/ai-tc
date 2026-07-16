import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { handleCapture } from '../src/handle-capture.ts';

// In standalone mode the effective ruleset is the store's INSTALLED snapshot
// (seeded from bundledDetections() by resolveDataGateway), NOT ad-hoc packs
// registered into the engine — so this test detects with a real bundled rule
// (secrets/aws-access-key). The canonical AWS example key id is composed at
// runtime so the repo's own secret scanning doesn't flag this file.
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-handle-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

describe('handleCapture (standalone)', () => {
  it('records the capture and never persists the raw secret (redacted content + original hash)', async () => {
    const text = `here is ${AWS_EXAMPLE_KEY} value`;
    const result = await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text },
      config(dir),
    );
    // The bundled secrets pack is unassigned, so it monitors (log) by default —
    // but at-rest masking is independent of the enforcement action: a detected
    // secret is always stored masked, whatever the policy decides.
    expect(result.action).toBe('log');

    const db = new DatabaseSync(join(dir, 'aka.db'));
    const row = db.prepare('SELECT content, content_hash FROM events').get() as {
      content: string;
      content_hash: string;
    };
    db.close();

    // Stored content has the secret masked; the original is recoverable only as a hash.
    expect(row.content).not.toContain(AWS_EXAMPLE_KEY);
    expect(row.content).toContain('[REDACTED:SECRET]');
    expect(row.content_hash).toBe(createHash('sha256').update(text).digest('hex'));
  });

  it('is fail-open: an unusable data dir yields log + the original text, no throw', async () => {
    // Point dataDir at a regular file so opening the store throws while resolving.
    const filePath = join(dir, 'blocker');
    writeFileSync(filePath, 'x');
    const result = await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      config(filePath),
    );
    expect(result).toEqual({ action: 'log', text: 'SECRET_MARKER', findings: [] });
  });
});
