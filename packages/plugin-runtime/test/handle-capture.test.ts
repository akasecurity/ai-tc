import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { SqliteInstalledPacksRepository } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
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
  removeTree(dir);
});

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
    // The bundled secrets pack is unassigned, so it monitors (log) by default.
    // At-rest masking FOLLOWS that decision rather than overriding it: only a
    // span whose own action was redact or stronger is masked in the stored
    // content, so a monitored detection is recorded exactly as it crossed.
    expect(result.action).toBe('log');

    const db = new DatabaseSync(join(dir, 'aka.db'));
    // Constrained to the four capture kinds — audit_events also holds
    // structural rows (session, run, tool_call, llm_call, source_lookup,
    // config_scan) a bare prompt capture never writes, but the predicate keeps
    // intent explicit and matches every other re-pointed capture-kind query.
    const row = db
      .prepare(
        `SELECT content, content_hash FROM audit_events
         WHERE event_type IN ('prompt','response','code_change','tool_use')`,
      )
      .get() as {
      content: string;
      content_hash: string;
    };
    db.close();

    // Monitored, so the stored content is the capture verbatim — no placeholder
    // stands in for a value nothing was going to strip. The hash is over the
    // original either way, so dedup is unaffected by what masking did or did not do.
    expect(row.content).toBe(text);
    expect(row.content).not.toContain('[REDACTED:SECRET]');
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

describe('handleCapture capture options', () => {
  function captureRowCount(): number {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    // audit_events also holds structural rows (session, llm_call, …), so the
    // count is constrained to the capture kinds the way this file's other
    // store read is.
    const row = db
      .prepare(
        `SELECT count(*) AS n FROM audit_events
         WHERE event_type IN ('prompt','response','code_change','tool_use')`,
      )
      .get() as { n: number };
    db.close();
    return row.n;
  }

  it("forwards 'with-findings', so a clean capture persists no row", async () => {
    const clean = await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: 'nothing sensitive here' },
      config(dir),
      { persist: 'with-findings' },
    );
    expect(clean.action).toBe('log');
    // Without the pass-through the option is dropped, capture() takes its
    // default 'always' path, and a benign assistant reply lands as a row.
    expect(captureRowCount()).toBe(0);
  });

  it('still persists a with-findings capture that actually found something', async () => {
    // The positive control: without it the case above passes for a
    // handleCapture that persists nothing at all.
    const hit = await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: `key: ${AWS_EXAMPLE_KEY}` },
      config(dir),
      { persist: 'with-findings' },
    );
    expect(hit.findings.length).toBeGreaterThan(0);
    expect(captureRowCount()).toBe(1);
  });

  it('defaults to persisting every capture when no option is passed', async () => {
    // The other positive control: the default must not silently become
    // 'with-findings' for callers that pass nothing.
    const dflt = await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: 'nothing sensitive here' },
      config(dir),
    );
    // The row separates 'always' from 'with-findings' only for a capture that
    // found nothing, so this case asserts its own precondition rather than
    // inheriting it from the text a sibling happens to share.
    expect(dflt.findings).toHaveLength(0);
    expect(captureRowCount()).toBe(1);
  });
});

// `persist` is one of four fields on CaptureOptions, so the cases above are all
// satisfied by a pass-through that names that one key and drops the rest.
// `rewritable` is the second field observable from here: it degrades a resolved
// `redact` to `settings.redactFallback` ('warn' in this file's config) inside
// the action resolution, so a dropped `rewritable: false` reads as a redact the
// caller could never have carried out.
describe('handleCapture forwards more of CaptureOptions than persist', () => {
  const SECRET_TEXT = `key: ${AWS_EXAMPLE_KEY}`;

  // The bundled secrets pack is unassigned out of the box, so it monitors and
  // no `redact` ever resolves for `rewritable` to degrade. Capture once to
  // inventory the bundled packs into a fresh store, then assign the pack Redact
  // through the repository that owns that write. A later handleCapture builds
  // its own runtime, which re-pulls the bundle, so the assignment takes effect
  // on the next call.
  //
  // The repository is constructed over the store handle ALONE, with no layout
  // base — its documented "no floor, no lock" construction. A base would send
  // the write's control-plane floor resolution at this dir's parent, which is
  // the shared temp root rather than anything this fixture owns, and whether
  // that resolution then finds an attached machine is a property of the host
  // rather than of the code under test.
  async function assignRedactToSecrets(): Promise<void> {
    await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: 'inventory the packs' },
      config(dir),
    );
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    try {
      // The assignment reports whether it matched an installed row: an
      // unseeded store would leave the pack monitoring and make both cases
      // below assert against a decision neither of them is about.
      expect(new SqliteInstalledPacksRepository(raw).setPolicy('aka', 'secrets', 'redact')).toBe(
        true,
      );
    } finally {
      raw.close();
    }
  }

  it('degrades the redact to the fallback when the caller cannot rewrite the field', async () => {
    await assignRedactToSecrets();
    const result = await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: SECRET_TEXT },
      config(dir),
      { rewritable: false },
    );
    expect(result.action).toBe('warn');
    // Warn leaves the text alone — there is no rewrite to show for it.
    expect(result.text).toBe(SECRET_TEXT);
  });

  it('keeps the redact when the caller can rewrite the field', async () => {
    // The pair's other half: both cases fail if the policy above never landed,
    // rather than this one passing because nothing resolved to redact at all.
    await assignRedactToSecrets();
    const result = await handleCapture(
      { kind: 'response', sourceTool: 'claude-ai', text: SECRET_TEXT },
      config(dir),
      { rewritable: true },
    );
    expect(result.action).toBe('redact');
    expect(result.text).not.toContain(AWS_EXAMPLE_KEY);
  });
});
