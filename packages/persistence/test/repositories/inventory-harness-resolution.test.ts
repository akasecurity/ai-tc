import { DatabaseSync } from 'node:sqlite';

import { HARNESS, HarnessId, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import { SqliteInventoryRepository } from '../../src/repositories/inventory.ts';
import { SqliteInventoryAssetsRepository } from '../../src/repositories/inventory-assets.ts';

// The harness card's id comes from resolveHarnessId, which reads the row's
// `provider` attribute when there is one and otherwise SNIFFS the row's title.
// The sample fixtures all carry a `provider`, so every existing suite takes the
// short-circuit and the sniff — the only path a REAL scanned row can take, since
// resolveInventoryContext writes no `provider` at all — was covered nowhere.
//
// What it has to get right is that its two sides speak different vocabularies:
// the stored title is a SOURCE_TOOL wire id, the returned card id is a HARNESS
// display id, and for ClaudeCode those are spelled differently ('claude-code' vs
// 'claudecode'). Both sides here are read from the registry rather than written
// out, so this stays true under a rename of either vocabulary and goes red if
// the needles are ever re-bound to the wrong one.
let db: DatabaseSync;
let inv: SqliteInventoryAssetsRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applyMigrations(db);
  inv = new SqliteInventoryAssetsRepository(db);
});

afterEach(() => {
  db.close();
});

/** Write a harness row exactly as the capture path does: title = the wire id, no attributes. */
const seedScannedHarness = (tool: string): void => {
  new SqliteInventoryRepository(db).upsert({
    objectType: 'harness',
    identityKey: tool,
    title: tool,
    attributes: {},
  });
};

describe('resolveHarnessId over rows the capture path actually writes', () => {
  it('resolves the hyphenated wire id onto the unhyphenated display id', async () => {
    // The discriminating case, and the reason the needles cannot be spelled from
    // HARNESS: these two strings differ, and only the stored one is ever on disk.
    expect(SOURCE_TOOL.ClaudeCode).not.toBe(HARNESS.ClaudeCode);
    seedScannedHarness(SOURCE_TOOL.ClaudeCode);
    const { items } = await inv.listHarnesses();
    expect(items.map((h) => h.id)).toEqual([HARNESS.ClaudeCode]);
  });

  it('resolves every HarnessId member from its own wire id', async () => {
    const members = Object.keys(HarnessId.enum) as (keyof typeof HarnessId.enum)[];
    // Positive control on the derivation: an empty member list would satisfy
    // the set comparison below while asserting nothing at all.
    expect(members.length).toBeGreaterThan(1);
    for (const member of members) seedScannedHarness(SOURCE_TOOL[member]);

    const { items } = await inv.listHarnesses();
    expect(items.map((h) => h.id).sort()).toEqual(members.map((member) => HARNESS[member]).sort());
  });

  it('returns no card for a title that names no known tool', async () => {
    seedScannedHarness('some-unknown-agent');
    expect((await inv.listHarnesses()).items).toEqual([]);
  });

  // resolveHarnessId's ladder is a hand-written chain of `if`s: extending
  // HarnessId makes HARNESS_LABELS and TITLE_NEEDLES compile errors and says
  // NOTHING about the dispatch. The derived case above would still pass with
  // the Copilot arm missing — its set comparison is over what came back, and a
  // member that resolves to null simply yields no card, which reads as an
  // ordinary absence. So Copilot's arm is driven by name, and with the label
  // asserted, since that is the other half of what a card renders.
  it('resolves the Copilot wire id and labels the card', async () => {
    seedScannedHarness(SOURCE_TOOL.Copilot);
    const { items } = await inv.listHarnesses();
    expect(items.map((h) => ({ id: h.id, label: h.label }))).toEqual([
      { id: HARNESS.Copilot, label: 'GitHub Copilot' },
    ]);
  });

  // The needle is the stripped WIRE id ('githubcopilot'), not the display id
  // ('copilot'), so a row titled with the bare word resolves to nothing. Pinned
  // because the two ids differ here exactly as they do for Claude Code, and a
  // needle respelled from HARNESS would silently widen this arm to match any
  // title carrying the word.
  it('does not resolve a bare "copilot" title', async () => {
    expect(SOURCE_TOOL.Copilot).not.toBe(HARNESS.Copilot);
    seedScannedHarness(HARNESS.Copilot);
    expect((await inv.listHarnesses()).items).toEqual([]);
  });
});
