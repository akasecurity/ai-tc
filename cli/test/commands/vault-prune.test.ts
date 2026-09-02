import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { VaultRow } from '@akasecurity/persistence';
import {
  applyOnboarding,
  createKeyProvider,
  dataDir,
  dbPath,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type {
  DetectionCategory,
  ListVaultInventoryResponse,
  Rule,
  VaultInventoryEntry,
} from '@akasecurity/schema';
import {
  isVaultConsentValid,
  MAX_VAULT_PAGE_LIMIT,
  VAULT_CONSENT_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runVault } from '../../src/commands/vault.ts';
import type { SightingLedgerSource } from '../../src/commands/vault-prune.ts';
import { selectOutOfPolicy, sightingLedger } from '../../src/commands/vault-prune.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// `aka vault prune` restores the pointers an out-of-policy detection wrote into
// a transcript and only then deletes those vault entries. The suite drives the
// REAL node:sqlite store, REAL vault key files and REAL transcript files on
// disk — the ordering it exists to prove is only observable when a restore can
// genuinely fail against bytes that are really there.
//
// Values here are deliberately not secret-shaped: nothing in this path scans,
// and a public tree is no place for a credential-shaped literal. They are still
// distinctive enough that an eight-character window of one cannot collide with
// ordinary command output.
const MONITOR_RAW = 'quixotic-vellum-marzipan-42';
// The same shape with a bare double quote in it. Spliced back into a JSON
// transcript line it breaks the record, which is the abort this suite drives.
const UNSPLICEABLE_RAW = 'quixotic-vellum"marzipan-42';
const VAULTED_RAW = 'harlequin-obelisk-tundra-91';

let home: string;
let userHome: string;
let transcript: string;

function scriptedIo(): Prompter & { output: () => string } {
  const chunks: string[] = [];
  return {
    output: () => chunks.join(''),
    out: (text) => {
      chunks.push(text);
    },
    err: (text) => {
      chunks.push(text);
    },
    isInteractive: false,
    ask: () => Promise.reject(new Error('non-interactive test io')),
    askHidden: () => Promise.reject(new Error('non-interactive test io')),
    readAllStdin: () => Promise.resolve(''),
  };
}

function rule(id: string, category: DetectionCategory): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category,
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['never-matched-here'], caseSensitive: false },
  };
}

// Install one pack holding one rule, and assign it a built-in archetype.
function installPack(packId: string, ruleId: string, category: DetectionCategory, policy: string) {
  const db = openLocalDatabase(dataDir(home));
  try {
    db.installedPacks.recordInventory([
      {
        namespace: 'aka',
        packId,
        version: '1.0.0',
        name: packId,
        rules: [rule(ruleId, category)],
      },
    ]);
    db.installedPacks.setPolicy('aka', packId, policy);
  } finally {
    db.close();
  }
}

/**
 * Vault one value through the real vault, and return its wire pointer.
 *
 * `userAuthorized` is the surfaced-secrets strike: the user pointed at this
 * value and asked for it to be replaced, which the vault records on the row.
 * Left off, this is an enforcing path acting on its own.
 */
async function vaultValue(
  raw: string,
  ruleId: string,
  category: DetectionCategory,
  userAuthorized = false,
): Promise<{ pointer: string; pointerId: string }> {
  const dir = dataDir(home);
  const db = openLocalDatabase(dir);
  try {
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(readWorkspaceSettings(home).vaultKeyCustody, keysDir(home)),
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(home).vaultConsent),
    });
    const pointer = await vault.tokenize(
      raw,
      { ruleId, category, maskedMatch: 'qui…-42', userAuthorized },
      () => loadOrCreateFingerprintKey(dir),
    );
    if (typeof pointer !== 'string') throw new Error('seeding tokenize was refused');
    const row = db.secretVault.listAll().find((r) => r.ruleId === ruleId);
    if (row === undefined) throw new Error('seeded row not found');
    return { pointer, pointerId: row.pointerId };
  } finally {
    db.close();
  }
}

function recordSighting(pointerId: string, location: string, kind: 'transcript' | 'prompt'): void {
  const db = openLocalDatabase(dataDir(home));
  try {
    db.secretVault.recordSighting({ pointerId, location, kind }, Date.now());
  } finally {
    db.close();
  }
}

function vaultRowCount(): number {
  const raw = new DatabaseSync(dbPath(home), { readOnly: true });
  try {
    const row = raw.prepare('SELECT count(*) AS n FROM secret_vault').get() as { n: number };
    return row.n;
  } finally {
    raw.close();
  }
}

function vaultRuleIds(): string[] {
  const raw = new DatabaseSync(dbPath(home), { readOnly: true });
  try {
    return (
      raw.prepare('SELECT rule_id AS ruleId FROM secret_vault ORDER BY rule_id').all() as {
        ruleId: string;
      }[]
    ).map((r) => r.ruleId);
  } finally {
    raw.close();
  }
}

function purgeDerefCount(): number {
  const raw = new DatabaseSync(dbPath(home), { readOnly: true });
  try {
    const row = raw
      .prepare(`SELECT count(*) AS n FROM secret_vault_deref WHERE reason = 'purge'`)
      .get() as { n: number };
    return row.n;
  } finally {
    raw.close();
  }
}

// Every `remediation` audit row for one pointer, oldest first, as
// `<outcome>` strings — the trail this verb's reveals and its aborts both write
// into.
function remediationTrail(pointerId: string): string[] {
  const raw = new DatabaseSync(dbPath(home), { readOnly: true });
  try {
    return (
      raw
        .prepare(
          `SELECT outcome FROM secret_vault_deref
            WHERE pointer_id = :pointerId AND reason = 'remediation'
            ORDER BY rowid`,
        )
        .all({ pointerId }) as { outcome: string }[]
    ).map((r) => r.outcome);
  } finally {
    raw.close();
  }
}

// One JSONL transcript line carrying the pointer inside a JSON string, which is
// the shape the at-rest scrub leaves behind.
function transcriptLine(pointer: string): string {
  return JSON.stringify({ type: 'user', message: { role: 'user', content: `path ${pointer}` } });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-cli-prune-home-'));
  userHome = mkdtempSync(join(tmpdir(), 'aka-cli-prune-user-'));
  const projects = join(userHome, '.claude', 'projects', 'demo');
  mkdirSync(projects, { recursive: true });
  transcript = join(projects, 'session.jsonl');
  applyOnboarding(
    {
      vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
    },
    home,
  );
});

afterEach(() => {
  removeTree(home);
  removeTree(userHome);
});

// A stored vault row with only the fields the split reads varied.
function storedRow(ruleId: string, n: number, userAuthorized = false): VaultRow {
  return {
    pointerId: `p${String(n)}`,
    valueFingerprint: `f${String(n)}`,
    fingerprintKeyVersion: 1,
    keyVersion: 1,
    formatVersion: 2,
    category: 'code_context',
    ruleId,
    maskedMatch: 'q…2',
    ciphertext: '',
    nonce: '',
    authTag: '',
    userAuthorized,
    occurrenceCount: 1,
    firstSeen: 0,
    lastSeen: 0,
  };
}

describe('selectOutOfPolicy', () => {
  it('splits by the installed action and never calls an unknown rule out of policy', () => {
    const rows = [
      storedRow('a/monitored', 1),
      storedRow('a/vaulted', 2),
      storedRow('a/uninstalled', 3),
    ];
    const actions = new Map([
      ['a/monitored', 'log' as const],
      ['a/vaulted', 'redact' as const],
    ]);

    const selection = selectOutOfPolicy(rows, actions);
    expect(selection.outOfPolicy.map((e) => e.ruleId)).toEqual(['a/monitored']);
    expect(selection.inPolicy).toBe(1);
    // The absent rule is a pack that is off or gone, not a decision that the
    // value must not be held — so it is reported, never pruned.
    expect(selection.ruleNotInstalled).toBe(1);
    expect(selection.userAuthorized).toBe(0);
  });

  it('never calls a user-authorized row out of policy, whatever its rule now says', () => {
    const rows = [storedRow('a/monitored', 1), storedRow('a/monitored', 2, true)];
    const actions = new Map([['a/monitored', 'log' as const]]);

    const selection = selectOutOfPolicy(rows, actions);

    // Same rule, same assignment, opposite answers: the ruleset speaks for the
    // rule, and the marker speaks for the value. The first row is the positive
    // control — without it a fix that simply stopped selecting anything would
    // read the same.
    expect(selection.outOfPolicy.map((e) => e.pointerId)).toEqual(['p1']);
    expect(selection.userAuthorized).toBe(1);
    expect(selection.inPolicy).toBe(0);
  });
});

// One inventory row, with only the two fields the ledger walk reads varied.
function inventoryEntry(pointerId: string): VaultInventoryEntry {
  return {
    pointerId,
    category: 'code_context',
    maskedMatch: 'q…2',
    occurrences: 1,
    firstSeen: new Date(0).toISOString(),
    lastSeen: new Date(0).toISOString(),
    revealGrantId: null,
    sightings: [
      { location: `/t/${pointerId}.jsonl`, kind: 'transcript', firstSeen: '0', lastSeen: '0' },
    ],
  };
}

// A page source rather than a store. The real repository stops minting cursors,
// so the one walk the page budget exists to backstop — the store reporting a
// next page forever, which ordering on a mutable `last_seen` makes reachable —
// cannot be staged against it. Nothing here stands in for node:sqlite: the
// store's own paging is covered by the suites that drive it, and this is the
// walk's termination on its own.
function endlessPages(total: number): SightingLedgerSource & { calls: () => number } {
  let calls = 0;
  return {
    calls: () => calls,
    secretVault: {
      listInventory: (): ListVaultInventoryResponse => {
        calls += 1;
        return {
          totals: { values: total },
          items: [inventoryEntry(`p${String(calls)}`)],
          nextCursor: `cursor-${String(calls)}`,
        };
      },
    },
  };
}

describe('sightingLedger', () => {
  it('stops on the store total when the cursor never ends', () => {
    const source = endlessPages(5 * MAX_VAULT_PAGE_LIMIT);

    const ledger = sightingLedger(source);

    // Five pages of rows plus the one that would carry the tail: the budget is
    // seeded once and spent one per page, so it reaches zero instead of
    // settling at a fixed point that never binds.
    expect(source.calls()).toBe(6);
    expect(ledger.size).toBe(6);
  });

  it('spends the budget even on an empty store', () => {
    const source = endlessPages(0);

    sightingLedger(source);

    expect(source.calls()).toBe(1);
  });

  it('walks a finite chain to its end without the budget cutting it short', () => {
    const chain: ListVaultInventoryResponse[] = [
      {
        totals: { values: 2 * MAX_VAULT_PAGE_LIMIT },
        items: [inventoryEntry('a')],
        nextCursor: 'next',
      },
      {
        totals: { values: 2 * MAX_VAULT_PAGE_LIMIT },
        items: [inventoryEntry('b')],
        nextCursor: null,
      },
    ];
    let calls = 0;
    const source: SightingLedgerSource = {
      secretVault: {
        listInventory: (): ListVaultInventoryResponse => {
          const page = chain[calls];
          calls += 1;
          if (page === undefined) throw new Error('walked past the end of the chain');
          return page;
        },
      },
    };

    const ledger = sightingLedger(source);

    expect(calls).toBe(2);
    expect([...ledger.keys()]).toEqual(['a', 'b']);
    expect(ledger.get('a')?.[0]?.location).toBe('/t/a.jsonl');
  });
});

describe('aka vault prune', () => {
  it('is a dry run by default: it changes no file and deletes no entry', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    const io = scriptedIo();
    await runVault(['prune', '--home', home, '--user-home', userHome], io);

    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRowCount()).toBe(1);
    expect(purgeDerefCount()).toBe(0);

    // Positive control on the same bytes the absence check reads: the plan
    // names the file and the work it would do.
    expect(io.output()).toContain('DRY RUN');
    expect(io.output()).toContain('session.jsonl');
    expect(io.output()).toContain('Would restore up to 1 pointer, then delete 1 vault entry.');
    // A plan never reveals, so the value must not be anywhere in it.
    expectNoEchoOf(io.output(), MONITOR_RAW);
  });

  it('--apply restores the raw value first, then deletes the entry', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    // The behaviour under test: the raw value IS back on disk, and the pointer
    // that stood in for it is gone.
    const after = readFileSync(transcript, 'utf8');
    expect(after).toContain(MONITOR_RAW);
    expect(after).not.toContain(pointer);
    // The line is still one valid JSON record, and still one line.
    expect(after.endsWith('\n')).toBe(true);
    const parsed = JSON.parse(after.trimEnd()) as { message: { content: string } };
    expect(parsed.message.content).toBe(`path ${MONITOR_RAW}`);

    // Only then is the entry destroyed, with the purge recorded.
    expect(vaultRowCount()).toBe(0);
    expect(purgeDerefCount()).toBe(1);

    expect(io.output()).toContain('Restored 1 pointer, then deleted 1 vault entry.');
    // The command reports counts and paths, never the recovered value.
    expectNoEchoOf(io.output(), MONITOR_RAW);
  });

  it('leaves the vault entry intact when the restore aborts', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      UNSPLICEABLE_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    // The whole point of the ordering: a restore that could not be completed
    // leaves the file byte-identical AND the only copy of the value in place.
    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRuleIds()).toEqual(['code-context/file-path']);
    expect(purgeDerefCount()).toBe(0);

    expect(io.output()).toContain('ABORTED');
    expect(io.output()).toContain('restoring would break a record in this file');
    expect(io.output()).toContain('Deleting them would leave their pointers permanently');
    expectNoEchoOf(io.output(), UNSPLICEABLE_RAW);

    // And the trail says the same thing the disk does. The reveal really
    // happened — the value was opened to decide the splice — so the row for it
    // stands; the row after it says that reveal produced no restore. Without
    // the second one the audit claims a value was revealed out of a file that
    // was never touched, for an entry still sitting in the vault.
    expect(remediationTrail(pointerId)).toEqual(['revealed', 'unavailable']);
  });

  it('stamps the trail when the rewrite aborts after the splice was computed', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    // A DIRECTORY sitting on the temp path the rewrite publishes through. The
    // sweep removes only regular files, so it survives, and the exclusive
    // create then fails — an abort reached AFTER the reveal and after the whole
    // splice was computed, which is the half `restoreText`'s own refusals
    // cannot reach. (A file there would simply be swept: it carries this
    // process's own pid.)
    mkdirSync(`${transcript}.${String(process.pid)}.aka-prune.tmp`);

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRowCount()).toBe(1);
    expect(io.output()).toContain('ABORTED');
    expect(io.output()).toContain('the rewrite could not be written');
    expect(remediationTrail(pointerId)).toEqual(['revealed', 'unavailable']);
    expectNoEchoOf(io.output(), MONITOR_RAW);
  });

  it('writes no abort stamp when the restore actually lands', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);

    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], scriptedIo());

    // The control on the case above: a reveal that DID restore leaves the one
    // row it earned, so the stamp cannot be written unconditionally.
    expect(readFileSync(transcript, 'utf8')).toContain(MONITOR_RAW);
    expect(remediationTrail(pointerId)).toEqual(['revealed']);
  });

  it('leaves an in-policy entry and its pointer alone', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    installPack('secrets', 'secrets/token', 'secret', 'vault');
    const monitored = await vaultValue(MONITOR_RAW, 'code-context/file-path', 'code_context');
    const vaulted = await vaultValue(VAULTED_RAW, 'secrets/token', 'secret');
    recordSighting(monitored.pointerId, transcript, 'transcript');
    recordSighting(vaulted.pointerId, transcript, 'transcript');
    writeFileSync(
      transcript,
      `${transcriptLine(monitored.pointer)}\n${transcriptLine(vaulted.pointer)}\n`,
    );

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    const after = readFileSync(transcript, 'utf8');
    expect(after).toContain(MONITOR_RAW);
    // Redact & Vault still authorizes holding this one, so its pointer stays.
    expect(after).toContain(vaulted.pointer);
    expect(after).not.toContain(VAULTED_RAW);
    expect(vaultRuleIds()).toEqual(['secrets/token']);
    expectNoEchoOf(io.output(), VAULTED_RAW);
  });

  it('never prunes an entry whose rule no installed pack carries', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(VAULTED_RAW, 'ghost/rule', 'code_context');
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRuleIds()).toEqual(['ghost/rule']);
    expect(io.output()).toContain('detection not installed  1');
    expect(io.output()).toContain('Nothing to undo.');
  });

  it('keeps an entry whose pointer sits outside the transcript root', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    const outside = join(userHome, 'elsewhere.jsonl');
    writeFileSync(outside, `${transcriptLine(pointer)}\n`);
    recordSighting(pointerId, outside, 'transcript');
    const before = readFileSync(outside, 'utf8');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    // Containment is structural: a path outside every root is never opened for
    // writing, so nothing is restored and nothing may be deleted.
    expect(readFileSync(outside, 'utf8')).toBe(before);
    expect(vaultRowCount()).toBe(1);
    expect(io.output()).toContain('UNREACHABLE');
    expect(io.output()).toContain('outside the transcript root');
    expect(io.output()).toContain('deleted 0 vault entries');
  });

  it('keeps an entry sighted only on a surface, and says so', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointerId } = await vaultValue(MONITOR_RAW, 'code-context/file-path', 'code_context');
    recordSighting(pointerId, 'user prompt', 'prompt');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    expect(vaultRowCount()).toBe(1);
    expect(io.output()).toContain('1 sighted on a prompt / tool-input / tool-output surface');
    expect(io.output()).toContain('The sighting ledger is best-effort');
  });

  it('never deletes an out-of-policy entry that has no sighting', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    // An entry an enforcing path vaulted and no ledger row points at. The rule
    // is assigned Monitor, so the split does file it as out of policy — and
    // phase 2 still refuses it, because deleting a value whose pointer might
    // sit in a file nobody recorded would strand that pointer for ever. This is
    // the ledger-completeness half of the refusal, on its own: the user's own
    // strikes are protected by the row's provenance marker instead, and are
    // covered by the case below.
    const { pointerId } = await vaultValue(MONITOR_RAW, 'code-context/file-path', 'code_context');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    expect(io.output()).toContain('out of policy            1');
    expect(io.output()).toContain('1 with no recorded sighting at all');
    expect(io.output()).toContain('deleted 0 vault entries');
    expect(vaultRowCount()).toBe(1);
    // Nothing was revealed for it either: an unsighted entry names no file, so
    // the restore pass never opens one.
    expect(remediationTrail(pointerId)).toEqual([]);
  });

  // The sequence this verb has to survive, end to end. The value is in the
  // vault twice over — once because a pack enforced, once because a person
  // asked — and the vault is content-addressed, so those two statements share
  // ONE row, sighting and all. Reasoning from today's assignment alone would
  // put the raw value back into the transcript the user had it struck from and
  // then destroy the only copy.
  it('never prunes a value the user struck, after the pack that vaulted it was lowered', async () => {
    // The pack is at Redact & Vault: it vaults on its own, and the scrub
    // records the transcript its pointer landed in.
    installPack('code-context', 'code-context/file-path', 'code_context', 'vault');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
    );
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    // The pack is lowered to Monitor — so the ruleset now says `log` about this
    // rule — and the user then strikes that same value off the surfaced-secrets
    // list, which vaults it whatever the assignment says.
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const struck = await vaultValue(MONITOR_RAW, 'code-context/file-path', 'code_context', true);
    // One value, one row: the strike landed on the row that already carries the
    // transcript sighting.
    expect(struck.pointerId).toBe(pointerId);

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    // Nothing restored, nothing destroyed, nothing revealed.
    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRowCount()).toBe(1);
    expect(purgeDerefCount()).toBe(0);
    expect(remediationTrail(pointerId)).toEqual([]);

    expect(io.output()).toContain('user-authorized          1');
    expect(io.output()).toContain('out of policy            0');
    expect(io.output()).toContain('Nothing to undo.');
    expectNoEchoOf(io.output(), MONITOR_RAW);
  });

  it('keeps that protection when a pack path vaults the same value afterwards', async () => {
    installPack('code-context', 'code-context/file-path', 'code_context', 'monitor');
    const { pointer, pointerId } = await vaultValue(
      MONITOR_RAW,
      'code-context/file-path',
      'code_context',
      true,
    );
    // The enforcing path meets the value again AFTER the strike, and records a
    // transcript sighting on the shared row. What the user said about the value
    // does not expire because a pack saw it again.
    await vaultValue(MONITOR_RAW, 'code-context/file-path', 'code_context');
    recordSighting(pointerId, transcript, 'transcript');
    writeFileSync(transcript, `${transcriptLine(pointer)}\n`);
    const before = readFileSync(transcript, 'utf8');

    const io = scriptedIo();
    await runVault(['prune', '--apply', '--home', home, '--user-home', userHome], io);

    expect(readFileSync(transcript, 'utf8')).toBe(before);
    expect(vaultRowCount()).toBe(1);
    expect(purgeDerefCount()).toBe(0);
    expect(io.output()).toContain('user-authorized          1');
    expect(io.output()).toContain('Nothing to undo.');
    expectNoEchoOf(io.output(), MONITOR_RAW);
  });

  it('prints its own help without touching the store', async () => {
    const io = scriptedIo();
    await runVault(['prune', '--help', '--home', home], io);
    expect(io.output()).toContain('aka vault prune --apply');
    expect(io.output()).toContain('restore the transcripts, then delete those entries');
  });
});
