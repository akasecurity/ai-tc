/**
 * `aka vault prune` — undo vaulting the current detection policy does not
 * authorize.
 *
 * A detection assigned Monitor or Warn may log a match and nothing more. If it
 * once ran under an assignment that vaulted, the machine is left holding two
 * pieces of damage: rows in the encrypted vault that no policy now justifies,
 * and transcripts whose text was rewritten to pointers standing in for values
 * the user never asked to have taken. This verb undoes both.
 *
 * ORDER IS THE WHOLE DESIGN AND IT IS NOT NEGOTIABLE: RESTORE FIRST, VERIFY,
 * DELETE LAST. The vault holds the only remaining copy of the plaintext, so a
 * pointer whose row is deleted before its transcript is rewritten can never be
 * resolved again — the transcript would be left reading as an unresolvable
 * token where a file path used to be. The store's scoped delete is therefore
 * reachable only from the far side of the restore pass, and the list it is
 * handed is derived from what that pass actually CLEARED, never from the
 * selection alone.
 *
 * Because it writes recovered PLAINTEXT back to disk, the verb is dry-run by
 * default (`--apply` performs it), it rewrites only files whose real path is
 * contained in the Claude Code transcript root, and any doubt about a file
 * leaves that file byte-identical and everything sighted in it in the vault.
 */
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import type { LocalDatabase, VaultRow } from '@akasecurity/persistence';
import {
  createKeyProvider,
  dataDir,
  keysDir,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type { ActionTaken, VaultSighting } from '@akasecurity/schema';
import {
  isActionAtLeast,
  isVaultConsentValid,
  MAX_VAULT_PAGE_LIMIT,
  pointerTokenScanner,
} from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import type { TransformResult } from '../lib/transcript-rewrite.ts';
import {
  containedRealPath,
  readContainedFile,
  rewriteContainedFile,
  transcriptRoots,
} from '../lib/transcript-rewrite.ts';

export const VAULT_PRUNE_HELP = `Undo vaulting that the current detection policy does not authorize.

  aka vault prune              show what would change (default)
  aka vault prune --apply      restore the transcripts, then delete those entries

A detection assigned Monitor or Warn may only log a match. Entries this machine
vaulted under a stronger assignment are out of policy once it is lowered, and
the transcripts carrying their pointers were rewritten for a value the policy no
longer says to take. This restores those pointers to their raw values FIRST and
deletes the vault entries only afterwards — the vault holds the only copy, so
the reverse order would strand every one of those pointers forever.

Only entries whose detection is installed AND enabled are considered. A rule the
installed packs no longer carry is left alone: a pack that is uninstalled or
switched off has made no statement about redaction. An entry you asked for
yourself — the Redact button on a surfaced secret — is left alone too, whatever
its detection is assigned now.

Flags:
  --apply             perform the restore and the delete (default: dry run)
  --user-home <dir>   OS home whose ~/.claude/projects holds the transcripts
  --home <dir>        alternate AKA home (default: ~/.aka)
`;

// The enforcement floor a detection must reach before anything it matches may
// be rewritten, masked at rest, or put in the vault. Below it, a match is a log
// line and nothing else.
const VAULTING_FLOOR: ActionTaken = 'redact';

/** One vault entry the current policy no longer justifies holding. */
export interface OutOfPolicyEntry {
  pointerId: string;
  valueFingerprint: string;
  ruleId: string;
  // The action this entry's detection resolves to NOW — always below the floor.
  action: ActionTaken;
}

export interface PolicySelection {
  outOfPolicy: OutOfPolicyEntry[];
  // Entries whose detection still authorizes vaulting.
  inPolicy: number;
  // Entries whose rule id no installed, enabled detection carries. NOT pruned.
  ruleNotInstalled: number;
  // Entries a person asked for, whatever their detection now says. NOT pruned.
  userAuthorized: number;
}

/**
 * Split the vault by what the installed detections say about each entry's rule
 * TODAY — and by what a person has said about the value, which outranks it.
 *
 * A rule id missing from the snapshot is deliberately NOT read as out of
 * policy. `installedRuleset` carries only the rules of packs that are installed
 * AND enabled, so an absent id means the pack was uninstalled, switched off, or
 * never installed here — none of which is a statement that the value must not
 * be held. Reading absence as "below redact" would empty the vault of
 * everything a user merely toggled off, and that deletion does not come back.
 * Absence is counted and reported instead.
 *
 * ONE VAULTING PATH THE RULESET CANNOT SPEAK FOR, which is why the row is asked
 * as well. A value the user pointed at on a surfaced-secrets list is vaulted
 * whatever its pack was assigned, because that is an instruction about specific
 * values and not the pack enforcing anything. Read from the ruleset alone such
 * an entry is indistinguishable from an out-of-policy one — the assignment says
 * `log`, which is exactly what it said when the value was struck — so pruning
 * it would restore the raw value into the artifact the user asked to have it
 * taken out of, and destroy the entry. `userAuthorized` is the row's own record
 * that a person asked, and it is what this reads.
 *
 * It is read from the ROW rather than inferred from the entry's bookkeeping
 * elsewhere. Absence of a sighting was the earlier stand-in and is not
 * sufficient: the vault is content-addressed, so one distinct value is ONE row
 * however many paths vault it, and a transcript sighting recorded by an
 * automatic vaulting of that same value sits on the row a later user strike
 * upserts onto. The marker survives that sharing — the store refuses to clear
 * it — and an absent sighting does not.
 */
export function selectOutOfPolicy(
  rows: readonly VaultRow[],
  ruleActions: ReadonlyMap<string, ActionTaken>,
): PolicySelection {
  const selection: PolicySelection = {
    outOfPolicy: [],
    inPolicy: 0,
    ruleNotInstalled: 0,
    userAuthorized: 0,
  };
  for (const row of rows) {
    // Checked before the ruleset, because it is an answer about this VALUE and
    // the ruleset only has answers about the rule that matched it.
    if (row.userAuthorized) {
      selection.userAuthorized += 1;
      continue;
    }
    const action = ruleActions.get(row.ruleId);
    if (action === undefined) {
      selection.ruleNotInstalled += 1;
      continue;
    }
    if (isActionAtLeast(action, VAULTING_FLOOR)) {
      selection.inPolicy += 1;
      continue;
    }
    selection.outOfPolicy.push({
      pointerId: row.pointerId,
      valueFingerprint: row.valueFingerprint,
      ruleId: row.ruleId,
      action,
    });
  }
  return selection;
}

/** The one store read the ledger walk needs: a page of the vault inventory. */
export interface SightingLedgerSource {
  secretVault: Pick<LocalDatabase['secretVault'], 'listInventory'>;
}

/**
 * Everywhere each pointer has been written, one page at a time.
 *
 * The inventory read is the only raw-free surface that carries sightings, so
 * the whole ledger is walked rather than queried per row. It orders on a
 * mutable column, so the walk is bounded by the store's own total as well as by
 * the cursor: a `last_seen` bump landing mid-walk must cost a missed entry (an
 * entry not pruned), never a loop.
 *
 * The page budget is taken from the FIRST page's store-wide total and then
 * spent one per iteration, unconditionally. Re-deriving it from every page
 * would let a store being written to raise the ceiling exactly as fast as the
 * walk lowers it — a bound that reaches a fixed point and never binds, leaving
 * the cursor as the only thing ending the loop, which is the very thing this
 * counter is here to backstop.
 */
export function sightingLedger(db: SightingLedgerSource): Map<string, VaultSighting[]> {
  const ledger = new Map<string, VaultSighting[]>();
  let cursor: string | undefined;
  // Undefined until the first page reports the total. The `+ 1` covers the
  // final page, which carries rows and no next cursor.
  let pagesLeft: number | undefined;
  do {
    const page = db.secretVault.listInventory({
      limit: MAX_VAULT_PAGE_LIMIT,
      ...(cursor === undefined ? {} : { cursor }),
    });
    for (const entry of page.items) ledger.set(entry.pointerId, entry.sightings);
    cursor = page.nextCursor ?? undefined;
    pagesLeft ??= Math.ceil(page.totals.values / MAX_VAULT_PAGE_LIMIT) + 1;
    pagesLeft -= 1;
  } while (cursor !== undefined && pagesLeft > 0);
  return ledger;
}

/** What this pass found, or did, in one transcript the ledger points at. */
interface FileReport {
  location: string;
  status: 'restored' | 'clean' | 'aborted' | 'unreachable';
  // Pointer occurrences rewritten back to their raw value — or, in a dry run,
  // the occurrences that would be.
  replaced: number;
  // False when anything leaves doubt that a pointer sighted here is really
  // gone. Every entry sighted in such a file stays in the vault.
  cleared: boolean;
  detail?: string;
}

function isJson(line: string): boolean {
  try {
    JSON.parse(line);
    return true;
  } catch {
    return false;
  }
}

/**
 * Which pointers in this text belong to an out-of-policy entry, and how many
 * tokens the vault could not attribute at all.
 *
 * Identification is audit-free by construction — `resolvePointerIdentity`
 * verifies a tag and reads a row, and writes no de-reference record — which is
 * what lets the dry run analyse a file without leaving a trail claiming a
 * reveal that never happened.
 */
async function analyseText(
  text: string,
  deps: {
    entryFor: (valueFingerprint: string) => OutOfPolicyEntry | undefined;
    identify: (token: string) => Promise<{ valueFingerprint: string } | null>;
  },
): Promise<{ hits: Map<string, OutOfPolicyEntry>; occurrences: number; unattributable: number }> {
  const hits = new Map<string, OutOfPolicyEntry>();
  const found = text.match(pointerTokenScanner()) ?? [];
  const tokens = new Set(found);
  let unattributable = 0;

  for (const token of tokens) {
    const identity = await deps.identify(token);
    if (identity === null) {
      // A token this vault cannot identify at all. It is attributable to no
      // entry, so it may be one we are about to delete — every entry sighted in
      // this file therefore loses its claim to being pruned.
      unattributable += 1;
      continue;
    }
    const entry = deps.entryFor(identity.valueFingerprint);
    if (entry === undefined) continue; // an in-policy entry — leave it alone
    hits.set(token, entry);
  }

  const occurrences = found.reduce((sum, token) => sum + (hits.has(token) ? 1 : 0), 0);
  return { hits, occurrences, unattributable };
}

/**
 * Rewrite every out-of-policy pointer in one transcript back to its raw value,
 * or abort the whole file.
 *
 * Four things abort rather than half-rewrite, because a transcript is a user's
 * own record and a partially restored one is worse than an untouched one:
 *
 *  - a pointer we mean to restore that the vault will not resolve (the value is
 *    gone, so the token is all that is left of it);
 *  - a restored value that is empty, or that carries a pointer token of its own;
 *  - a line that was valid JSON before the splice and is not after it. The
 *    scrub that put a pointer there replaced bytes INSIDE a JSON string, so
 *    putting the same bytes back reproduces the original line exactly — unless
 *    the entry was minted elsewhere from already-decoded text, in which case its
 *    raw form is unescaped and would break the record it is spliced into;
 *  - any pointer left in the finished text that we set out to replace.
 */
async function restoreText(
  text: string,
  hits: ReadonlyMap<string, OutOfPolicyEntry>,
  reveal: (token: string) => Promise<string | null>,
): Promise<TransformResult> {
  const replacements = new Map<string, string>();
  for (const token of hits.keys()) {
    const raw = await reveal(token);
    if (raw === null || raw === '') {
      return { abort: 'a pointer here could not be resolved back to its value' };
    }
    if (raw.includes('[[aka:')) {
      return { abort: 'a restored value would carry a pointer of its own' };
    }
    replacements.set(token, raw);
  }
  if (replacements.size === 0) return { text, replaced: 0 };

  // Line by line, so a splice can only change bytes WITHIN a line: the newline
  // structure — a trailing newline included, which survives the split/join
  // round trip as a final empty element — is preserved exactly.
  const lines = text.split('\n');
  let replaced = 0;
  for (const [index, line] of lines.entries()) {
    if (line === '') continue;
    let next = line;
    for (const [token, raw] of replacements) {
      if (!next.includes(token)) continue;
      // Literal splice via split/join, never a replace-family call: a `$` in a
      // recovered value carries no pattern semantics here.
      const parts = next.split(token);
      replaced += parts.length - 1;
      next = parts.join(raw);
    }
    if (next === line) continue;
    if (isJson(line) && !isJson(next)) {
      return { abort: 'restoring would break a record in this file' };
    }
    lines[index] = next;
  }

  const out = lines.join('\n');
  for (const token of replacements.keys()) {
    if (out.includes(token)) return { abort: 'a pointer survived the rewrite' };
  }
  return { text: out, replaced };
}

/**
 * Record, for each pointer a file's transform revealed, that the restore it was
 * revealed FOR did not happen.
 *
 * `detokenize` writes its `revealed` row the instant it opens a row's
 * ciphertext, and every check that can still abort the file sits after that: a
 * splice that breaks a JSON record, a pointer that survived the rewrite, a
 * transcript that grew between the read and the rename. Left alone, the trail
 * would carry a reveal against a file that is byte-identical and an entry that
 * is still vaulted — the same false record the dry run refuses to write.
 *
 * Two ways to make the trail agree with the disk, and the reveal cannot be the
 * one deferred: every route to a plaintext this verb can call audits before it
 * returns, so holding the row back until after the rename is not something the
 * caller can choose. The abort is stamped instead. Both halves are true of what
 * happened — the process really did hold the value, and the restore it was for
 * really did deliver nothing — so a reader of the trail sees the reveal and, at
 * the same pointer, a `remediation` row whose outcome says nothing came of it.
 * `unavailable` is the outcome the purge trail already uses for a pointer that
 * resolves to nothing usable; a reveal is not `refused`.
 */
function stampUnrestored(db: LocalDatabase, pointerIds: readonly string[]): void {
  for (const pointerId of pointerIds) {
    db.secretVault.recordDeref({
      id: randomUUID(),
      pointerId,
      at: Date.now(),
      target: 'human',
      reason: 'remediation',
      outcome: 'unavailable',
    });
  }
}

function plural(count: number, one: string, many: string): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

export async function runPrune(argv: string[], io: Prompter): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      ...HOME_OPTION,
      apply: { type: 'boolean', default: false },
      'user-home': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help === true) {
    io.out(VAULT_PRUNE_HELP);
    return;
  }

  const apply = values.apply;
  const base = homeBase(values.home);
  const roots = transcriptRoots(values['user-home']);
  const db = openLocalDatabase(dataDir(base));
  const out: string[] = [];

  try {
    const { ruleActions } = db.installedPacks.installedRuleset();
    const selection = selectOutOfPolicy(db.secretVault.listAll(), ruleActions);
    const total =
      selection.outOfPolicy.length +
      selection.inPolicy +
      selection.ruleNotInstalled +
      selection.userAuthorized;

    out.push(apply ? 'aka vault prune' : 'aka vault prune — DRY RUN, nothing was changed');
    out.push('');
    out.push(`Vault entries              ${String(total)}`);
    out.push(
      `  out of policy            ${String(selection.outOfPolicy.length)}  their detection may not vault`,
    );
    out.push(`  in policy                ${String(selection.inPolicy)}`);
    out.push(`  detection not installed  ${String(selection.ruleNotInstalled)}  left alone`);
    out.push(
      `  user-authorized          ${String(selection.userAuthorized)}  the user asked for these; left alone`,
    );

    if (selection.outOfPolicy.length === 0) {
      out.push('');
      out.push('Nothing to undo.');
      io.out(`${out.join('\n')}\n`);
      return;
    }

    const byFingerprint = new Map(selection.outOfPolicy.map((e) => [e.valueFingerprint, e]));
    const ledger = sightingLedger(db);

    // Where each out-of-policy entry's pointer was written. A sighting whose
    // kind is not `transcript` records a SURFACE — a prompt, a tool input, a
    // tool output — rather than a file, so it names nothing this verb can open.
    const locations = new Set<string>();
    let surfaceSighted = 0;
    let unsighted = 0;
    for (const entry of selection.outOfPolicy) {
      const sightings = ledger.get(entry.pointerId) ?? [];
      const files = sightings.filter((s) => s.kind === 'transcript');
      for (const sighting of files) locations.add(sighting.location);
      if (sightings.length === 0) unsighted += 1;
      else if (files.length < sightings.length) surfaceSighted += 1;
    }

    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(readWorkspaceSettings(base).vaultKeyCustody, keysDir(base)),
      // Read live, exactly as `aka vault show` does. Consent gates VAULTING; it
      // has never gated a reveal, and this verb only ever reveals.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(base).vaultConsent),
    });

    const analyse = async (text: string): Promise<Awaited<ReturnType<typeof analyseText>>> =>
      analyseText(text, {
        entryFor: (fingerprint) => byFingerprint.get(fingerprint),
        identify: (token) => vault.resolvePointerIdentity(token),
      });

    // ── PHASE 1: restore. Nothing below this loop may delete anything. ──────
    const reports: FileReport[] = [];
    const clearedLocations = new Set<string>();

    for (const location of [...locations].sort()) {
      const realPath = containedRealPath(location, roots);
      if (realPath === null) {
        reports.push({
          location,
          status: 'unreachable',
          replaced: 0,
          cleared: false,
          detail: 'missing, or outside the transcript root',
        });
        continue;
      }

      if (!apply) {
        // The plan reads and analyses the same bytes the apply pass would, and
        // stops there. It never reveals: `detokenize` writes an audit row, and
        // an audited reveal that produced no restore is a false record. The
        // count it prints is therefore an upper bound, and the summary says so.
        const text = readContainedFile(realPath);
        if (text === null) {
          reports.push({
            location,
            status: 'unreachable',
            replaced: 0,
            cleared: false,
            detail: 'unreadable, or larger than the read cap',
          });
          continue;
        }
        const plan = await analyse(text);
        const cleared = plan.unattributable === 0;
        reports.push({
          location,
          status: plan.occurrences === 0 ? 'clean' : 'restored',
          replaced: plan.occurrences,
          cleared,
          ...(cleared ? {} : { detail: 'carries pointers this vault cannot identify' }),
        });
        if (cleared) clearedLocations.add(location);
        continue;
      }

      // `unattributable` is captured from the transform because the bytes the
      // rewrite actually acts on are the ones it read itself, under its own
      // stat — re-reading here to look would be asking a different file.
      // `revealed` is captured the same way and for the abort trail below.
      let unattributable = 0;
      const revealed: string[] = [];
      const outcome = await rewriteContainedFile(realPath, async (text) => {
        const analysis = await analyse(text);
        unattributable = analysis.unattributable;
        revealed.length = 0;
        return await restoreText(text, analysis.hits, async (token) => {
          const value = await vault.detokenize(token, { target: 'human', reason: 'remediation' });
          if (typeof value !== 'string') return null;
          const entry = analysis.hits.get(token);
          if (entry !== undefined) revealed.push(entry.pointerId);
          return value;
        });
      });

      // The rewrite did not land, so every reveal it audited above stands for a
      // restore that never happened. Say so, against the same pointers.
      if (outcome.status !== 'rewritten') stampUnrestored(db, revealed);

      if (outcome.status === 'aborted') {
        reports.push({
          location,
          status: 'aborted',
          replaced: 0,
          cleared: false,
          detail: outcome.reason,
        });
        continue;
      }
      const cleared = unattributable === 0;
      reports.push({
        location,
        status: outcome.status === 'unchanged' ? 'clean' : 'restored',
        replaced: outcome.status === 'unchanged' ? 0 : outcome.replaced,
        cleared,
        ...(cleared ? {} : { detail: 'carries pointers this vault cannot identify' }),
      });
      if (cleared) clearedLocations.add(location);
    }

    // ── PHASE 2: prune, and only what phase 1 cleared. ─────────────────────
    // An entry may be deleted only when EVERY place the ledger records its
    // pointer is a transcript this pass cleared. Anything else — a surface
    // sighting, no sighting at all, one file left in doubt — keeps the entry,
    // because the vault is the only remaining copy of what that pointer stands
    // for.
    const prunable = selection.outOfPolicy.filter((entry) => {
      const sightings = ledger.get(entry.pointerId) ?? [];
      if (sightings.length === 0) return false;
      return sightings.every((s) => s.kind === 'transcript' && clearedLocations.has(s.location));
    });

    const totalReplaced = reports.reduce((sum, r) => sum + r.replaced, 0);
    out.push('');
    if (reports.length === 0) {
      out.push('No transcript the ledger records carries a pointer for these entries.');
    } else {
      out.push('Transcripts');
      for (const report of reports) {
        const suffix = report.detail === undefined ? '' : `  (${report.detail})`;
        const status = report.status.toUpperCase().padEnd(11);
        out.push(`  ${status}${String(report.replaced).padStart(6)}  ${report.location}${suffix}`);
      }
    }

    out.push('');
    if (apply) {
      // Audited from what the DELETE reported, never from the selection that
      // asked for it. `prunable` is a claim about a read taken before the whole
      // restore pass; the store is shared, and an entry another process purged
      // in between is one this pass never destroyed. A purge row written for it
      // records a destruction that did not happen here — the same false record
      // the abort stamp above exists to keep out of this trail.
      const deleted = db.secretVault.deleteByPointerIds(prunable.map((e) => e.pointerId));
      for (const pointerId of deleted) {
        // The purge trail outlives the values, exactly as the vault's own purge
        // does: the record that entries were destroyed has to survive them.
        db.secretVault.recordDeref({
          id: randomUUID(),
          pointerId,
          at: Date.now(),
          target: 'human',
          reason: 'purge',
          outcome: 'unavailable',
        });
      }
      out.push(
        `Restored ${plural(totalReplaced, 'pointer', 'pointers')}, then deleted ${plural(deleted.length, 'vault entry', 'vault entries')}.`,
      );
    } else {
      out.push(
        `Would restore up to ${plural(totalReplaced, 'pointer', 'pointers')}, then delete ${plural(prunable.length, 'vault entry', 'vault entries')}.`,
      );
      out.push('An upper bound: a value the vault cannot resolve, or a record that');
      out.push('restoring would break, aborts its whole file when --apply runs.');
    }

    const kept = selection.outOfPolicy.length - prunable.length;
    if (kept > 0) {
      out.push('');
      out.push(
        `${plural(kept, 'out-of-policy entry stays', 'out-of-policy entries stay')} in the vault:`,
      );
      if (surfaceSighted > 0) {
        out.push(
          `  ${String(surfaceSighted)} sighted on a prompt / tool-input / tool-output surface, which names no file`,
        );
      }
      if (unsighted > 0) out.push(`  ${String(unsighted)} with no recorded sighting at all`);
      out.push('  any others sit in a transcript this pass could not clear (listed above)');
      out.push('Deleting them would leave their pointers permanently unresolvable.');
    }

    out.push('');
    out.push('The sighting ledger is best-effort: a pointer may sit in a file it never');
    out.push('recorded, and this pass does not find those.');

    io.out(`${out.join('\n')}\n`);
  } finally {
    db.close();
  }
}
