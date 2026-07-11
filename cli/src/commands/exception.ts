import { userInfo } from 'node:os';
import { parseArgs } from 'node:util';

import { getLoadedRules, maskMatch, scan } from '@akasecurity/detections';
import type { BlockedDetection, LocalDatabase } from '@akasecurity/persistence';
import type { CreateExceptionInput } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import {
  dataDir,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  registerBundledPacks,
  rotateFingerprintKey,
} from '@akasecurity/plugin-sdk';
import type { DetectionException, ResolvedScope } from '@akasecurity/schema';
import { resolveScopeFlags, scopeFromAnswer } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { formatRelative, formatTimestamp } from '../lib/duration.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

// Task-oriented top screen (also shown for unknown subcommands): the two
// situations users are actually in first, then the review/undo verbs, then the
// two rules every grant follows.
const EXCEPTION_HELP = `Manage detection exceptions (explicit, audited bypasses).

Just got blocked?         aka exception approve            pick the block, choose scope
Pre-authorize a value:    aka exception add --rule <id>    value via hidden prompt/stdin
Review / undo:            aka exception list · show <id> · revoke <id>
Key hygiene:              aka exception rotate-key         invalidates every grant

Scopes (required, pick one):  --once | --for 30m|1h|24h | --permanent
Every exception needs --reason "<why>" — it is the audit trail.
Run 'aka exception <verb> --help' for flags.
`;

const SCOPE_REQUIRED = `a scope is required — pick exactly one (there is no default):
  --once            single use, 30-minute backstop expiry
  --for <duration>  time-limited: 30m, 1h, 24h (max 24h)
  --permanent       until revoked (typed confirmation required)`;

const VERB_HELP: Record<string, string> = {
  approve: `Usage: aka exception approve [reference|value] [flags]

Grant an exception from a detection blocked in the last 30 minutes. Select the
block by the reference from the block message, the masked value shown there,
or by pasting the blocked value itself. A pasted value is matched by its keyed
fingerprint and never stored or echoed — but it does land in your shell
history, so prefer the reference where that matters.

Flags:
  --once | --for <30m|1h|24h> | --permanent   scope (required, pick one)
  --reason "<why>"    required; prompted on a terminal if omitted
  --yes               skip confirmations (non-interactive use)
  --home <dir>        alternate AKA home (default: ~/.aka)

Example: aka exception approve 3f2a --for 1h --reason "temp deploy creds"
`,
  add: `Usage: aka exception add --rule <ruleId> [--stdin] [flags]

Pre-authorize a value that was not just blocked. The value is NEVER accepted as
an argument — pipe it with --stdin or type it at the hidden prompt. It must
actually match the given rule, or the grant would never apply.

Flags:
  --rule <ruleId>     the detection rule to except (required)
  --stdin             read the value from stdin (otherwise: hidden prompt)
  --once | --for <30m|1h|24h> | --permanent   scope (required, pick one)
  --reason "<why>"    required; prompted on a terminal if omitted
  --yes               skip confirmations (non-interactive use)
  --home <dir>        alternate AKA home (default: ~/.aka)

Example: aka exception add --rule secrets/aws-access-key --stdin --once --reason "rotating today" < key.txt
`,
  list: `Usage: aka exception list [--all]

Active exceptions by default; --all includes expired, consumed, and revoked
grants (kept as audit evidence) with a STATE column.

Example: aka exception list --all
`,
  show: `Usage: aka exception show <id>

Full detail for one exception (id prefix is enough when unambiguous).

Example: aka exception show 3f2a91
`,
  revoke: `Usage: aka exception revoke <id> [--reason "<why>"] [--yes]

Revoke an active exception (id prefix ok). Nothing is deleted — the row is
kept as audit evidence.

Example: aka exception revoke 3f2a91 --reason "no longer needed"
`,
  'rotate-key': `Usage: aka exception rotate-key [--yes]

Mint a new fingerprint key. Rotation is invalidation: EVERY existing grant
stops matching (fingerprints cannot be re-keyed — raw values are never
stored). Active permanent grants are listed so they can be re-approved
deliberately.

Example: aka exception rotate-key
`,
};

// Scope + confirmation flags shared by approve/add.
const SCOPE_OPTIONS = {
  once: { type: 'boolean' },
  for: { type: 'string' },
  permanent: { type: 'boolean' },
  reason: { type: 'string' },
  yes: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
} as const;

// registerBundledPacks parses+validates every bundled rule JSON — do it once
// per process (mirrors the runtime's own guard).
let packsRegistered = false;
function ensurePacks(): void {
  if (!packsRegistered) {
    registerBundledPacks();
    packsRegistered = true;
  }
}

// Who grants/revokes. There is no machine-local user identity in the OSS
// store (it is tenant-free), so the OS account name is the honest source.
function resolveCreatedBy(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

function shortId(id: string): string {
  return id.slice(0, 6);
}

// Derived exception state (never stored — see the persistence repository).
function stateOf(ex: DetectionException, now = Date.now()): string {
  if (ex.revokedAt !== null) return 'revoked';
  if (ex.maxUses !== null && ex.useCount >= ex.maxUses) return 'consumed';
  if (ex.expiresAt !== null && Date.parse(ex.expiresAt) <= now) return 'expired';
  return 'active';
}

function viaLabel(via: DetectionException['createdVia']): string {
  switch (via) {
    case 'cli-approve':
      return 'approve';
    case 'cli-add':
      return 'add';
    case 'web-approve':
      return 'web approve';
    case 'web-add':
      return 'web add';
    case 'api':
      return 'api';
  }
}

function scopeSummary(ex: Pick<DetectionException, 'scope' | 'expiresAt'>): string {
  if (ex.scope === 'permanent') return 'permanent — until revoked';
  if (ex.expiresAt === null) return ex.scope;
  return `${ex.scope} — expires ${formatTimestamp(ex.expiresAt)} (${formatRelative(ex.expiresAt)})`;
}

// Two-space-indented monochrome table (matches the plain `aka stats` aesthetic).
function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((row) => (row[i] ?? '').length)),
  );
  const line = (cells: string[]): string =>
    `  ${cells
      .map((cell, i) => cell.padEnd(widths[i] ?? 0))
      .join('  ')
      .trimEnd()}\n`;
  return line(headers) + rows.map(line).join('');
}

// ---------------------------------------------------------------------------
// Shared prompt flows
// ---------------------------------------------------------------------------

interface ScopeReasonFlags {
  once?: boolean | undefined;
  for?: string | undefined;
  permanent?: boolean | undefined;
  reason?: string | undefined;
}

// Scope and reason, from flags or (on a terminal) interactive prompts. Scope
// is an explicit choice — no flag and no TTY is an error, never a default.
async function resolveScopeAndReason(
  flags: ScopeReasonFlags,
  io: Prompter,
): Promise<{ scope: ResolvedScope; reason: string }> {
  let scope = resolveScopeFlags({
    once: flags.once,
    for: flags.for,
    permanent: flags.permanent,
  });
  if (scope === null) {
    if (!io.isInteractive) throw new Error(SCOPE_REQUIRED);
    scope = scopeFromAnswer(await io.ask('Scope — once, a duration (30m/1h/24h), or permanent: '));
  }
  let reason = flags.reason?.trim() ?? '';
  if (reason === '') {
    if (!io.isInteractive) {
      throw new Error('--reason "<why>" is required — it is the audit trail');
    }
    reason = (await io.ask('Reason (recorded in the audit trail): ')).trim();
    if (reason === '') throw new Error('a non-empty reason is required — it is the audit trail');
  }
  return { scope, reason };
}

// The --permanent guard: on a terminal the user types the masked value back
// (a deliberate, value-specific confirmation); non-interactively --yes is
// required and a loud warning is printed.
async function confirmPermanent(io: Prompter, maskedValue: string, yes: boolean): Promise<void> {
  if (io.isInteractive) {
    io.out('A permanent exception never expires — it applies until explicitly revoked.\n');
    const typed = await io.ask(`Type the masked value ${maskedValue} to confirm: `);
    if (typed.trim() !== maskedValue) {
      throw new Error('confirmation did not match — nothing was created');
    }
    return;
  }
  if (!yes) {
    throw new Error(
      'a permanent exception requires confirmation — run on a terminal, or pass --yes to proceed non-interactively',
    );
  }
  io.err(
    'WARNING: creating a PERMANENT exception without interactive confirmation (--yes). It applies until explicitly revoked — review with: aka exception list\n',
  );
}

async function createGrant(
  db: LocalDatabase,
  input: CreateExceptionInput,
): Promise<DetectionException> {
  try {
    return await db.exceptions.create(input);
  } catch (err) {
    if ((err as { code?: string }).code === 'duplicate-active-exception') {
      throw new Error(
        `an active exception already exists for rule "${input.ruleId}" and this value — see 'aka exception list' and revoke it before granting a new one`,
        { cause: err },
      );
    }
    throw err;
  }
}

function printGranted(io: Prompter, ex: DetectionException): void {
  io.out(
    `Exception granted: ${shortId(ex.id)}  ${ex.ruleId}  ${ex.maskedValue}  ${scopeSummary(ex)}\n`,
  );
}

// ---------------------------------------------------------------------------
// approve — grant from the blocked-detections ledger (the primary flow)
// ---------------------------------------------------------------------------

function blockedLine(entry: BlockedDetection): string {
  return `${entry.reference}  ${entry.maskedValue}  ${entry.ruleId}  ${formatRelative(entry.blockedAt)}`;
}

async function pickBlocked(
  entries: BlockedDetection[],
  selector: string | undefined,
  io: Prompter,
  dir: string,
): Promise<BlockedDetection> {
  if (selector !== undefined) {
    // The selector is the ledger reference (as printed in the block message),
    // the masked value the user saw there, or the blocked value itself pasted
    // back. A pasted value is reduced to its keyed fingerprint for the
    // comparison — it is never stored, and because it may be a live secret it
    // is never echoed back in any message below.
    const matches = entries.filter(
      (e) => e.reference.startsWith(selector) || e.maskedValue === selector,
    );
    const exact = matches.find((e) => e.reference === selector);
    if (exact) return exact;
    if (matches.length === 1 && matches[0]) return matches[0];
    if (matches.length > 1) {
      throw new Error(
        `the selector matches ${String(matches.length)} recent blocks — run 'aka exception approve' bare to pick from the list`,
      );
    }
    const key = loadOrCreateFingerprintKey(dir);
    const fingerprint = fingerprintValue(key, selector);
    const byValue = entries.filter(
      (e) => e.keyVersion === key.version && e.valueFingerprint === fingerprint,
    );
    const newest = byValue[0];
    if (newest) {
      const rules = new Set(byValue.map((e) => e.ruleId));
      if (rules.size > 1) {
        throw new Error(
          `that value was blocked under ${String(rules.size)} different rules — run 'aka exception approve' bare to pick which rule to except`,
        );
      }
      // Same value, same rule, blocked more than once: the rows are
      // interchangeable grant material (entries arrive newest-first).
      return newest;
    }
    throw new Error(
      `no blocked detection matches that reference or value — run 'aka exception approve' to list recent blocks`,
    );
  }
  const only = entries[0];
  if (entries.length === 1 && only) {
    io.out(`Approving the only recent block:\n  ${blockedLine(only)}\n`);
    return only;
  }
  if (!io.isInteractive) {
    io.err(`Blocked in the last 30 minutes:\n`);
    for (const entry of entries) io.err(`  ${blockedLine(entry)}\n`);
    throw new Error('pass the reference to approve: aka exception approve <reference>');
  }
  io.out('Blocked in the last 30 minutes:\n');
  entries.forEach((entry, i) => {
    io.out(`  ${String(i + 1)}) ${blockedLine(entry)}\n`);
  });
  const answer = await io.ask(`Which one? [1-${String(entries.length)}]: `);
  const index = Number.parseInt(answer.trim(), 10);
  const picked = Number.isInteger(index) ? entries[index - 1] : undefined;
  if (!picked) throw new Error(`invalid choice '${answer.trim()}'`);
  return picked;
}

async function runApprove(argv: string[], io: Prompter): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, ...SCOPE_OPTIONS },
    allowPositionals: true,
  });
  if (values.help) {
    io.out(VERB_HELP.approve ?? '');
    return;
  }
  const dir = dataDir(homeBase(values.home));
  const db = openLocalDatabase(dir);
  try {
    const entries = await db.exceptions.recentBlocked();
    if (entries.length === 0) {
      io.out(
        `Nothing was blocked in the last 30 minutes, so there is nothing to approve.\nTo pre-authorize a value instead: aka exception add --rule <ruleId>\n`,
      );
      return;
    }
    // Trim paste artifacts (a multi-line paste arrives with embedded
    // newlines); a whitespace-only selector falls back to the bare picker.
    const selector = positionals[0]?.trim();
    const entry = await pickBlocked(entries, selector === '' ? undefined : selector, io, dir);
    const { scope, reason } = await resolveScopeAndReason(values, io);
    if (scope.scope === 'permanent') {
      await confirmPermanent(io, entry.maskedValue, values.yes === true);
    }
    // The grant is created FROM THE LEDGER ENTRY — the fingerprint was
    // computed when the hook blocked; the raw value never enters this process.
    const granted = await createGrant(db, {
      ruleId: entry.ruleId,
      category: entry.category,
      valueFingerprint: entry.valueFingerprint,
      keyVersion: entry.keyVersion,
      maskedValue: entry.maskedValue,
      ...scope,
      justification: reason,
      conditions: null,
      createdBy: resolveCreatedBy(),
      createdVia: 'cli-approve',
    });
    printGranted(io, granted);
    io.out('Resubmit the blocked prompt — it will now pass.\n');
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// add — grant for a value supplied out-of-band (stdin / hidden prompt)
// ---------------------------------------------------------------------------

// Read the value (never from argv), verify it actually triggers the rule, and
// reduce it to fingerprint + masked preview. The raw value stays inside this
// function: only the derived, non-reversible fields escape, and the local
// references are cleared before returning.
async function fingerprintForRule(
  ruleId: string,
  useStdin: boolean,
  dir: string,
  io: Prompter,
): Promise<{ valueFingerprint: string; keyVersion: number; maskedValue: string }> {
  let raw: string;
  if (useStdin) {
    // Trim ONLY the trailing newline — anything else may be part of the value.
    raw = (await io.readAllStdin()).replace(/\r?\n$/, '');
  } else if (io.isInteractive) {
    raw = await io.askHidden(`Value for ${ruleId} (hidden): `);
  } else {
    throw new Error(
      'no value: pipe it with --stdin (aka exception add --rule <id> --stdin < file) or run on a terminal for a hidden prompt',
    );
  }
  if (raw.length === 0) throw new Error('empty value — nothing to except');

  // The grant must bind to something the engine would actually detect under
  // this rule, or it would never apply at enforcement time.
  const matches = scan(raw);
  const ruleMatches = matches.filter((m) => m.ruleId === ruleId);
  if (ruleMatches.length === 0) {
    const others = [...new Set(matches.map((m) => m.ruleId))];
    const hint =
      others.length > 0
        ? ` The value DOES match: ${others.join(', ')} — did you mean one of those?`
        : '';
    throw new Error(
      `value does not match rule ${ruleId}; a grant for it would never apply.${hint}`,
    );
  }
  const spans = [...new Set(ruleMatches.map((m) => m.rawMatch))];
  const first = spans[0];
  if (spans.length > 1 || first === undefined) {
    throw new Error(
      `the input contains ${String(spans.length)} distinct values matching rule ${ruleId} — supply exactly one`,
    );
  }
  if (first !== raw) {
    io.out('Note: the grant binds to the exact detected span, not the whole input.\n');
  }

  const key = loadOrCreateFingerprintKey(dir);
  const result = {
    valueFingerprint: fingerprintValue(key, first),
    keyVersion: key.version,
    maskedValue: maskMatch(first),
  };
  // `raw` goes out of scope here — only the non-reversible fields survive.
  return result;
}

async function runAdd(argv: string[], io: Prompter): Promise<void> {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        ...HOME_OPTION,
        ...SCOPE_OPTIONS,
        rule: { type: 'string' },
        stdin: { type: 'boolean' },
      },
    }));
  } catch (err) {
    // parseArgs echoes the offending argument in its message — if someone
    // passed the secret as a positional it is already in shell history and
    // `ps`, but it must NOT also be re-echoed to stderr by us.
    if ((err as { code?: string }).code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') {
      throw new Error(
        'unexpected argument — values are never accepted on the command line; pipe with --stdin or use the hidden prompt',
        { cause: err },
      );
    }
    throw err;
  }
  if (values.help) {
    io.out(VERB_HELP.add ?? '');
    return;
  }
  const ruleId = values.rule;
  if (ruleId === undefined || ruleId === '') {
    throw new Error('--rule <ruleId> is required (e.g. secrets/aws-access-key)');
  }
  ensurePacks();
  const rule = getLoadedRules().find((r) => r.id === ruleId);
  if (!rule) {
    const known = getLoadedRules()
      .map((r) => r.id)
      .join(', ');
    throw new Error(`unknown rule '${ruleId}' — known rules: ${known}`);
  }

  const dir = dataDir(homeBase(values.home));
  const grant = await fingerprintForRule(ruleId, values.stdin === true, dir, io);
  const { scope, reason } = await resolveScopeAndReason(values, io);
  if (scope.scope === 'permanent') {
    await confirmPermanent(io, grant.maskedValue, values.yes === true);
  }

  const db = openLocalDatabase(dir);
  try {
    const granted = await createGrant(db, {
      ruleId,
      category: rule.category,
      ...grant,
      ...scope,
      justification: reason,
      conditions: null,
      createdBy: resolveCreatedBy(),
      createdVia: 'cli-add',
    });
    printGranted(io, granted);
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// list / show
// ---------------------------------------------------------------------------

async function runList(argv: string[], io: Prompter): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, all: { type: 'boolean' }, help: { type: 'boolean', short: 'h' } },
  });
  if (values.help) {
    io.out(VERB_HELP.list ?? '');
    return;
  }
  const includeTerminal = values.all === true;
  const db = openLocalDatabase(dataDir(homeBase(values.home)));
  try {
    const exceptions = await db.exceptions.list({ includeTerminal });
    if (exceptions.length === 0) {
      if (includeTerminal) {
        io.out('No exceptions recorded.\n');
        return;
      }
      // An empty ACTIVE list with retained terminal rows reads like data loss
      // ("where did my exception go?") — say where they went.
      const terminal = (await db.exceptions.list({ includeTerminal: true })).length;
      io.out(
        terminal > 0
          ? `No active exceptions (${String(terminal)} consumed/expired/revoked — 'aka exception list --all' to view).\nJust got blocked? Run 'aka exception approve'.\n`
          : `No active exceptions. Just got blocked? Run 'aka exception approve'.\n`,
      );
      return;
    }
    const headers = ['ID', 'RULE', 'VALUE', 'SCOPE', 'EXPIRES', 'USES', 'CREATED BY'];
    if (includeTerminal) headers.push('STATE');
    const rows = exceptions.map((ex) => {
      const state = stateOf(ex);
      const row = [
        shortId(ex.id),
        ex.ruleId,
        ex.maskedValue,
        ex.scope,
        // An expiry countdown is meaningless once the budget/revocation ended
        // the grant ("consumed · expires in 24m" reads as a contradiction);
        // 'expired' keeps its timestamp — when it lapsed IS the information.
        state === 'consumed' || state === 'revoked' ? '—' : formatRelative(ex.expiresAt),
        ex.maxUses !== null ? `${String(ex.useCount)}/${String(ex.maxUses)}` : String(ex.useCount),
        ex.createdBy,
      ];
      if (includeTerminal) row.push(state);
      return row;
    });
    io.out(renderTable(headers, rows));
  } finally {
    db.close();
  }
}

// Prefix lookup shared by show/revoke; maps the repository's tagged errors to
// user-facing messages.
async function findByPrefix(db: LocalDatabase, prefix: string): Promise<DetectionException> {
  let found: DetectionException | undefined;
  try {
    found = await db.exceptions.getByIdPrefix(prefix);
  } catch (err) {
    if ((err as { code?: string }).code === 'ambiguous-exception-id') {
      throw new Error('ambiguous id, be more specific', { cause: err });
    }
    throw err;
  }
  if (!found) {
    throw new Error(`no exception matches '${prefix}' — see 'aka exception list --all'`);
  }
  return found;
}

async function runShow(argv: string[], io: Prompter): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, help: { type: 'boolean', short: 'h' } },
    allowPositionals: true,
  });
  if (values.help) {
    io.out(VERB_HELP.show ?? '');
    return;
  }
  const prefix = positionals[0];
  if (prefix === undefined) throw new Error('usage: aka exception show <id>');
  const db = openLocalDatabase(dataDir(homeBase(values.home)));
  try {
    const ex = await findByPrefix(db, prefix);
    // Severity is derivable when the rule is in the loaded packs; the stored
    // category is the fallback for rules this build does not carry.
    ensurePacks();
    const rule = getLoadedRules().find((r) => r.id === ex.ruleId);
    const ruleLine = rule
      ? `${ex.ruleId} (${ex.category} · ${rule.severity})`
      : `${ex.ruleId} (${ex.category})`;
    const fp = `${ex.valueFingerprint.slice(0, 4)}…${ex.valueFingerprint.slice(-4)}`;
    const label = (name: string): string => `  ${name.padEnd(10)}`;
    const lines = [
      `${label('Rule')}${ruleLine}`,
      `${label('Value')}${ex.maskedValue}   fingerprint ${fp} (key v${String(ex.keyVersion)})`,
      `${label('Scope')}${scopeSummary(ex)}${ex.maxUses !== null ? ` · max ${String(ex.maxUses)} use${ex.maxUses === 1 ? '' : 's'}` : ''}`,
      `${label('Reason')}"${ex.justification}"`,
      `${label('Created')}${formatTimestamp(ex.createdAt)} by ${ex.createdBy} via ${viaLabel(ex.createdVia)}`,
      `${label('Used')}${
        ex.useCount === 0
          ? 'never'
          : `${String(ex.useCount)} time${ex.useCount === 1 ? '' : 's'}${ex.lastUsedAt !== null ? ` · last ${formatTimestamp(ex.lastUsedAt)}` : ''}`
      }`,
    ];
    if (ex.revokedAt !== null) {
      lines.push(
        `${label('Revoked')}${formatTimestamp(ex.revokedAt)} by ${ex.revokedBy ?? 'unknown'}${ex.revokeReason !== null && ex.revokeReason !== '' ? ` — "${ex.revokeReason}"` : ''}`,
      );
    }
    io.out(`${lines.join('\n')}\n`);
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// revoke / rotate-key
// ---------------------------------------------------------------------------

async function runRevoke(argv: string[], io: Prompter): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      ...HOME_OPTION,
      reason: { type: 'string' },
      yes: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });
  if (values.help) {
    io.out(VERB_HELP.revoke ?? '');
    return;
  }
  const prefix = positionals[0];
  if (prefix === undefined) throw new Error('usage: aka exception revoke <id> [--reason "<why>"]');
  const db = openLocalDatabase(dataDir(homeBase(values.home)));
  try {
    const ex = await findByPrefix(db, prefix);
    if (ex.revokedAt !== null) {
      throw new Error(
        `exception ${shortId(ex.id)} is already revoked (${formatTimestamp(ex.revokedAt)})`,
      );
    }
    io.out(`Revoking ${shortId(ex.id)}  ${ex.ruleId}  ${ex.maskedValue}  ${scopeSummary(ex)}\n`);
    if (values.yes !== true) {
      if (!io.isInteractive) {
        throw new Error('pass --yes to revoke non-interactively');
      }
      const answer = await io.ask('Revoke this exception? [y/N]: ');
      if (!/^y(es)?$/i.test(answer.trim())) {
        io.out('Aborted — nothing revoked.\n');
        return;
      }
    }
    const revoked = await db.exceptions.revoke(ex.id, resolveCreatedBy(), values.reason);
    if (!revoked) {
      throw new Error(`exception ${shortId(ex.id)} is already revoked`);
    }
    io.out(`Revoked ${shortId(ex.id)} — ${ex.ruleId} ${ex.maskedValue} no longer applies.\n`);
  } finally {
    db.close();
  }
}

async function runRotateKey(argv: string[], io: Prompter): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, yes: { type: 'boolean' }, help: { type: 'boolean', short: 'h' } },
  });
  if (values.help) {
    io.out(VERB_HELP['rotate-key'] ?? '');
    return;
  }
  const dir = dataDir(homeBase(values.home));
  const db = openLocalDatabase(dir);
  try {
    io.out(
      `Rotating the fingerprint key invalidates EVERY existing exception grant:\nfingerprints cannot be re-keyed (raw values are never stored), so grants\nwritten under the old key simply stop matching. They remain listed for audit.\n`,
    );
    const permanents = (await db.exceptions.list()).filter((ex) => ex.scope === 'permanent');
    if (permanents.length > 0) {
      io.out('Active PERMANENT exceptions that will stop matching (re-approve deliberately):\n');
      for (const ex of permanents) {
        io.out(`  ${shortId(ex.id)}  ${ex.ruleId}  ${ex.maskedValue}\n`);
      }
    }
    if (values.yes !== true) {
      if (!io.isInteractive) {
        throw new Error('pass --yes to rotate non-interactively');
      }
      const answer = await io.ask('Rotate the key now? [y/N]: ');
      if (!/^y(es)?$/i.test(answer.trim())) {
        io.out('Aborted — key unchanged.\n');
        return;
      }
    }
    let version: number;
    try {
      version = rotateFingerprintKey(dir).version;
    } catch (err) {
      // A corrupt key file must not print a stack trace — surface the reason
      // with a way forward. (Grants under a corrupt key already cannot match.)
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        `cannot rotate: ${message}\nDelete ${dir}/exception.key to start fresh — grants written under it already cannot match.`,
        { cause: err },
      );
    }
    io.out(
      `Fingerprint key rotated — new key version v${String(version)}.\nExisting grants no longer match; re-approve deliberately where still needed.\n`,
    );
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

const VERBS: Record<string, (argv: string[], io: Prompter) => Promise<void>> = {
  approve: runApprove,
  add: runAdd,
  list: runList,
  show: runShow,
  revoke: runRevoke,
  'rotate-key': runRotateKey,
};

/**
 * `aka exception <verb>` — manage detection exceptions (explicit, audited
 * bypasses of a block/redact for one specific detected value). The io seam is
 * injectable so tests script prompts; the default talks to the terminal.
 * Bare/unknown verbs print the task-oriented help rather than an error.
 */
export async function runException(
  argv: string[],
  io: Prompter = terminalPrompter(),
): Promise<void> {
  const [verb, ...rest] = argv;
  if (verb === undefined || verb === '-h' || verb === '--help') {
    io.out(EXCEPTION_HELP);
    return;
  }
  const handler = VERBS[verb];
  if (!handler) {
    io.out(EXCEPTION_HELP);
    return;
  }
  await handler(rest, io);
}
