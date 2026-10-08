import { existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import {
  addAttachmentScopeEntries,
  applyOnboarding,
  canonicalRepoUrl,
  dataDir as dataDirOf,
  DB_FILENAME,
  enrollableRepoKey,
  managedConnectionHold,
  managedScopedRefusal,
  overlayManagedSettings,
  readControlPlaneCredentialFile,
  readEffectiveSettings,
  readManagedSettings,
  removeAttachmentScopeEntries,
  seedEnrolledCapturesOwed,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import { attachmentScopeLines, printableForTerminal } from '@akasecurity/plugin-runtime';
import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type {
  ControlPlaneConnection,
  CredentialUnusableReason,
  ManagedSettings,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH,
  attachmentModeOf,
  AttachmentScopeEntry,
  controlPlaneName,
  isAttached,
  isHistorySyncConsentValid,
  parseAttachmentScope,
} from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';
import { refusalLine } from '../lib/refusal-line.ts';

// `aka enroll` / `aka unenroll` / `aka enroll --list` — which repositories a
// SCOPED attachment sends.
//
// LOCAL ONLY. These verbs edit this machine's settings and contact nothing: no
// deployment is asked and nothing is sent by the command itself. What they
// change is the record later sends decide by. A session or a scan you start
// after the edit reads the new record, so from then on an enrollment applies to
// it and an unenrollment keeps the repository out of it. Work already under way,
// such as a scan that is running or a background sync that was already started,
// may have read the record before the edit, and nothing here says otherwise.
//
// THE RECORD IS EDITED RAW. The stored `attachmentScope` may hold entries or
// envelope keys a newer build wrote. The edits append to, or take out of, the
// stored `entries` array and keep everything else; they never write back a
// parsed copy, which would drop what this build cannot read.
//
// BOUND TO THE ENDPOINT IN FORCE. The record names the deployment it is for, and
// that is the EFFECTIVE endpoint, with any administrator's overlay applied: the
// one every forward path reads. The settings writer hands its updater the user's
// own file, so the updater re-derives the endpoint in force from that file and
// writes nothing when it no longer matches the endpoint checked beforehand.

// Printed on every usage error, including on a machine where an administrator
// governs the connection and a scoped attach is refused. It therefore names no
// command that attaches.
const ENROLL_USAGE = `Usage: aka enroll [path]
       aka enroll --repo <clone-url | host/owner/repo>
       aka enroll --list

On a machine attached in the scoped mode, activity is sent to the deployment
only from the repositories enrolled here; activity anywhere else stays on this
machine. The policy pull and the device report are not limited to them: the
report's finding counts and dates are for everything recorded on the machine.

  [path]         Enroll the repository this directory is in (default: .).
  --repo <repo>  Enroll by clone URL, or by key, as in github.com/acme/payments-api.
  --list         Show what is enrolled.
  --home <dir>   Use an alternate AKA home instead of ~/.aka.

Enrolling changes this machine's settings and contacts nothing.`;

const UNENROLL_USAGE = `Usage: aka unenroll [path]
       aka unenroll --repo <clone-url | host/owner/repo>

Stops sending a repository from a scoped attachment: sessions and scans you
start afterwards keep its activity on this machine.

  [path]         The repository this directory is in (default: .).
  --repo <repo>  A clone URL, or a key, as in github.com/acme/payments-api.
  --home <dir>   Use an alternate AKA home instead of ~/.aka.

Unenrolling changes this machine's settings and contacts nothing.`;

const USAGE: Record<Verb, string> = { enroll: ENROLL_USAGE, unenroll: UNENROLL_USAGE };

/** What the enrollment verbs read from outside, injectable so tests drive them. */
export interface EnrollDeps {
  /** The AKA home. Defaults to `--home`, else ~/.aka. */
  base: string;
  prompter: Prompter;
  /**
   * The administrative overlay. `null` means unmanaged; leaving it out reads the
   * real system paths.
   */
  managedSettings: ManagedSettings | null;
  /** Records a failing exit code. Defaults to setting `process.exitCode`. */
  exit: (code: number) => void;
  /** What a relative path is resolved against. Defaults to this process's working directory. */
  cwd: () => string;
  /** The enrollment time. */
  now: () => Date;
}

type Verb = 'enroll' | 'unenroll';

/**
 * Add the repository `[path]` is in (default: the working directory), or the
 * one `--repo` names, to this machine's scope; or, with `--list`, show the scope.
 *
 * Resolves to the exit code — 0, 1 for a refusal or a failed write, 2 for a
 * usage error — and hands a non-zero one to `deps.exit` as well. Asynchronous
 * in signature only, like the other entries `main()` awaits.
 */
export function runEnroll(
  argv: readonly string[],
  deps: Partial<EnrollDeps> = {},
): Promise<number> {
  return new Promise<number>((settle) => {
    settle(enroll(argv, deps));
  });
}

/** Take a repository out of this machine's scope. Same contract as `runEnroll`. */
export function runUnenroll(
  argv: readonly string[],
  deps: Partial<EnrollDeps> = {},
): Promise<number> {
  return new Promise<number>((settle) => {
    settle(unenroll(argv, deps));
  });
}

function enroll(argv: readonly string[], deps: Partial<EnrollDeps>): number {
  const ready = preflight('enroll', argv, deps);
  if (typeof ready === 'number') return ready;
  const { io, fail, base, managed, connection, name } = ready;
  if (ready.args.list) {
    const lines = attachmentScopeLines(ready.settings.attachmentScope, connection.endpoint);
    io.out(`Enrolled with ${name}:\n${lines.join('\n')}\n`);
    return 0;
  }
  const identity = namedRepository('enroll', ready);
  if (typeof identity === 'number') return identity;
  // Checked here, before the settings lock is taken: the raw edit throws for an
  // entry the store would not read back, and a throw from inside the lock would
  // be reported as a failed write rather than as what was wrong with the entry.
  const entry = enrollmentOf(identity, (deps.now ?? (() => new Date()))());
  if (entry === undefined) {
    io.err(
      'aka enroll: could not record that repository (its key or the date was not valid),\n' +
        'so nothing was enrolled.\n',
    );
    return fail(1);
  }
  // Echoed BEFORE the write, through the strip `aka status` uses, so what is
  // about to be enrolled is on screen whatever happens next.
  io.out(`Enrolling ${shown(identity)} with ${name}.\n`);
  const edit = editScope(base, managed, connection.endpoint, (raw) => {
    const { next, added } = addAttachmentScopeEntries(raw, connection.endpoint, [entry]);
    return { next, changed: added };
  });
  if (edit.kind !== 'saved') {
    io.err(EDIT_FAILURES[edit.kind]('enrolled'));
    return fail(1);
  }
  if (edit.changed.length === 0) {
    io.out(`Already enrolled with ${name}; nothing changed.\n`);
    return 0;
  }
  io.out(`Enrolled. Activity in this repository is sent to ${name} from now on.\n`);
  const record = parseAttachmentScope(edit.committed.attachmentScope);
  if (record !== undefined && (!named(record.tenantName) || !named(record.userEmail))) {
    io.out(
      "Note: this machine's enrollment list is not tied to the account it attached as, so the\n" +
        'next `aka attach` starts it empty and the repositories would be enrolled again.\n',
    );
  }
  io.out(earlierActivity(base, edit.committed, edit.changed));
  return 0;
}

function unenroll(argv: readonly string[], deps: Partial<EnrollDeps>): number {
  const ready = preflight('unenroll', argv, deps);
  if (typeof ready === 'number') return ready;
  const { io, fail, base, managed, connection, name } = ready;
  const identity = namedRepository('unenroll', ready);
  if (typeof identity === 'number') return identity;
  const edit = editScope(base, managed, connection.endpoint, (raw) => {
    const { next, removed } = removeAttachmentScopeEntries(
      raw,
      connection.endpoint,
      identity.matches,
    );
    return { next, changed: removed };
  });
  if (edit.kind !== 'saved') {
    io.err(EDIT_FAILURES[edit.kind]('unenrolled'));
    return fail(1);
  }
  const keyText = (key: string): string =>
    printableForTerminal(key, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  if (edit.changed.length === 0) {
    io.out(
      `${keyText(identity.key)} is not enrolled with ${name}; nothing changed.\n` +
        'Run `aka enroll --list` to see the keys enrolled.\n',
    );
    return 0;
  }
  // The keys actually removed, as stored: what `aka enroll --list` showed.
  const repository = edit.changed.map(keyText).join(', ');
  // The owed markers stay (nothing clears them) and the scoped read is what
  // keeps those rows unsent for now: enrolling the repository again, or a
  // machine-wide attach to the same deployment, makes them sendable. Said here
  // so an unenroll is not mistaken for erasing anything, or for a promise that
  // they stay unsent. Nothing is promised about work already under way (a scan
  // that is running, a background sync that was already started) either.
  io.out(
    `Unenrolled ${repository}. From now on, sessions and scans you start do not send its activity to ${name}.\n` +
      'Anything from it that was waiting to be sent stays unsent while it is not enrolled;\n' +
      'enrolling it again, or attaching this machine machine-wide to the same deployment,\n' +
      'makes it sendable again.\n',
  );
  return 0;
}

/** What both verbs establish before they touch the scope record. */
interface Prepared {
  io: Prompter;
  fail: (code: number) => number;
  args: EnrollArgs;
  base: string;
  managed: ManagedSettings | null;
  connection: ControlPlaneConnection;
  settings: WorkspaceSettings;
  /** The deployment's name, stripped for the terminal. */
  name: string;
  /** What a relative path is resolved against; read only when a path is named. */
  cwd: () => string;
}

/**
 * The steps the two verbs share, in one place so they cannot drift: read the
 * arguments, find the home and the administrator's overlay once, and require a
 * usable scoped attachment. Resolves to the exit code when it has already said
 * why the command cannot go on (a usage error, or a machine that cannot enroll).
 */
function preflight(
  verb: Verb,
  argv: readonly string[],
  deps: Partial<EnrollDeps>,
): Prepared | number {
  const io = deps.prompter ?? terminalPrompter();
  const fail = failingWith(deps.exit);
  const args = parseEnrollArgs(verb, argv);
  if ('error' in args) {
    io.err(`${args.error}\n\n${USAGE[verb]}\n`);
    return fail(2);
  }
  const base = deps.base ?? homeBase(args.home);
  const managed = deps.managedSettings === undefined ? readManagedSettings() : deps.managedSettings;
  const target = scopedAttachment(verb, base, managed);
  if (target.kind === 'refused') {
    io.err(`${target.line}\n`);
    return fail(1);
  }
  const { connection, settings } = target;
  return {
    io,
    fail,
    args,
    base,
    managed,
    connection,
    settings,
    name: printableForTerminal(controlPlaneName(connection)),
    cwd: deps.cwd ?? (() => process.cwd()),
  };
}

/** The repository the command names, or the exit code after saying why it names none. */
function namedRepository(verb: Verb, ready: Prepared): RepoIdentity | number {
  const identity = identityOf(verb, ready.args, ready.cwd());
  if (identity.kind === 'refused') {
    ready.io.err(`${identity.line}\n`);
    return ready.fail(1);
  }
  return identity;
}

/** A non-zero exit, recorded and returned. The default records it on the process. */
function failingWith(exit: ((code: number) => void) | undefined): (code: number) => number {
  const record =
    exit ??
    ((code: number) => {
      process.exitCode = code;
    });
  return (code) => {
    record(code);
    return code;
  };
}

interface EnrollArgs {
  home?: string | undefined;
  repo?: string | undefined;
  path?: string | undefined;
  list: boolean;
}

function parseEnrollArgs(verb: Verb, argv: readonly string[]): EnrollArgs | { error: string } {
  let values: { home?: string | undefined; repo?: string | undefined; list?: boolean | undefined };
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: [...argv],
      options: { ...HOME_OPTION, repo: { type: 'string' }, list: { type: 'boolean' } },
      allowPositionals: true,
    }));
  } catch {
    return { error: `aka ${verb} does not take those arguments.` };
  }
  if (verb === 'unenroll' && values.list !== undefined) {
    return { error: 'aka unenroll takes no --list.' };
  }
  if (positionals.length > 1) return { error: `aka ${verb} takes one path.` };
  const [path] = positionals;
  if (values.repo !== undefined && path !== undefined) {
    return { error: `aka ${verb} takes a path or --repo, not both.` };
  }
  if (values.repo?.trim() === '') {
    return { error: '--repo needs a clone URL or a key, as in github.com/acme/payments-api.' };
  }
  if (values.list === true && (values.repo !== undefined || path !== undefined)) {
    return { error: 'aka enroll --list takes no repository.' };
  }
  return { home: values.home, repo: values.repo, path, list: values.list === true };
}

/**
 * Why a stored credential cannot be used, in a few words. An exhaustive Record,
 * so a reason the reader learns later fails typecheck here rather than printing
 * a line with a hole in it.
 */
const CREDENTIAL_REASONS: Record<CredentialUnusableReason, string> = {
  absent: 'there is none',
  'untrusted-file': 'the file is not one this machine trusts',
  unreadable: 'it cannot be read',
  malformed: 'this version cannot read it',
  'unsafe-endpoint': 'it names an address a key must not be sent to',
  'endpoint-mismatch': 'it is for another deployment',
};

type Target =
  | { kind: 'scoped'; connection: ControlPlaneConnection; settings: WorkspaceSettings }
  | { kind: 'refused'; line: string };

/**
 * The command that attaches this machine to `endpoint` as a personal device, as
 * it can be pasted, or the form of it when it cannot be.
 *
 * The command is built from the whole endpoint, quoted for a shell, so it runs
 * as shown. An endpoint with control characters in it cannot be typed back as
 * it would have to be shown, so it gets the form with a placeholder instead of
 * a command that would not do what it says.
 */
function reattachCommand(endpoint: string): string {
  const typable = printableForTerminal(endpoint, Infinity) === endpoint;
  return `\`aka attach --url ${typable ? quotedForShell(endpoint) : '<url>'} --scoped\``;
}

/**
 * The attachment an enrollment edits, or why there is none.
 *
 * Read with the administrator's overlay applied: the endpoint in force is the
 * one every forward path reads, so it is the one the record must name. The
 * credential is read for that endpoint and must be a usable SCOPED one. A
 * machine-wide attachment sends activity from anywhere on the machine whatever
 * is enrolled, so an enrollment there would be a promise the forward paths do
 * not keep.
 */
function scopedAttachment(verb: Verb, base: string, managed: ManagedSettings | null): Target {
  // Asked once, before any refusal is worded. An administrator who governs the
  // connection keeps the machine machine-wide and `aka attach --scoped` is
  // refused there, so where this is non-null no line below names that command:
  // each prints the sentence that refusal prints instead.
  const governed = managedScopedRefusal(base, managed);
  const { settings } = readEffectiveSettings(base, managed);
  if (!isAttached(settings) || settings.controlPlane === undefined) {
    // A machine HELD standalone cannot be attached at all, so it is not told it
    // "attaches machine-wide": the hold's own sentence, the one `aka attach`
    // prints there, says why.
    const hold = governed === null ? null : managedConnectionHold(base, managed);
    return {
      kind: 'refused',
      line:
        `aka ${verb}: this machine is not attached to a deployment, so nothing is enrolled.\n` +
        (governed === null
          ? 'Attach it first: `aka attach --url <url> --scoped`.'
          : refusalLine(hold?.reason === 'held-standalone' ? hold : governed)),
    };
  }
  const connection = settings.controlPlane;
  const name = printableForTerminal(controlPlaneName(connection));
  const reattach = reattachCommand(connection.endpoint);
  const read = readControlPlaneCredentialFile(settingsDirOf(base), connection);
  if (!read.usable) {
    return {
      kind: 'refused',
      line:
        `aka ${verb}: the stored credential for ${name} cannot be used ` +
        `(${CREDENTIAL_REASONS[read.reason]}).\n` +
        (governed === null
          ? `Re-attach with ${reattach}, then ${verb} again.`
          : refusalLine(governed)),
    };
  }
  if (attachmentModeOf(read.credential) !== 'scoped') {
    return {
      kind: 'refused',
      line:
        `aka ${verb}: this machine is attached to ${name} machine-wide, so activity from\n` +
        'anywhere on this machine is sent and nothing is enrolled. ' +
        (governed === null
          ? `To send activity only from the repositories you enroll, re-attach with\n${reattach}.`
          : refusalLine(governed)),
    };
  }
  return { kind: 'scoped', connection, settings };
}

/**
 * The repository a command names. `key` is what it echoes; `matches` is every
 * stored identity it stands for, compared byte for byte (one key, except for
 * `aka unenroll --repo`).
 */
interface RepoIdentity {
  kind: 'repo';
  key: string;
  label: string | undefined;
  matches: readonly string[];
}
type Identity = RepoIdentity | { kind: 'refused'; line: string };

function identityOf(verb: Verb, args: EnrollArgs, cwd: string): Identity {
  if (args.repo === undefined) return identityFromPath(verb, args.path, cwd);
  return verb === 'unenroll' ? storedIdentity(args.repo) : identityFromInput(args.repo, cwd);
}

/**
 * What `aka unenroll --repo` removes: the STORED identity the input spells, byte
 * for byte, never a key enrollableRepoKey would accept. `[path]` stores the key
 * the checkout's attribution produced without re-judging it, and that may be one
 * the validator refuses (a single-segment `host:repo.git` remote keys as
 * `host/repo`), or one a newer build stored under another rule. Routed through
 * the validator, such an entry could be removed only from inside its checkout,
 * or by detaching. A clone URL also matches the key it canonicalises to.
 */
function storedIdentity(input: string): Identity {
  const typed = input.trim();
  const canonical = canonicalRepoUrl(typed);
  return {
    kind: 'repo',
    key: typed,
    label: undefined,
    matches: canonical === undefined || canonical === typed ? [typed] : [typed, canonical],
  };
}

/**
 * The key of the repository a directory is in.
 *
 * Made ABSOLUTE first: the attribution keys only an absolute directory, since a
 * relative one would resolve against this process's working directory rather
 * than the one the user meant. Read uncached, because this is a one-shot command
 * and the answer should be what is on disk now. A linked worktree keys as its
 * main checkout and a submodule by its own remote, the keys sessions in them
 * stamp. A repository with no remote on a code host has no key another machine
 * could share, so it cannot be enrolled.
 */
function identityFromPath(verb: Verb, path: string | undefined, cwd: string): Identity {
  const dir = resolve(cwd, path ?? '.');
  const attribution = resolveRepoAttribution(dir, { cache: false });
  const where = printableForTerminal(dir, 200);
  if (attribution.repo === undefined) {
    return { kind: 'refused', line: `aka ${verb}: ${where} is not inside a git repository.` };
  }
  if (attribution.scopeKey === undefined) {
    return {
      kind: 'refused',
      line:
        verb === 'enroll'
          ? `aka enroll: the repository at ${where} has no remote on a code host, so it has no key\n` +
            'another machine shares, and it cannot be enrolled.'
          : `aka unenroll: the repository at ${where} has no remote on a code host, so it has no\n` +
            'key to remove. Give the key with `aka unenroll --repo <key>`; `aka enroll --list` shows them.',
    };
  }
  return {
    kind: 'repo',
    key: attribution.scopeKey,
    label: defaultLabel(attribution.repo),
    matches: [attribution.scopeKey],
  };
}

/** Whether `path` names a directory that exists. */
function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** Characters that need no quoting in a shell word. */
const SHELL_SAFE = /^[\w@%+=:,./-]+$/;

/**
 * `text` as one shell word, quoted unless every character in it is plain. POSIX
 * shells take single quotes (a quote inside is closed, escaped and reopened);
 * Windows shells take double quotes, which a Windows path cannot itself contain.
 */
export function quotedForShell(text: string, platform: NodeJS.Platform = process.platform): string {
  if (SHELL_SAFE.test(text)) return text;
  return platform === 'win32' ? `"${text}"` : `'${text.replaceAll("'", `'\\''`)}'`;
}

/**
 * The refusal for `--repo` text that names a directory which is not the
 * checkout of the repository it spells.
 *
 * The command it suggests is built from the whole text, quoted for a shell, so
 * it can be pasted as it stands. A name with control characters cannot be typed
 * back as it would have to be shown, so it gets no command, only the form.
 */
function directoryRefusal(typed: string): string {
  const where = printableForTerminal(typed, 200);
  const typable = printableForTerminal(typed, Infinity) === typed;
  return (
    `aka enroll: ${where} is a directory on this machine, not a repository key.\n` +
    (typable
      ? `To enroll the repository it is in, pass it as a path: \`aka enroll ${quotedForShell(typed)}\`.`
      : 'To enroll the repository it is in, pass the directory as a path instead of --repo.')
  );
}

/**
 * The key a typed clone URL or key names, for `aka enroll --repo`.
 *
 * Text that names a directory here is refused unless that directory is the
 * checkout of the very repository the text spells (a tree laid out by host,
 * owner and repository). A relative path such as `src/acme/payments-api` reads
 * as a key whose host has no dot, and enrollableRepoKey cannot tell the two
 * apart, so it would be stored as a repository that matches nothing. The
 * directory is the repository to enroll, and `[path]` is the form that reads one.
 *
 * A refused input that has no `:` was typed as a key. Keys are compared byte for
 * byte, so a near miss is not corrected silently; when the input re-spelled as
 * a key is one that could be enrolled, the refusal names that spelling instead.
 */
function identityFromInput(input: string, cwd: string): Identity {
  const typed = input.trim();
  const directory = resolve(cwd, typed);
  const accepted = enrollableRepoKey(typed);
  if (
    isDirectory(directory) &&
    (accepted === undefined ||
      resolveRepoAttribution(directory, { cache: false }).scopeKey !== accepted)
  ) {
    return { kind: 'refused', line: directoryRefusal(typed) };
  }
  if (accepted !== undefined) {
    return {
      kind: 'repo',
      key: accepted,
      label: defaultLabel(accepted.slice(accepted.lastIndexOf('/') + 1)),
      matches: [accepted],
    };
  }
  const shownInput = printableForTerminal(typed, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  const respelled = typed.includes(':') ? undefined : canonicalRepoUrl(`https://${typed}`);
  if (
    respelled !== undefined &&
    respelled !== typed &&
    enrollableRepoKey(respelled) === respelled
  ) {
    const canonical = printableForTerminal(respelled, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
    return {
      kind: 'refused',
      line: `aka enroll: ${shownInput} is not how that repository is keyed; its key is ${canonical}.`,
    };
  }
  return {
    kind: 'refused',
    line:
      `aka enroll: ${shownInput} does not name a repository that can be enrolled. Give its clone\n` +
      'URL, or its key, as in github.com/acme/payments-api.',
  };
}

/**
 * The bound `AttachmentScopeEntry.label` carries (`printable(80)`), used only to
 * cut a slug to fit. The schema itself still decides: if its bound ever drops
 * below this, a cut label fails the check below and is omitted rather than
 * stored.
 */
const LABEL_MAX_LENGTH = 80;

/**
 * The label an enrollment gets when the user names none: the repository's slug,
 * cut by whole characters to the longest prefix the label bound allows, and
 * kept only when the schema's label rule accepts it.
 */
export function defaultLabel(slug: string | undefined): string | undefined {
  if (slug === undefined) return undefined;
  let label = '';
  for (const character of slug) {
    if (label.length + character.length > LABEL_MAX_LENGTH) break;
    label += character;
  }
  return label !== '' && AttachmentScopeEntry.shape.label.safeParse(label).success
    ? label
    : undefined;
}

/**
 * The entry an enrollment stores, as the schema reads it back, or `undefined`
 * when the schema would drop it (a key or label it refuses, or a time that is
 * not a date). `Date.prototype.toISOString` throws for an invalid date, so that
 * case is handed to the schema as an empty time instead.
 */
function enrollmentOf(
  identity: { key: string; label: string | undefined },
  when: Date,
): AttachmentScopeEntry | undefined {
  const parsed = AttachmentScopeEntry.safeParse({
    kind: 'repo',
    identity: identity.key,
    ...(identity.label === undefined ? {} : { label: identity.label }),
    enrolledAt: Number.isNaN(when.getTime()) ? '' : when.toISOString(),
  });
  return parsed.success ? parsed.data : undefined;
}

function shown(identity: { key: string; label: string | undefined }): string {
  const text = printableForTerminal(identity.key, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  return identity.label === undefined ? text : `${text} (${printableForTerminal(identity.label)})`;
}

/** A binding field that names someone: present and not empty. */
function named(value: string | undefined): boolean {
  return value !== undefined && value !== '';
}

/** Thrown inside the settings lock when the endpoint in force moved; nothing is written. */
class AttachmentMoved extends Error {}

type ScopeEdit =
  | { kind: 'saved'; changed: readonly string[]; committed: WorkspaceSettings }
  | { kind: 'moved' }
  | { kind: 'failed' };

const EDIT_FAILURES: Record<'moved' | 'failed', (done: string) => string> = {
  moved: (done) =>
    "This machine's attachment changed while that was being saved, so nothing was " +
    `${done}.\nRun the command again.\n`,
  failed: (done) =>
    `Could not save that, so nothing was ${done}. If another program is changing AKA's\n` +
    'settings right now, run the command again.\n',
};

/**
 * One raw edit of the stored scope record, inside the settings lock.
 *
 * The updater is handed the user's OWN file, not the settings in force, so the
 * endpoint the record is bound to is re-derived there with the overlay the
 * pre-flight read applied. If it no longer matches the endpoint checked before
 * the write (a re-attach elsewhere landed in between), the updater throws and
 * nothing is written: the record must not be rebound to a deployment the
 * credential check never saw.
 *
 * The credential is read again there too, and must still be usable and scoped:
 * a machine-wide re-attach to the same endpoint changes nothing the endpoint
 * check can see.
 *
 * Returns the identities the edit changed and the settings as written, overlay
 * applied, or why nothing was written. Never throws.
 */
function editScope(
  base: string,
  managed: ManagedSettings | null,
  endpoint: string,
  change: (raw: unknown) => { next: unknown; changed: readonly string[] },
): ScopeEdit {
  let changed: readonly string[] = [];
  try {
    const written = applyOnboarding(
      (current) => {
        const inForce = overlayManagedSettings(current, managed).controlPlane;
        if (inForce?.endpoint !== endpoint) throw new AttachmentMoved();
        // The same endpoint can have been re-attached machine-wide since the
        // check, and a scope record must never be written onto that credential.
        const read = readControlPlaneCredentialFile(settingsDirOf(base), inForce);
        if (!read.usable || attachmentModeOf(read.credential) !== 'scoped') {
          throw new AttachmentMoved();
        }
        const result = change(current.attachmentScope);
        changed = result.changed;
        return result.changed.length === 0 ? {} : { attachmentScope: result.next };
      },
      base,
      managed,
    );
    return { kind: 'saved', changed, committed: overlayManagedSettings(written, managed) };
  } catch (err) {
    return { kind: err instanceof AttachmentMoved ? 'moved' : 'failed' };
  }
}

/** The line that closes every queued-captures report: what a count leaves out. */
const ALREADY_QUEUED = 'Captures already queued for it are sent as well.\n';

/** How many captures the enrollment newly queued, and that earlier ones go too. */
function queuedLines(queued: number): string {
  if (queued === 0) {
    return `No earlier captured prompts, replies or tool results from it needed queueing.\n${ALREADY_QUEUED}`;
  }
  const what =
    queued === 1
      ? 'Queued 1 earlier captured prompt, reply or tool result\nfrom it that is'
      : `Queued ${queued.toLocaleString('en-US')} earlier captured prompts, replies and tool results\nfrom it that are`;
  return `${what} still kept on this machine. ${ALREADY_QUEUED}`;
}

/**
 * What becomes of what was recorded in the repository before it was enrolled,
 * said only as far as it is true.
 *
 * Under a history-sync grant for this deployment, three things hold, and the
 * copy says all three. The captures still kept for the new keys are marked to
 * send, and the count is only those newly marked: captures already marked are
 * sent as well. The history drain re-reads the scope on every pass, bounded by
 * the instant this machine attached, so the repository's other activity from
 * before the attachment (sessions, tool calls, token usage) is sent too. What
 * it recorded between attaching and enrolling, other than those captures, was
 * judged local when it happened and stays local. Without a grant nothing
 * earlier is sent, and the line names the command that would change that.
 * What has already aged out is gone, so no line promises everything.
 *
 * The enrollment is saved when this runs. A queue that could not be written is
 * reported as not queued, never as a failed enrollment, and so is a machine
 * with no store; the two differ only in the reason given. The seed runs only
 * after the grant is checked here: marking is the first step of sending.
 */
function earlierActivity(
  base: string,
  committed: WorkspaceSettings,
  added: readonly string[],
): string {
  if (!isHistorySyncConsentValid(committed.historySyncConsent, committed.controlPlane?.endpoint)) {
    return (
      'Nothing recorded in it before now is sent. To send its earlier history as well,\n' +
      'run `aka sync-history --on`.\n'
    );
  }
  const queued = seedEnrolledCapturesOwed(dataDirOf(base), added);
  if (queued === undefined) {
    // Asked only after the seed answered: the seed itself already treats a
    // missing store as nothing to mark, and this only chooses the words.
    return existsSync(join(dataDirOf(base), DB_FILENAME))
      ? 'Earlier captures from it were not queued: the local store could not be read.\n' +
          'The enrollment itself is saved.\n'
      : 'Earlier captures from it were not queued: nothing was recorded on this machine before now.\n' +
          'The enrollment itself is saved.\n';
  }
  return (
    queuedLines(queued) +
    'The history sync also sends the rest of its activity recorded before this machine attached\n' +
    '(sessions, tool calls, token usage), in the background. Activity it recorded between\n' +
    'attaching and enrolling, other than those captures, stays on this machine.\n'
  );
}
