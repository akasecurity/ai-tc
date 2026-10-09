import { readFileSync } from 'node:fs';

import { cliVersion, installBackgroundSync, uninstallBackgroundSync } from '@akasecurity/local-ops';
import type { CredentialFileRead } from '@akasecurity/persistence';
import {
  applyOnboarding,
  captureBackfillScope,
  clearAttachmentDerivedState,
  controlPlaneCredentialPath,
  dataDir as dataDirOf,
  decideAttachMode,
  freshAttachmentScope,
  holdsScopedFor,
  managedAttachRefusal,
  managedDetachRefusal,
  ManagedFieldError,
  managedScopedRefusal,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  readEffectiveSettings,
  readLocalHistoryPreview,
  readManagedSettings,
  removeControlPlaneCredential,
  seedCaptureBacklogOwed,
  settingsDir as settingsDirOf,
  settledDecisionHolds,
  writeControlPlaneCredential,
  writeOwnerOnlyFileSync,
  writesSettingsFirst,
} from '@akasecurity/persistence';
import {
  printableForTerminal,
  readDeviceIdentity,
  renderAttachedStatus,
  renderPolicyLine,
} from '@akasecurity/plugin-runtime';
import { hostCompatibilityLines, readHostVersionCache } from '@akasecurity/plugin-sdk';
import { createAttachClient, createRemoteClient } from '@akasecurity/remote';
import type {
  AttachedCredentialAny,
  AttachmentMode,
  ConnectionRefusal,
  HistorySyncConsent,
  ManagedSettings,
  PluginWhoami,
  UnsafeEndpointReason,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  attachmentModeOf,
  HISTORY_SYNC_PAYLOAD_VERSION,
  isAttachmentScopeBoundTo,
  originOnly,
  parseAttachmentScope,
  unsafeEndpointReason,
} from '@akasecurity/schema';

import { homeBase } from '../lib/args.ts';
import { openUrl } from '../lib/open-url.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';
import { refusalLine } from '../lib/refusal-line.ts';
import { attachByDeviceCode, type DeviceAttachOutcome } from './attach-device.ts';

// `aka attach` / `aka detach` / `aka status` — registering this machine against
// an organization's deployment, and saying so afterwards.
//
// THE CREDENTIAL NEVER TOUCHES ARGV. There is no `--key` flag and adding one is
// a defect rather than a convenience: argv is world-readable through `ps` for
// the life of the process and lands in shell history besides. It arrives on a
// hidden prompt, or on stdin for an automated enrolment. An unknown flag exits
// 2 rather than being ignored, because a mistyped `--key` that was silently
// dropped would be the exact failure this rule exists to prevent.

const USAGE = `Usage: aka attach --url <https-url> [--label <name>] [--key-stdin] [--scoped | --machine]

Registers this machine against your organization's AKA deployment.

  --url <url>     Where the deployment lives. https, or http on loopback.
  --label <name>  What to call it on screen. Defaults to the URL.
  --key-stdin     Read the access key from stdin instead of prompting.
  --home <dir>    Use an alternate AKA home instead of ~/.aka.

  --scoped   A personal device: send activity only from the repositories you
             enroll with \`aka enroll\`; none is sent until you enroll one.
             Whenever a session starts anywhere on this machine, in a
             repository or not (a browser chat included), the machine pulls
             the deployment's policy (at most every 15 minutes) and sends it a
             device report (at most hourly): a device identifier, host name,
             versions, detection packs, policy counts, finding counts and
             dates for everything recorded on the machine, and, when the
             machine is attached as a personal device, the fact that it is
             one. Where a scan is available (the coding-agent plugins, not a
             browser chat), the same session start also checks it for device
             commands.
  --machine  A machine your organization owns: send activity from anywhere on
             this machine.

  With neither flag, a re-attach to the same deployment keeps the mode it has;
  otherwise a terminal is asked which, and a run with no terminal attaches
  machine-wide, or stops for one of these flags when that could widen what this
  machine sends. With a flag, the flag decides. A machine whose connection an
  administrator manages attaches machine-wide only.

  --sync-history     Also send the activity already recorded on this machine,
                     without asking.
  --no-sync-history  Do not send it, without asking.

The key is never accepted as a command-line argument — it would be visible to
every process on this machine and recorded in your shell history.`;

/** The interactive attach, injectable so tests drive it without a socket. */
export type DeviceAttachRunner = (input: {
  io: Prompter;
  endpoint: string;
  label?: string | undefined;
  base: string;
  verify: (endpoint: string, apiKey: string) => Promise<{ tenantName: string; userEmail: string }>;
}) => Promise<DeviceAttachOutcome>;

export interface AttachDeps {
  /** The browser-approval path. Replaced wholesale in tests. */
  deviceAttach?: DeviceAttachRunner;
  /** The macOS background-sync scheduler install/uninstall, injectable so
   * tests never touch a real LaunchAgent. See
   * @akasecurity/local-ops/background-schedule for what each does. */
  installBackgroundSync?: (base: string) => void;
  uninstallBackgroundSync?: (base: string) => void;
  /** The administrative overlay, injectable so a suite is not at the mercy of
   * whatever the developer's own machine is enrolled in. `null` means
   * unmanaged; omitted means read the real system paths. */
  managedSettings?: ManagedSettings | null;
  base?: string;
  prompter?: Prompter;
  /** The transport, injectable so tests verify a credential without a network. */
  verify?: (endpoint: string, apiKey: string) => Promise<{ tenantName: string; userEmail: string }>;
  exit?: (code: number) => void;
}

interface ParsedArgs {
  url?: string | undefined;
  label?: string | undefined;
  home?: string | undefined;
  keyStdin: boolean;
  /** Set only by a flag; undefined means "ask", which is what a bare attach does. */
  syncHistory?: boolean | undefined;
  /** Set only by `--scoped` / `--machine`; undefined means decide (see decideAttachMode). */
  mode?: AttachmentMode | undefined;
}

/**
 * Parse argv, refusing anything not named here.
 *
 * `--key` is called out BY NAME in the refusal rather than falling into the
 * generic unknown-flag message: someone reaching for it is trying to do the one
 * thing this command must not allow, and they need to be told where the key
 * goes instead.
 */
export function parseAttachArgs(argv: readonly string[]): ParsedArgs | { error: string } {
  const parsed: ParsedArgs = { keyStdin: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--key' || arg?.startsWith('--key=')) {
      return {
        error:
          'aka attach does not take --key: a key on the command line is visible to every ' +
          'process on this machine and is written to your shell history. Run without it to be ' +
          'prompted, or pipe the key in with --key-stdin.',
      };
    }
    if (arg === '--key-stdin') {
      parsed.keyStdin = true;
    } else if (arg === '--sync-history') {
      if (parsed.syncHistory === false) return { error: MUTUALLY_EXCLUSIVE };
      parsed.syncHistory = true;
    } else if (arg === '--no-sync-history') {
      if (parsed.syncHistory === true) return { error: MUTUALLY_EXCLUSIVE };
      parsed.syncHistory = false;
    } else if (arg === '--scoped' || arg === '--machine') {
      const mode: AttachmentMode = arg === '--scoped' ? 'scoped' : 'machine';
      if (parsed.mode !== undefined && parsed.mode !== mode) return { error: MODES_EXCLUSIVE };
      parsed.mode = mode;
    } else if (arg === '--url') {
      parsed.url = argv[++i];
    } else if (arg?.startsWith('--url=')) {
      parsed.url = arg.slice('--url='.length);
    } else if (arg === '--label') {
      parsed.label = argv[++i];
    } else if (arg?.startsWith('--label=')) {
      parsed.label = arg.slice('--label='.length);
    } else if (arg === '--home') {
      parsed.home = argv[++i];
    } else if (arg?.startsWith('--home=')) {
      parsed.home = arg.slice('--home='.length);
    } else {
      return { error: `unknown option ${printableForTerminal(String(arg), 200)}` };
    }
  }
  if (parsed.label !== undefined && CONTROL_CHARS.test(parsed.label)) {
    return {
      error:
        'aka attach does not take a --label containing control characters. The label is printed ' +
        'into `aka status`, which a user reads to decide whether their machine is managed, and an ' +
        'escape sequence there can repaint or hide lines of that block.',
    };
  }
  return parsed;
}

/**
 * Control and format characters, which have no place in a label.
 *
 * REFUSED here rather than stripped, because the person who typed it is the
 * person who can fix it — silently mangling their label would leave them
 * wondering why `aka status` disagrees with what they wrote. The renderer
 * strips instead, and that difference is deliberate: a label can also arrive
 * from an administrator's managed overlay, which the user reading the status
 * block cannot correct, so the render-time strip is the layer that has to hold
 * unconditionally. This one keeps the bad value out of `settings.json` at all,
 * which protects every other reader of that file.
 */
const CONTROL_CHARS = /[\p{Cc}\p{Cf}]/u;

const MUTUALLY_EXCLUSIVE = '--sync-history and --no-sync-history are mutually exclusive';

const MODES_EXCLUSIVE = '--scoped and --machine are mutually exclusive';

/**
 * Why a run with no terminal and no mode flag stops before any network call.
 *
 * decideAttachMode refuses for either of two causes and does not say which,
 * so the message names both: a credential file that exists but cannot be
 * read, which may be a scoped attachment a newer aka wrote, and a scoped
 * attachment this machine holds for another deployment. In either case a
 * machine-wide credential written from automation would widen what this
 * machine sends with nobody told, and whoever runs it is one flag away from
 * saying which. It echoes nothing read from disk.
 */
const NEEDS_MODE_FLAG =
  'refusing to attach without --scoped or --machine: this machine holds either a credential ' +
  'file aka cannot read, which may be a scoped attachment written by a newer aka, or a scoped ' +
  'attachment to another deployment, and attaching machine-wide without asking could widen ' +
  'what it sends. Re-run with --scoped to send activity only from the repositories you enroll, or with ' +
  '--machine to send activity from anywhere on this machine. Nothing was changed.';

/**
 * Said when the credential on disk no longer fits the mode that was settled.
 * The decision is made before a key is verified, which on the browser path can
 * take minutes, and another aka may attach, detach or re-attach this machine in
 * that time. Writing what was settled over a different state could widen a
 * personal device or overwrite a newer build's credential with nobody asked, so
 * nothing is written.
 */
const CHANGED_WHILE_WAITING =
  "this machine's attachment changed while this command waited, so it was not written over. " +
  'Nothing was changed on this machine; run the command again.';

/**
 * Said when the settled decision, put again with the administrator's answer as it
 * is after the wait, no longer holds, although it holds with the answer read
 * before it: whether an administrator manages this machine's connection changed
 * while this command waited. A machine they stopped managing is the user's to
 * decide again, so what was settled is not written. Nothing has been written when
 * this is said.
 */
const MANAGEMENT_CHANGED_WHILE_WAITING =
  "whether an administrator manages this machine's connection changed while this command " +
  'waited, so the attachment was not written. Nothing was changed on this machine; run the ' +
  'command again.';

/** What a failed save says when the earlier credential file is back exactly as it was. */
const LEFT_AS_IT_WAS = 'could not save the attachment; this machine is left as it was.';

/**
 * What an attach says when its settings landed and its credential did not (see
 * the order of the writes in runAttach): a machine-wide attach over a personal
 * device's credential, a file that cannot be used or no file with a list or a
 * grant stored, and a scoped attach that does not keep the list stored beside
 * it, over settings with a list or a grant, and not over a usable machine-wide
 * credential (which writes the credential first and never prints this).
 * The settings dropped the enrolled list, or replaced it with an empty one, and
 * carry no earlier grant. Beside that, what the machine already had sends no
 * repository's activity: a scoped credential has no repository enrolled, a file
 * that cannot be used or one for another deployment sends nothing, and with no
 * credential file there is nothing to send with. The last sentence is there
 * because the earlier scoped key for this deployment can survive the failed
 * write, and enrolling a repository under it would send that repository.
 */
const CREDENTIAL_NOT_SAVED_AFTER_SETTINGS =
  'could not save the attachment: the settings were saved but the credential was not. The ' +
  "enrolled list is cleared, and no repository's activity is sent until this machine is " +
  'attached again with `aka attach`. Run `aka attach` again before enrolling a repository.';

/**
 * What a failed save left of the credential file the machine held before.
 *
 *   `restored`  — the earlier state is back, or was never disturbed (this
 *                 attach's credential write did not land): the credential or the
 *                 raw bytes of an unparseable file written again, or no earlier
 *                 file existed and the one this attach wrote is gone.
 *   `replaced`  — the earlier file could not be read at all (a symlink, someone
 *                 else's file), so there were no bytes to put back, and this
 *                 attach's file had already replaced it. This attach's file is
 *                 removed; the earlier one is gone.
 *   `untouched` — the earlier file could not be read and this attempt never
 *                 replaced it.
 *   `superseded` — the file no longer held what this attach wrote, nor what was
 *                  there before: another attach, re-attach or detach changed it
 *                  after this attach's write. It is left as it is. Where the
 *                  earlier file could not be read, a usable credential from
 *                  another attach in its place counts as the same.
 *   `failed`    — the earlier state could not be written back.
 */
type CredentialRollback = 'restored' | 'replaced' | 'untouched' | 'superseded' | 'failed';

/**
 * What is added to a failed save's message when the earlier credential file is
 * not back as it was, one true sentence per way that can happen. A Record, so a
 * new outcome cannot be added without saying what it means.
 */
const ROLLBACK_NOTE: Record<Exclude<CredentialRollback, 'restored'>, string> = {
  replaced:
    'The credential file this machine had before could not be read, so it could not be put ' +
    'back, and it is gone. Run `aka attach` again.',
  untouched:
    'The credential file this machine had before could not be read; this attempt did not ' +
    'change it.',
  superseded:
    'The credential file changed while this attach was saving, so it was not put back and is ' +
    'left as it is now. Run `aka status` to see what this machine is attached to.',
  failed:
    'The credential file on this machine could not be put back as it was before this attempt, ' +
    'so it may differ from what it was. Run `aka attach` again.',
};

/** The one line a failed save prints, from what the rollback managed. */
function saveFailedMessage(err: unknown, rollback: CredentialRollback): string {
  const note = rollback === 'restored' ? undefined : ROLLBACK_NOTE[rollback];
  // An administrator can freeze `runMode`, and a machine they froze to
  // standalone is one this command must not talk around.
  if (err instanceof ManagedFieldError) {
    return (
      'your organization manages this setting on this machine, so it cannot be attached here.' +
      (note === undefined ? '' : ` ${note}`)
    );
  }
  return note === undefined ? LEFT_AS_IT_WAS : `could not save the attachment. ${note}`;
}

/**
 * The line an attach refused by the administrator's overlay prints, whether the
 * refusal came before the round trip or after it. Leaving --label off is refused
 * as the rename it amounts to, and the flag that keeps the name is this
 * surface's to name.
 */
function attachRefusalLine(refusal: ConnectionRefusal): string {
  return refusal.reason === 'label-required'
    ? `${refusalLine(refusal)} Attach with the --label it already has, as \`aka status\` shows it.`
    : refusalLine(refusal);
}

/**
 * The administrator's overlay, read once: an overlay handed in is returned as it
 * is, and otherwise the system's is read, a read that fails being no overlay, as
 * in every other read of it.
 *
 * For answers that must agree with one another. Each refusal function reads the
 * system overlay itself when it is handed none, so two of them asked in a row
 * can see two overlays if one lands between the reads.
 */
function overlayNow(deps: AttachDeps): ManagedSettings | null {
  const handedIn = deps.managedSettings;
  if (handedIn !== undefined) return handedIn;
  try {
    return readManagedSettings();
  } catch {
    return null;
  }
}

const isError = (v: ParsedArgs | { error: string }): v is { error: string } => 'error' in v;

/**
 * The plain-language reason `--url` was refused, rendered beneath
 * `refusing to attach to <origin>:` — never the raw endpoint, since the
 * `userinfo` case exists to keep a copy-pasted password out of this message.
 */
function unsafeEndpointMessage(reason: UnsafeEndpointReason): string {
  switch (reason) {
    case 'unparseable':
      return (
        'that does not look like a web address; include the scheme, as in ' +
        'https://aka.example.com.'
      );
    case 'userinfo':
      return (
        'the address carries a username or password; remove them, the access key ' +
        'is sent separately.'
      );
    case 'query-or-fragment':
      return (
        'the address must be an origin, optionally with a path; drop the query ' +
        'string or fragment.'
      );
    case 'insecure':
      return (
        'an access key must not travel in the clear. Use an https URL (http is ' +
        'accepted only for a loopback deployment).'
      );
  }
}

/**
 * Attach: verify the credential, then write both halves.
 *
 * VERIFIED BEFORE ANYTHING IS WRITTEN, and the URL is checked before the
 * verification — so a plaintext endpoint is refused without the key ever being
 * put on a wire. What the verification buys is the difference between "attached"
 * and "attached to something that will refuse every request from now on": a
 * typo'd URL or a revoked key is a message here rather than silence for the life
 * of the install, since every later failure is deliberately swallowed.
 */
export async function runAttach(argv: string[], deps: AttachDeps = {}): Promise<void> {
  const io = deps.prompter ?? terminalPrompter();
  const exit = deps.exit ?? ((code: number) => process.exit(code));

  const args = parseAttachArgs(argv);
  if (isError(args)) {
    io.err(`${args.error}\n\n${USAGE}`);
    exit(2);
    return;
  }
  // `--home` is a global every other command honours, and these three were
  // reading the real `~/.aka` regardless of it. On `detach` that is the sharp
  // one: `aka detach --home /tmp/scratch` would have detached the user's actual
  // machine while appearing to touch a throwaway.
  const base = deps.base ?? homeBase(args.home);
  const endpoint = args.url;
  if (endpoint === undefined || endpoint === '') {
    io.err(USAGE);
    exit(2);
    return;
  }
  const unsafeReason = unsafeEndpointReason(endpoint);
  if (unsafeReason !== null) {
    io.err(`refusing to attach to ${originOnly(endpoint)}: ${unsafeEndpointMessage(unsafeReason)}`);
    exit(2);
    return;
  }

  // THE INTERACTIVE PATH IS TRIED FIRST, and only when nobody asked for the
  // key path. `--key-stdin` is an explicit choice — an automated enrolment
  // piping a key it already holds — and probing a deployment on its behalf
  // would be a network call it did not ask for.
  //
  // A deployment that does not offer the flow answers 404 and this falls
  // through to the prompt below. That is the whole compatibility story: no
  // version handshake, and no way for the CLI to require a deployment newer
  // than the one in front of it.
  // Set by the interactive path when it succeeds, so the shared write below
  // does not ask `whoami` a second time for an identity the confirmation step
  // has already shown the user and had them accept.
  let confirmed: { apiKey: string; identity: { tenantName: string; userEmail: string } } | null =
    null;

  // AHEAD OF BOTH PATHS, not only the interactive one. The key path used to
  // skip this and let the writer decide, which under a pinned-but-unlocked
  // overlay is no decision at all: the write lands, and the next read overlays
  // the pin back over it. Both paths also reach a network before the write —
  // a grant on one, `whoami` on the other — and neither should be asked about
  // a deployment this machine was never going to keep. The decision is shared
  // with the dashboard's attach action, so the two surfaces cannot disagree.
  const refusal = managedAttachRefusal({ endpoint, label: args.label }, base, deps.managedSettings);
  if (refusal !== null) {
    io.err(attachRefusalLine(refusal));
    exit(2);
    return;
  }

  // THE MODE, DECIDED BEFORE ANY NETWORK CALL, beside the refusal above and for
  // its reason: a machine whose administrator manages its connection attaches
  // machine-wide only, and a run that cannot be told which mode to write must
  // stop before a deployment approves a device or is shown a key. The refusal
  // above comes first on purpose: it reports a machine held at standalone or
  // pinned to another deployment as that, which the decision below does not
  // know about. See decideAttachMode for the rules. The question it may call
  // for is asked after verification, below.
  //
  // The WIDE read, no connection passed: the question is what this machine holds
  // for THIS endpoint, which the decision compares by value. It is not the read
  // the rollback restores. That one stays just before the writes (`previous`
  // below), because a browser approval can wait up to fifteen minutes and a
  // rollback must put back what was on disk immediately before the write.
  //
  // GUARDED (see readCredentialGuarded): reported here, before anything is sent,
  // rather than as a crash after a device approval.
  const prior = readCredentialGuarded(base, io);
  if (prior === undefined) {
    exit(1);
    return;
  }
  const scopedRefusal = managedScopedRefusal(base, deps.managedSettings);
  const modeDecision = decideAttachMode({
    flag: args.mode,
    managed: scopedRefusal,
    previous: prior,
    endpoint,
    interactive: io.isInteractive,
  });
  if (modeDecision.kind === 'refuse') {
    io.err(
      modeDecision.why === 'scoped-managed'
        ? `${refusalLine(scopedRefusal ?? { reason: 'scoped-managed' })} ` +
            'Re-run without --scoped.'
        : NEEDS_MODE_FLAG,
    );
    exit(2);
    return;
  }

  if (!args.keyStdin) {
    const outcome = await (deps.deviceAttach ?? runDeviceAttach)({
      io,
      endpoint,
      label: args.label,
      base,
      verify: deps.verify ?? verifyWithControlPlane,
    });
    if (outcome.kind === 'declined' || outcome.kind === 'failed') {
      io.err(outcome.kind === 'failed' ? `could not attach: ${outcome.reason}` : outcome.reason);
      exit(1);
      return;
    }
    if (outcome.kind === 'attached') {
      confirmed = { apiKey: outcome.apiKey, identity: outcome.identity };
    } else {
      // 'not-offered' — fall through to the prompt, with one line so the user
      // knows why they are being asked for something the newer flow would not
      // have needed. The two wordings are not interchangeable: "does not offer"
      // is the deployment ANSWERING, while a reason means the probe never got
      // an answer, and a user debugging an unreachable control plane needs to
      // see which of those happened rather than be told a working deployment
      // lacks a feature.
      io.out(
        outcome.reason === undefined
          ? 'This deployment does not offer browser approval yet; paste an access key instead.\n'
          : `Could not start browser approval (${outcome.reason}); paste an access key instead.\n`,
      );
    }
  }

  const apiKey = (
    confirmed !== null
      ? confirmed.apiKey
      : args.keyStdin
        ? (await io.readAllStdin()).trim()
        : io.isInteractive
          ? (await io.askHidden('Access key (input hidden): ')).trim()
          : ''
  ).trim();
  if (apiKey === '') {
    io.err(
      io.isInteractive || args.keyStdin
        ? 'no access key was provided; nothing was changed.'
        : 'no terminal to prompt on. Pipe the key in with --key-stdin.',
    );
    exit(2);
    return;
  }

  let identity: { tenantName: string; userEmail: string };
  try {
    // Already proved, and already shown to the user, when the interactive path
    // produced this key — asking again would be a second round trip for an
    // answer that has been on screen since before they confirmed.
    identity =
      confirmed?.identity ?? (await (deps.verify ?? verifyWithControlPlane)(endpoint, apiKey));
  } catch {
    io.err(
      `could not verify that key against ${printableForTerminal(endpoint, 200)}. Nothing was changed — ` +
        'check the URL and that the key has not been revoked.',
    );
    exit(1);
    return;
  }

  // THE MODE, SETTLED, by the history question's rule below: asked after
  // verification, so nobody is asked about a deployment the machine turns out
  // not to join, and answered before the writes. Asked ONCE. On the browser path
  // its own confirmation has returned by now, so the two questions follow one
  // another and neither repeats the other.
  let mode: AttachmentMode;
  // What this attach says about the enrolled list it replaces, held until every
  // check that can still stop it has passed: a line promising a list will be
  // cleared must not be followed by a refusal that clears nothing.
  let listNotice: string | undefined;
  if (modeDecision.kind === 'ask') {
    const answered = await askAboutMode(io);
    if (answered === undefined) {
      io.err(
        'not attaching: no answer to whether this is a personal device. ' +
          'Nothing was changed on this machine.',
      );
      exit(1);
      return;
    }
    mode = answered;
  } else {
    mode = modeDecision.mode;
    if (modeDecision.why === 'managed') {
      // A MANAGED machine that was a personal device, attached to this
      // deployment or to another: nobody is asked, because the administrator
      // decided, and one line says why it attaches machine-wide now. `widening`
      // is never asked about here: under management it is information, never a
      // question, and it only picks which notice names the deployment. The write
      // below clears the enrolled list either way. Another deployment
      // is not named: its endpoint is read from disk, so that notice says
      // nothing of it. The administrator's name in the refusal sentence is their
      // own, and refusalLine strips it for the terminal.
      if (prior.usable && attachmentModeOf(prior.credential) === 'scoped') {
        // The decision's own answer, so another spelling of this deployment is
        // named as this one, the way the widening it is counts it.
        const notice = modeDecision.widening ? wideningNotice(endpoint) : MANAGED_ELSEWHERE_NOTICE;
        listNotice = `${refusalLine(scopedRefusal ?? { reason: 'scoped-managed' })} ${notice}\n`;
      }
    } else if (modeDecision.widening) {
      // WIDENING by --machine over a scoped attachment to this deployment. The
      // write below clears the enrolled list, so a later --scoped starts empty
      // rather than reviving it, and that is said before it happens.
      if (io.isInteractive) {
        if (!(await confirmWidening(io, endpoint))) {
          io.err('not attaching machine-wide. Nothing was changed on this machine.');
          exit(1);
          return;
        }
      } else {
        // No terminal to ask on, and --machine was typed: the flag is the answer.
        listNotice = `Attaching machine-wide, as --machine asks. ${wideningNotice(endpoint)}\n`;
      }
    }
  }
  // ASKED AFTER VERIFICATION, ANSWERED BEFORE THE WRITES. After, so the machine
  // is never asked about a deployment it turns out not to join; before, so the
  // grant rides the same `applyOnboarding` call as the attachment itself and the
  // two either both land or both roll back.
  const historyConsent = await askAboutHistory(
    io,
    args.syncHistory,
    base,
    endpoint,
    identity,
    mode,
  );

  // THE ADMINISTRATOR'S OVERLAY, READ AGAIN for every attach, with nothing written
  // yet. The answers above were read before a browser approval or a key
  // verification that can take minutes, and an overlay may have arrived, changed or
  // gone since.
  //
  // First the refusals no mode gets past, worded as the check above words them: a
  // machine held at standalone, a connection pinned to another deployment, a name
  // the administrator gives or a lock keeps. The settings writer refuses a change to
  // a LOCKED pair but writes a PINNED one through, and the next read overlays the pin
  // back over it, so without this a machine-wide attach could store a credential for
  // a deployment the settings no longer name.
  //
  // Then a scoped write on a machine that has become machine-only. That check is
  // also what lets the enrolled list below bind to `endpoint`: with no pin on the
  // connection, the overlay leaves the descriptor this attach writes alone, so the
  // endpoint written is the one every read sees.
  //
  // Both are answered from ONE read of the overlay, and so is the second put
  // below: an overlay landing between two reads would otherwise be seen by one
  // check and not by the other.
  //
  // This narrows the window rather than closing it: an overlay can still arrive
  // between here and the settings write, and there the writer refuses a lock but
  // not a pin.
  const overlayAfterWait = overlayNow(deps);
  const lateRefusal = managedAttachRefusal({ endpoint, label: args.label }, base, overlayAfterWait);
  if (lateRefusal !== null) {
    io.err(`${attachRefusalLine(lateRefusal)} Nothing was changed on this machine.`);
    exit(1);
    return;
  }
  const lateScopedRefusal = managedScopedRefusal(base, overlayAfterWait);
  if (mode === 'scoped' && lateScopedRefusal !== null) {
    io.err(`${refusalLine(lateScopedRefusal)} Nothing was changed on this machine.`);
    exit(1);
    return;
  }

  // What was there before, so a failed write can be put back. Re-attaching is
  // how a key is ROTATED, so this path routinely runs on a machine that is
  // already attached and working — and an unconditional rollback would take
  // that machine from "attached and forwarding" to "attached, no usable
  // credential" while printing that nothing was changed.
  // The WIDE read, because a rollback writes back the exact bytes that were
  // there. This runs in the CLI's own process; nothing here crosses to a
  // browser, which is the boundary the narrow state exists to protect.
  //
  // GUARDED like the early read: a file can take the settings directory's place
  // during a browser approval, and that is reported with nothing written.
  const previous = readCredentialGuarded(base, io);
  if (previous === undefined) {
    exit(1);
    return;
  }

  // THE LOST UPDATE THE DECISION CANNOT SEE, put twice. The mode was settled from
  // the file read before the key was verified, and on the browser path that can be
  // minutes ago.
  //
  // First with the administrator's answer the decision was made with, so that what
  // it measures is the file. If the decision no longer agrees (see
  // settledDecisionHolds) another aka has attached, re-attached or detached this
  // machine in between, and writing what was settled could widen a personal device,
  // narrow a machine-wide attachment, or overwrite a newer build's file that the
  // confirmation in front of the user never covered.
  //
  // Then with the answer read again above. The two can disagree only where an
  // administrator began or stopped managing the connection during the wait, and a
  // machine they stopped managing is the user's to decide again: a mode the
  // administrator alone settled could widen what it sends.
  //
  // Either way, stop and say which; the next run decides again from what is there.
  const putAgain = {
    flag: args.mode,
    previous,
    endpoint,
    interactive: io.isInteractive,
    settled: modeDecision,
    mode,
  };
  if (!settledDecisionHolds({ ...putAgain, managed: scopedRefusal })) {
    io.err(CHANGED_WHILE_WAITING);
    exit(1);
    return;
  }
  if (!settledDecisionHolds({ ...putAgain, managed: lateScopedRefusal })) {
    io.err(MANAGEMENT_CHANGED_WHILE_WAITING);
    exit(1);
    return;
  }
  // Every check that can stop this attach has passed: now it says what it is
  // about to do to the enrolled list.
  if (listNotice !== undefined) io.out(listNotice);
  // A file this build cannot parse may be a scoped credential a newer aka
  // wrote; this attach goes ahead over it only because a flag or an answer
  // chose the mode. Its BYTES are kept, so a failed write puts that file back
  // instead of deleting it while saying the machine is left as it was. Only a
  // regular file the reader opened and read qualifies: a symlink
  // (`untrusted-file`) is never followed, and an `unreadable` one has no bytes.
  const previousBytes =
    !previous.usable && (previous.reason === 'malformed' || previous.reason === 'unsafe-endpoint')
      ? credentialBytes(settingsDirOf(base))
      : undefined;

  // ONE instant, used both as the descriptor's `attachedAt` and as the bound
  // `seedCaptureBacklog` marks owed up to. The two have to agree: the
  // structural drain already treats `attachedAt` as where the pre-attach
  // backlog ends, and a capture backfill using a different instant would mark
  // owed a set the consent prompt's own preview did not describe.
  const attachedAt = new Date();

  // The credential this attach writes, held as a value so the capture backfill
  // below reads its MODE from the same object the file will contain: what is
  // marked owed follows the attachment being made, not the one it replaces.
  // NO `keyPrefix` DERIVED FROM THE KEY. The field exists so a deployment
  // can hand back a non-secret label for its own key list, and a prefix taken
  // from the secret here is not that: it is a contiguous run of the
  // credential, written to a file and then printed by `aka status` into
  // terminals, scrollback and CI logs. The suite catches it — the run-based
  // no-echo check fails on exactly this — and the fix is to stop producing it
  // rather than to shorten it under whatever window the check uses. What
  // identifies an attachment on screen is the deployment and when it
  // happened, neither of which is secret.
  //
  // BY MODE. Machine-wide is the version-1 file every attach has always
  // written: these four members, in this order, byte for byte. Scoped is
  // version 2 with `mode: 'scoped'` LAST, where the reader's parse puts it
  // (AttachedCredentialV2 extends v1, and the key it adds goes after v1's).
  // The rollback below writes back what the reader returned, so this order is
  // what lets a failed re-attach restore exactly the bytes written here.
  const mintedAt = new Date().toISOString();
  const credential: AttachedCredentialAny =
    mode === 'scoped'
      ? {
          specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
          endpoint,
          apiKey,
          mintedAt,
          mode: 'scoped',
        }
      : { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint, apiKey, mintedAt };
  // What the attach committed, for the backfill's scope. Assigned in the try
  // below; its catch returns, so the backfill only ever reads a committed file.
  let committed: WorkspaceSettings | undefined;

  // The enrolled list this attach writes, given the one on file. Machine-wide:
  // none. Scoped: the list on file, RAW, when this machine was ALREADY a
  // personal device attached to this exact endpoint and the list is bound to
  // it and to the organization and account just verified, so a key rotation
  // keeps every enrollment and whatever a newer build added survives.
  // Otherwise a fresh empty one bound to them: a list for another endpoint,
  // for someone else, or naming nobody cannot be shown to be this account's;
  // and a bound list found beside a machine-wide credential, or none, was left
  // by a writer that did not clear it (an older aka's re-attach or detach), so
  // its enrollments belong to an attachment that has ended.
  // `previous` is the credential on disk just before the write, not the one the
  // mode was decided from: another aka may have attached this machine in between,
  // and what is kept must follow what is there now.
  const keepScope = holdsScopedFor(previous, endpoint);
  // How many entries this build can read in what was kept, for the success text.
  const kept = { readableEntries: 0 };
  // What a fresh list replaced, for the success text: how many entries this
  // build could read in it, why it was not kept, and what in it this build could
  // not read.
  const cleared: {
    readableEntries: number;
    because: ListClearedBecause | undefined;
    unread: number | 'list';
  } = {
    readableEntries: 0,
    because: undefined,
    unread: 0,
  };
  // Whether this attach keeps `stored` as the enrolled list: only a rotation of a
  // personal device on this deployment, for the organization and account just
  // verified. The one judgment, shared by what is written and by the order of the
  // writes.
  const keepsStoredList = (stored: unknown): boolean =>
    mode === 'scoped' && keepScope && isAttachmentScopeBoundTo(stored, endpoint, identity);
  const scopeToWrite = (stored: unknown): unknown => {
    if (mode === 'machine') return undefined;
    if (keepsStoredList(stored)) {
      kept.readableEntries = parseAttachmentScope(stored)?.entries.length ?? 0;
      return stored;
    }
    cleared.because = whyListCleared(stored, endpoint, identity, keepScope);
    cleared.readableEntries =
      cleared.because === undefined ? 0 : (parseAttachmentScope(stored)?.entries.length ?? 0);
    cleared.unread = unreadInReplacedList(stored);
    return freshAttachmentScope(endpoint, identity);
  };

  // THE ORDER OF THE TWO WRITES, chosen by what a stop between them would leave.
  //
  // CREDENTIAL FIRST, then the descriptor, unless the rule below picks the other
  // order. In the other order a machine that fails on the second write is left
  // claiming an attachment it has no credential for, which reads to every later
  // surface as a broken attachment rather than as one that never happened.
  //
  // SETTINGS FIRST (writesSettingsFirst) where the credential first would put the
  // new credential beside an enrolled list or a history grant that the finished
  // attach replaces, in a pairing of credential mode and stored list or grant that
  // the machine did not have:
  //   - a machine-wide attach over a credential that is, or may be, a personal
  //     device's, or over no credential file beside settings that still carry a
  //     list or a grant. The history drain would read a grant given for enrolled
  //     repositories as one for the whole machine.
  //   - a scoped attach that does not keep the list it finds (the key verified as
  //     another organization or account, a list that names no account, a list for
  //     another deployment, or a credential that is not a personal device's for
  //     this one), over settings that carry a list or a grant. A list enrolled
  //     under another account would forward under the new key.
  // The settings write no list (machine-wide) or an empty one (scoped), and carry
  // this run's history answer. In this order a stop leaves what the machine had
  // before beside no list or an empty one and no earlier grant, which sends no
  // repository's activity.
  //
  // So an attach is credential first only where a stop cannot leave the new
  // credential in such a pairing, with one exception:
  //   - a machine-wide attach replaces a machine-wide credential, or there is no
  //     credential file and the settings hold neither a list nor a grant;
  //   - a scoped attach finds settings that hold neither a list nor a grant, or
  //     keeps the list it finds (a rotation), so a stop leaves the new credential
  //     beside that same list;
  //   - the exception is a scoped attach over a machine-wide credential. Settings
  //     first there would leave the machine-wide credential beside this run's
  //     answer about the repositories to be enrolled, and the drain would read
  //     that as a grant for the whole machine. So a stop there leaves the new
  //     scoped credential beside the list on file, which the finished attach would
  //     have replaced and which may be another organization's or account's, and
  //     beside the earlier grant, with this run's answer lost. If that list names
  //     this deployment, its repositories forward under the new key, and their
  //     history goes under the earlier grant, until `aka attach` is run again.
  const settingsFirst = writesSettingsFirst(
    mode,
    previous,
    readEffectiveSettings(base, deps.managedSettings).settings,
    keepsStoredList,
  );
  const writeSettings = (): WorkspaceSettings =>
    applyOnboarding(
      // The FUNCTION form, so the enrolled list is judged against the file this
      // merge lands on, inside the settings lock: an `aka enroll` that lands just
      // before is judged with it rather than overwritten by a stale copy.
      (current) => ({
        runMode: 'attached',
        controlPlane: {
          endpoint,
          attachedAt: attachedAt.toISOString(),
          ...(args.label === undefined ? {} : { label: args.label }),
        },
        // SPELLED, never omitted. `undefined` on an optional key is how this
        // writer records a REVOCATION; leaving the key out instead merges over
        // the existing settings and preserves whatever grant is already there.
        // Re-attaching to the SAME deployment is the ordinary path — it is how a
        // key is rotated — so an omitted key would let a user who is asked again
        // and answers no keep sending, with their decline discarded.
        historySyncConsent: historyConsent,
        // SPELLED on every attach, for the same reason. A machine attachment
        // never holds an enrolled list, so a later --scoped cannot revive one,
        // and a scoped one keeps the list only when it is this account's.
        attachmentScope: scopeToWrite(current.attachmentScope),
      }),
      base,
      // The same overlay the pre-flight read — injected or real — so the writer
      // and the pre-flight cannot disagree about who manages this machine.
      deps.managedSettings,
    );
  // Set once the settings have landed ahead of the credential, so a failure after
  // that point is reported as what it left rather than rolled back: putting the
  // list and the grant back would take another settings write that can fail too.
  let settingsSaved = false;
  try {
    if (settingsFirst) {
      committed = writeSettings();
      settingsSaved = true;
      writeControlPlaneCredential(settingsDirOf(base), credential);
    } else {
      writeControlPlaneCredential(settingsDirOf(base), credential);
      committed = writeSettings();
    }
  } catch (err) {
    if (settingsSaved) {
      io.err(CREDENTIAL_NOT_SAVED_AFTER_SETTINGS);
      exit(1);
      return;
    }
    // Put back exactly what was there, rather than removing unconditionally,
    // and only while the file still holds what this attach wrote (see
    // restoreCredential): another aka may have attached or detached this machine
    // after that write. On a first attach that is "no credential"; on a rotation
    // it is the key the machine was working with. When it cannot be put back, or
    // must not be, the message below says so instead.
    const rollback = restoreCredential(settingsDirOf(base), previous, previousBytes, credential);
    io.err(saveFailedMessage(err, rollback));
    exit(1);
    return;
  }

  // The capture half of the grant. The structural half needs no equivalent
  // call: it re-derives its own backlog from `backlogBefore` on the drain's
  // next pass. A capture is reachable only through `outbox_owed`, and this is
  // the one moment anything sets it for a row recorded before now.
  //
  // SCOPED like the drain's own read (see captureBackfillScope), by the
  // credential this attach wrote: a machine credential means every capture, as
  // before, and on a scoped attachment it is the keys enrolled for this
  // endpoint. That is none on a first attach, so such a machine's backlog waits
  // for its repositories to be enrolled and re-seeded. Passed as a function,
  // like the other seed callers, so working it out stays inside the seed's own
  // best-effort guard.
  if (historyConsent !== undefined) {
    seedCaptureBacklogOwed(dataDirOf(base), attachedAt.getTime(), () =>
      captureBackfillScope({ usable: true, credential }, committed),
    );
  }

  // Best-effort, macOS only today: closes the gap where this host never
  // reopens a session to trigger SessionStart's own drain. Never blocks or
  // fails the attach — see @akasecurity/local-ops/background-schedule.
  //
  // INSTALLED UNCONDITIONALLY, even when historyConsent is undefined (a
  // decline, or --no-sync-history): `aka sync-history --on` is the only way
  // to grant consent after the fact, and it installs nothing itself — so
  // gating this on consent would leave a machine that grants later with no
  // scheduler until its next `aka attach`. A declined machine's scheduled
  // pass is a genuine no-op (`runHistorySyncPass` returns the 'no-consent'
  // skip reason and forwards nothing) rather than a silent cost, which is
  // what makes installing ahead of consent the cheaper failure mode.
  (deps.installBackgroundSync ?? installBackgroundSync)(base);

  // What attaching forwards depends on the MODE, and each block is true of its
  // own. The scoped one borrows no sentence from the machine-wide one, which is
  // unchanged.
  const attachedLines =
    mode === 'scoped'
      ? [
          // The label and the verified identity come from outside this process
          // (a deployment's whoami, a typed flag), so each goes through the one
          // shared terminal strip.
          `Attached to ${printableForTerminal(args.label ?? endpoint, 200)} as a personal device.`,
          `  organization  ${printableForTerminal(identity.tenantName, 200)}`,
          `  you           ${printableForTerminal(identity.userEmail, 320)}`,
          '',
          'Activity is sent to that deployment only from repositories you enroll, and',
          'the Data Shares register a scan records goes only for an enrolled',
          'repository — destinations and call sites, never source text. Activity',
          'anywhere else stays on this machine. A command you run inside an enrolled',
          "repository is sent as that repository's activity, even when it reads files",
          'elsewhere.',
          // A fresh list that replaced one holding entries this build can read
          // says how many and why they were not kept, so a re-attach that
          // verified as someone else does not empty the list unannounced. A list
          // that held what this build cannot read, the whole record or some
          // entries, says so on its own line, so a newer build's list is not
          // emptied unannounced.
          ...(cleared.because === undefined
            ? []
            : [clearedListLine(cleared.readableEntries), LIST_CLEARED_BECAUSE[cleared.because]]),
          ...unreadClearedLines(cleared.unread),
          // Chosen by what was KEPT that this build can read, not by whether a
          // record was kept: a bound record with no entries (a rotation before
          // anything was enrolled), or one holding only a newer build's kinds,
          // enrolls nothing here, and saying it was kept would read as done.
          kept.readableEntries > 0
            ? 'The repositories already enrolled here are kept: `aka enroll --list` shows them.'
            : 'Nothing is enrolled yet. Run `aka enroll` in a repository to start sending it.',
          '',
          // The policy pull and the device report happen in either mode, when a
          // session starts anywhere on the machine (a browser chat included), and
          // the scope does not gate them: the report's finding counts and dates
          // are for the whole store, and on a personal device the report also
          // says that it is one. The check for device commands is made only
          // where the host supplies a scan, which the browser host does not.
          'Whenever a session starts anywhere on this machine, in a repository or not',
          "(a browser chat included), the machine pulls that deployment's policy (at",
          'most every 15 minutes) and sends it a device report (at most hourly): a',
          'device identifier, host name, versions, detection packs, policy counts,',
          'finding counts and dates for everything recorded on the machine, and, when',
          'the machine is attached as a personal device, the fact that it is one. Where',
          'a scan is available (the coding-agent plugins, not a browser chat), the same',
          'session start also checks it for device commands.',
          // An aka older than this one writes a version-1 credential on every
          // attach, from its command line and from its dashboard alike, and
          // version 1 is machine-wide. Said here because the reader is the one
          // who would run it.
          'Re-attaching with an aka older than this one, from its command line or its',
          'dashboard, makes this machine machine-wide.',
          '',
          'Policy arrives on the next session. Run `aka status` to see it.',
          ...(historyConsent === undefined
            ? []
            : [
                '',
                'Unsent activity from the repositories you enroll is sent in the background,',
                'a little at a time, starting with your next session. Run `aka status` to',
                'watch it, or `aka sync-history --off` to stop.',
              ]),
          '',
        ]
      : [
          // The label, the address and the verified identity come from outside this
          // process, so each goes through the one shared terminal strip, as in the
          // scoped block.
          `Attached to ${printableForTerminal(args.label ?? endpoint, 200)}.`,
          `  organization  ${printableForTerminal(identity.tenantName, 200)}`,
          `  you           ${printableForTerminal(identity.userEmail, 320)}`,
          '',
          // Said here, on the one path every successful attach ends on, because the
          // forwarding they describe follows from the attachment and not from the
          // history answer. The register a scan records is named with what it does
          // and does not carry, since `aka scan` reads as a local verb.
          'Activity from here on is sent to that deployment automatically.',
          'So is the Data Shares register a scan records — destinations and call sites, never source text.',
          '',
          'Policy arrives on the next session. Run `aka status` to see it.',
          ...(historyConsent === undefined
            ? []
            : [
                '',
                'Your existing activity is sent in the background, a little at a time,',
                'starting with your next session. Run `aka status` to watch it, or',
                '`aka sync-history --off` to stop.',
              ]),
          '',
        ];
  io.out(attachedLines.join('\n'));
}

/**
 * The wide credential read, reported rather than thrown.
 *
 * GUARDED, although the reader's docblock says it never throws: with a FILE
 * where ~/.aka/settings should be, its lstat raises ENOTDIR (`throwIfNoEntry:
 * false` covers a missing entry only), the case the dashboard's attach action
 * already guards. Both reads in an attach go through here, the early one and
 * the one just before the writes, since that file can take the directory's
 * place during a browser approval. `undefined` means it was reported and the
 * caller exits having written nothing.
 */
function readCredentialGuarded(base: string, io: Prompter): CredentialFileRead | undefined {
  try {
    return readControlPlaneCredentialFile(settingsDirOf(base));
  } catch {
    io.err(
      `could not read this machine's AKA settings in ${printableForTerminal(settingsDirOf(base), Infinity)}; nothing was ` +
        'changed on this machine. Check that it is a directory you own.',
    );
    return undefined;
  }
}

/** Whether `a` and `b` are the same credential: every member this attach writes, and its mode. */
function sameCredential(a: AttachedCredentialAny, b: AttachedCredentialAny): boolean {
  return (
    a.specVersion === b.specVersion &&
    a.endpoint === b.endpoint &&
    a.apiKey === b.apiKey &&
    a.mintedAt === b.mintedAt &&
    attachmentModeOf(a) === attachmentModeOf(b)
  );
}

/**
 * Put the credential file back as it was before a failed save, and say what
 * came of it (see CredentialRollback). Never throws.
 *
 * - A credential this build could read is written back from the reader's own
 *   parse, which is the same bytes (the scoped literal's key order exists for
 *   this).
 * - No earlier file: the one this attach wrote is removed.
 * - A file the reader opened and could not parse: its raw bytes go back.
 * - A file it could not open at all (a symlink, someone else's file, one that
 *   would not read) has no bytes to put back. If the credential write replaced
 *   it, the file now on disk is the one this attach wrote, identified by every
 *   member of it and not by the key alone, and that file is removed: its
 *   settings were never written, so the settings on disk describe whatever the
 *   machine had before (or nothing), and a credential for another key or
 *   deployment beside them is a half-written attachment. The earlier file is
 *   gone either way. If the credential write never got as far as replacing it,
 *   the file is left alone: removing it would delete something this attach did
 *   not write.
 *
 * Each of those writes or removals happens only while the file still holds what
 * this attach wrote, every member of it (see sameCredential). Otherwise the file
 * is left alone: `restored` when it is still what was there before (this attach's
 * write never landed), `superseded` when something else changed it after that
 * write, since putting the earlier credential back would pair it with the
 * settings that other change wrote. None of the credential helpers takes a lock,
 * so this narrows the window between the read here and the write-back rather
 * than closing it.
 */
function restoreCredential(
  settingsDir: string,
  previous: CredentialFileRead,
  previousBytes: string | undefined,
  written: AttachedCredentialAny,
): CredentialRollback {
  try {
    const now = readControlPlaneCredentialFile(settingsDir);
    const holdsWritten = now.usable && sameCredential(now.credential, written);
    if (previous.usable) {
      if (holdsWritten) {
        writeControlPlaneCredential(settingsDir, previous.credential);
        return 'restored';
      }
      return now.usable && sameCredential(now.credential, previous.credential)
        ? 'restored'
        : 'superseded';
    }
    if (previous.reason === 'absent') {
      if (holdsWritten) {
        removeControlPlaneCredential(settingsDir);
        return 'restored';
      }
      return !now.usable && now.reason === 'absent' ? 'restored' : 'superseded';
    }
    if (previousBytes !== undefined) {
      if (holdsWritten) {
        // Owner-only and atomic, as every credential write is; the bytes as read.
        writeOwnerOnlyFileSync(controlPlaneCredentialPath(settingsDir), previousBytes);
        return 'restored';
      }
      return credentialBytes(settingsDir) === previousBytes ? 'restored' : 'superseded';
    }
    if (holdsWritten) {
      removeControlPlaneCredential(settingsDir);
      return 'replaced';
    }
    // Neither the earlier file, which could not be read, nor this attach's: a
    // usable credential is another attach's, whether it replaced this attach's
    // file or the unreadable one this attach never got to replace. A file that is
    // still unusable is the earlier one, which this attempt did not change.
    return now.usable ? 'superseded' : 'untouched';
  } catch {
    // The rollback itself failed. Nothing further to try.
    return 'failed';
  }
}

/** The credential file's bytes as text, or undefined when they cannot be read. Never throws. */
function credentialBytes(settingsDir: string): string | undefined {
  try {
    return readFileSync(controlPlaneCredentialPath(settingsDir), 'utf8');
  } catch {
    return undefined;
  }
}

/** Why no history question was asked, worded the same on both modes. */
const NO_TERMINAL_FOR_HISTORY =
  'Not asking about existing history: no terminal to prompt on. Nothing was sent.\n' +
  'Run `aka sync-history --on` later to send it.';

/**
 * What is masked in a drained capture's text, said by both history questions.
 * ONE copy, so the two cannot come to disagree about a rule that is the same
 * for both: the masking follows the detection's policy, whatever the mode.
 */
const MASKING_RULE_LINES: readonly string[] = [
  'prompt, an assistant reply or a tool result INCLUDES ITS TEXT. What is',
  'masked in that text follows the policy assigned to the detection that',
  'flagged the value: it is masked before it is stored or sent',
  'only where that policy is redact or block. Under monitor or warn the',
  'value goes as it was seen, and no detection ships on redact or block, so on',
  'a default install nothing in that text is masked. Everything outside a',
  'flagged span goes as written either way.',
];

/**
 * Whether this machine may also send the activity it recorded before attaching.
 *
 * Never throws and never blocks the attach: a store that cannot be read costs
 * the two numbers in the question, and no terminal costs the question itself.
 * Declining is the default everywhere — an empty answer, a non-TTY session, an
 * unreadable answer all decline, because sending cannot be undone.
 *
 * A SCOPED attachment is asked its own question. It forwards only what its
 * enrolled repositories record, and a first scoped attach has none enrolled, so
 * the whole machine's history would describe a backlog this grant never sends.
 * The store is not read for it.
 */
async function askAboutHistory(
  io: Prompter,
  flag: boolean | undefined,
  base: string,
  endpoint: string,
  identity: { tenantName: string },
  mode: AttachmentMode,
): Promise<HistorySyncConsent | undefined> {
  const granted = (): HistorySyncConsent => ({
    acknowledgedAt: new Date().toISOString(),
    payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    endpoint,
  });

  if (flag === false) return undefined;
  if (flag === true) return granted();

  if (mode === 'scoped') {
    if (!io.isInteractive) {
      io.err(NO_TERMINAL_FOR_HISTORY);
      return undefined;
    }
    io.out(scopedHistoryQuestion(identity.tenantName));
    const answer = (await io.ask('Send unsent activity from the repositories you enroll? [y/N]: '))
      .trim()
      .toLowerCase();
    return answer === 'y' || answer === 'yes' ? granted() : undefined;
  }

  const preview = readLocalHistoryPreview(dataDirOf(base));
  // NO EARLY RETURN ON AN EMPTY STORE, and that changed with payload v2.
  //
  // Under v1 the grant's only subject was the pre-attach backlog, so an empty
  // store made the question one with no subject and skipping it was right. v2
  // gave it a second subject that exists on any machine, empty or not: whether a
  // capture the live path FAILS to deliver is kept and retried or dropped. A
  // fresh machine — the common case for a first `aka attach` — has no history
  // and every future undelivered capture to decide about.
  //
  // Skipping the question there would leave it permanently ungranted and
  // silently drop that traffic, which is the v1 behaviour the outbox exists to
  // end. So the numbers are what an empty store costs, not the question: `scale`
  // below already has a branch for a store it could not read, and that is the
  // one an empty store now takes too.

  if (!io.isInteractive) {
    io.err(NO_TERMINAL_FOR_HISTORY);
    return undefined;
  }

  // Two shapes, because the grant has two subjects and only one of them needs a
  // store to be interesting. A machine with history is told how much; a machine
  // without one is still asked, about the half that is entirely in its future.
  // What attaching forwards regardless of this answer is not said here: this
  // question is skipped by both flags and by a session with no terminal, so it
  // is said once, by `runAttach`, after the attachment has been written.
  const backlog =
    preview === undefined || preview.sessions === 0
      ? undefined
      : preview.days >= 1
        ? `This machine has ${String(preview.days)} days of activity already recorded ` +
          `locally (${String(preview.sessions)} sessions). AKA can send that history.`
        : `This machine has ${String(preview.sessions)} sessions of activity already ` +
          'recorded locally. AKA can send that history.';

  io.out(
    [
      '',
      `Verified against ${printableForTerminal(identity.tenantName, 200)}.`,
      '',
      ...(backlog === undefined ? [] : [backlog]),
      `AKA can ${backlog === undefined ? '' : 'also '}keep anything a live send fails to deliver, instead of`,
      'dropping it.',
      '',
      ...(backlog === undefined
        ? []
        : [
            'What that history sends: which sessions ran, when, in which project,',
            '                  repo and git branch; token usage and model per call;',
            '                  which tools were called, with their inputs truncated;',
            '                  what AKA detected in those tool inputs; and the',
            '                  prompts, assistant replies and tool results',
            '                  themselves.',
            '',
          ]),
      // The masking half is CONDITIONAL and has to read that way. A drained
      // capture is the stored content, and a span is masked in the store only
      // where the policy assigned its detection is redact or block — so copy
      // promising that every detected secret is masked first would be false
      // under monitor and warn, which is every detection until the user
      // promotes one. Saying so is the point of asking, and it now covers BOTH
      // buckets alike: once granted, that history is sent through the same
      // outbox mark and the same drain as an undelivered live send, so the
      // same masking rule applies to both.
      ...(backlog === undefined
        ? [
            'For anything a live send could not deliver — the deployment was',
            'unreachable, or refused the key — what was captured, which for a',
          ]
        : [
            'For that history, and for anything a later live send could not',
            'deliver — the deployment was unreachable, or refused the key — what',
            'was captured, which for a',
          ]),
      ...MASKING_RULE_LINES,
      '',
      'Saying no does not stop live sending — that is part of being attached.',
      'It means an undelivered item is dropped rather than kept and retried.',
      '',
      'It runs in the background over your next few sessions. Anything sent',
      'cannot be recalled.',
      '',
    ].join('\n'),
  );

  const answer = (await io.ask("Send this machine's unsent activity? [y/N]: "))
    .trim()
    .toLowerCase();
  return answer === 'y' || answer === 'yes' ? granted() : undefined;
}

/**
 * The history question on a SCOPED attachment.
 *
 * It names no count. The local preview counts every session this machine
 * recorded, enrolled or not, so a number would describe what this grant never
 * sends. What the grant can send is said in terms of enrolled repositories:
 * some of what one recorded before it was enrolled (whatever this machine still
 * holds of it), and anything a live send from one fails to deliver. The tenant
 * name comes from the deployment, so it goes through the terminal strip.
 */
function scopedHistoryQuestion(tenantName: string): string {
  return [
    '',
    `Verified against ${printableForTerminal(tenantName, 200)}.`,
    '',
    'This machine is attaching as a personal device: AKA sends the activity of',
    'the repositories you enroll with `aka enroll`, and none from anywhere else.',
    "A command you run inside an enrolled repository is sent as that repository's",
    'activity, even when it reads files elsewhere.',
    'It can also send some of what an enrolled repository recorded here before',
    'you enrolled it, and keep anything a live send from one fails to deliver,',
    'instead of dropping it.',
    '',
    'For an enrolled repository, that history is which sessions ran, when, in',
    'which project, repo and git branch; token usage and model per call; which',
    'tools were called, with their inputs truncated; what AKA detected in those',
    'tool inputs; and the prompts, assistant replies and tool results themselves.',
    '',
    'For that history, and for anything a later live send could not',
    'deliver — the deployment was unreachable, or refused the key — what',
    'was captured, which for a',
    ...MASKING_RULE_LINES,
    '',
    'Saying no does not stop live sending from enrolled repositories — that is',
    'part of being attached. It means nothing an enrolled repository recorded',
    'before you enrolled it is sent, and an undelivered item is dropped rather',
    'than kept and retried.',
    '',
    'It runs in the background over your next few sessions. Anything sent',
    'cannot be recalled.',
    '',
  ].join('\n');
}

/** How many times the personal-device question is put before the attach gives up. */
const MODE_QUESTION_TRIES = 3;

/**
 * Whether this machine is a personal device, asked when nothing else decides
 * the mode (see decideAttachMode): a terminal, no flag, and no usable
 * credential for this endpoint.
 *
 * NO DEFAULT. Either wrong answer costs something: a personal device attached
 * machine-wide sends what nothing can recall, and a machine the organization
 * owns attached as a personal device forwards activity, and refuses the
 * organization's prohibited models, only in the repositories enrolled until
 * someone notices. So only y/yes and n/no are answers, case-insensitive and
 * trimmed; anything else, an empty line included, is asked again, up to
 * MODE_QUESTION_TRIES times. `undefined` after the last means no answer, and
 * the caller writes nothing.
 */
async function askAboutMode(io: Prompter): Promise<AttachmentMode | undefined> {
  io.out(
    [
      '',
      'How much of this machine should AKA send?',
      '',
      '  A personal device sends activity only from the repositories you enroll',
      '  with `aka enroll`, and none until you enroll one. Whenever a session',
      '  starts anywhere on this machine, in a repository or not (a browser chat',
      "  included), the machine pulls your organization's policy (at most every 15",
      '  minutes) and sends it a device report (at most hourly): a device',
      '  identifier, host name, versions, detection packs, policy counts, finding',
      '  counts and dates for everything recorded on the machine, and, when the',
      '  machine is attached as a personal device, the fact that it is one. Where a',
      '  scan is available (the coding-agent plugins, not a browser chat), the same',
      '  session start also checks it for device commands.',
      '  A machine your organization owns sends activity from anywhere on this',
      '  machine.',
      '',
    ].join('\n'),
  );
  // One question at a time: each answer decides whether to ask again.
  for (let attempt = 1; attempt <= MODE_QUESTION_TRIES; attempt += 1) {
    const answer = (await io.ask('Is this a personal device? [y/n]: ')).trim().toLowerCase();
    if (answer === 'y' || answer === 'yes') return 'scoped';
    if (answer === 'n' || answer === 'no') return 'machine';
    if (attempt < MODE_QUESTION_TRIES) {
      io.out('Answer y for a personal device, or n for a machine your organization owns.\n');
    }
  }
  return undefined;
}

/**
 * Confirm `--machine` over a scoped attachment to the same deployment, on a
 * terminal. Declining is the default, for the history question's reason: what
 * is sent cannot be recalled.
 */
async function confirmWidening(io: Prompter, endpoint: string): Promise<boolean> {
  io.out(
    [
      '',
      `This machine is attached to ${printableForTerminal(endpoint, 200)} as a personal device: activity is`,
      'sent only from the repositories enrolled on it. With --machine, activity from',
      'anywhere on this machine is sent, and the enrolled list is cleared.',
      '',
    ].join('\n'),
  );
  const answer = (await io.ask('Send activity from anywhere on this machine? [y/N]: '))
    .trim()
    .toLowerCase();
  return answer === 'y' || answer === 'yes';
}

/** What a widening that is not asked about says it is doing. */
function wideningNotice(endpoint: string): string {
  return (
    `This machine was attached to ${printableForTerminal(endpoint, 200)} as a personal device; ` +
    'its enrolled list will be cleared.'
  );
}

/**
 * Why a scoped attach started a fresh enrolled list instead of keeping the one
 * on file, for the line that says so. An exhaustive Record keys the wording, so
 * a reason added later cannot print a line with a hole in it.
 */
type ListClearedBecause = 'deployment' | 'replaced' | 'unbound' | 'organization' | 'account';

const LIST_CLEARED_BECAUSE: Record<ListClearedBecause, string> = {
  deployment: 'it was made for another deployment.',
  replaced: 'this attach does not continue a personal-device attachment to this deployment.',
  unbound: 'it names no account, so whose it is could not be checked.',
  organization: 'it names an organization other than the one this key verified as.',
  account: 'it names an account other than the one this key verified as.',
};

/**
 * Why a scoped attach to `endpoint` as `who` does not keep `stored`, or
 * undefined when the list holds no entry this build can read, which leaves
 * nothing for its line to report (what this build cannot read in it has a line
 * of its own, see unreadInReplacedList). `continues` is whether the credential being replaced is a
 * personal device's for exactly this endpoint (holdsScopedFor). Judged by the
 * rules the keep decision uses, in its order: the endpoint as an exact string,
 * then whether this attach continues one, then the binding, each field byte for
 * byte. Pure; never throws.
 */
function whyListCleared(
  stored: unknown,
  endpoint: string,
  who: Pick<PluginWhoami, 'tenantName' | 'userEmail'>,
  continues: boolean,
): ListClearedBecause | undefined {
  const record = parseAttachmentScope(stored);
  if (record === undefined || record.entries.length === 0) return undefined;
  if (record.endpoint !== endpoint) return 'deployment';
  if (!continues) return 'replaced';
  const { tenantName, userEmail } = record;
  if (
    tenantName === undefined ||
    tenantName === '' ||
    userEmail === undefined ||
    userEmail === ''
  ) {
    return 'unbound';
  }
  if (tenantName !== who.tenantName) return 'organization';
  if (userEmail !== who.userEmail) return 'account';
  return undefined;
}

/** The line that opens the report of a list a scoped attach did not keep. */
function clearedListLine(readableEntries: number): string {
  return readableEntries === 1
    ? 'The list on this machine held 1 enrollment; it was cleared because'
    : `The list on this machine held ${readableEntries.toLocaleString('en-US')} enrollments; ` +
        'they were cleared because';
}

/**
 * What the list on file held that this build cannot read, for a scoped attach
 * that replaces it with a fresh one: `'list'` when a record is stored (neither
 * absent nor null, the two ways no list is stored) and does not parse, else how
 * many of its stored entries the parse dropped. Pure; never throws.
 */
function unreadInReplacedList(stored: unknown): number | 'list' {
  if (stored === undefined || stored === null) return 0;
  const record = parseAttachmentScope(stored);
  if (record === undefined) return 'list';
  return typeof stored === 'object' && 'entries' in stored && Array.isArray(stored.entries)
    ? stored.entries.length - record.entries.length
    : 0;
}

/**
 * The line that says a fresh list replaced what this build could not read in the
 * one on file, the whole record or some of its entries, or none. The entries are
 * counted, never printed: one written by a newer build is not this build's to
 * describe.
 */
function unreadClearedLines(unread: number | 'list'): string[] {
  if (unread === 'list') {
    return ['This version of aka could not read the list on this machine; it was cleared.'];
  }
  if (unread === 0) return [];
  return [
    unread === 1
      ? 'This version of aka could not read 1 entry in the list on this machine; it was cleared.'
      : `This version of aka could not read ${unread.toLocaleString('en-US')} entries in the list ` +
        'on this machine; they were cleared.',
  ];
}

/**
 * What a managed attach says when the personal-device attachment it replaces
 * was to another deployment. That endpoint is not named: it is read from disk.
 */
const MANAGED_ELSEWHERE_NOTICE =
  'This machine was attached to another deployment as a personal device; ' +
  'its enrolled list will be cleared.';

/** The real verification: one round trip that proves the key is accepted. */
async function verifyWithControlPlane(
  endpoint: string,
  apiKey: string,
): Promise<{ tenantName: string; userEmail: string }> {
  const who = await createRemoteClient({ endpoint, apiKey }).whoami();
  return { tenantName: who.tenantName, userEmail: who.userEmail };
}

/**
 * Detach: clear the attachment and everything derived from it.
 *
 * THE CACHED POLICY GOES TOO, and that is not tidiness. An organization's
 * bundle merges over the local one RAISE-ONLY, so one left behind keeps
 * escalating enforcement on a machine nothing manages any more — and nothing
 * would ever refresh or clear it, because the sync that wrote it runs only
 * while attached. The recorded sync and posture outcomes go for the same
 * reason: each describes a deployment this machine is no longer talking to,
 * and leaving either would have status report a stale refusal after a later
 * re-attach.
 */
export function runDetach(argv: string[], deps: AttachDeps = {}): void {
  const io = deps.prompter ?? terminalPrompter();
  const exit = deps.exit ?? ((code: number) => process.exit(code));

  const args = parseAttachArgs(argv);
  if (isError(args)) {
    io.err(args.error);
    exit(2);
    return;
  }
  // The parser is shared with attach, so the mode flags parse here too. A detach
  // has no mode to choose, and accepting one silently would read as if it did.
  if (args.mode !== undefined) {
    io.err('aka detach does not take --scoped or --machine.');
    exit(2);
    return;
  }
  const base = deps.base ?? homeBase(args.home);

  // AHEAD OF EVERYTHING THIS COMMAND TOUCHES, the history window included. The
  // lock's refusal used to arrive from the writer, by which point the attached
  // period had been handed to the live path and the drain's boundary released
  // — for a detach that then did not happen. And under a pin with no lock the
  // writer refuses nothing at all: see managedDetachRefusal, which the
  // dashboard's detach action decides through as well.
  const refusal = managedDetachRefusal(base, deps.managedSettings);
  if (refusal !== null) {
    io.err(refusalLine(refusal));
    exit(1);
    return;
  }

  // THE DESCRIPTOR FIRST, and the credential only once it has actually gone.
  // The other order lets a refused detach still take effect in the way that
  // matters: an administrator can freeze `runMode`, so `applyOnboarding` throws
  // (the pre-flight above answers that first; the writer's own refusal is the
  // last word only if the overlay appeared between the two reads) — but the
  // credential is already deleted, settings still say `attached`, and the
  // machine silently stops forwarding while being told nothing happened. That
  // would let any user end reporting on a machine their organization manages,
  // by running a command that claims it did nothing.
  const had = readControlPlaneCredentialState(settingsDirOf(base)).usable;
  // BEFORE the descriptor is cleared, because it is what says when this
  // attachment began. The period since then belonged to the live forward path;
  // recording that hands it over and releases the history drain's boundary, so a
  // later re-attach to the same deployment freezes a new one and picks up the
  // window in which nothing was forwarding. Without it that window is delivered
  // by neither path and reported as outstanding by neither.
  //
  // Through the same overlay the pre-flight read — injected or real — so this
  // reads what the machine reads, and a suite reads what it injected.
  closeHistoryWindow(
    base,
    readEffectiveSettings(base, deps.managedSettings).settings.controlPlane?.attachedAt,
  );
  try {
    // The history grant and the enrolled list go with the attachment they
    // named. `undefined` on an optional key is how this writer records a
    // REVOCATION, so each key leaves settings.json rather than lingering for a
    // deployment this machine no longer talks to. A list left behind would be
    // kept by a later scoped attach as the same account, reviving enrollments
    // made under an attachment that ended here.
    applyOnboarding(
      {
        runMode: 'standalone',
        controlPlane: undefined,
        historySyncConsent: undefined,
        attachmentScope: undefined,
      },
      base,
      deps.managedSettings,
    );
  } catch (err) {
    io.err(
      err instanceof ManagedFieldError
        ? 'your organization manages this setting on this machine, so it cannot be detached here.'
        : 'could not clear the attachment; this machine is left as it was.',
    );
    exit(1);
    return;
  }
  removeControlPlaneCredential(settingsDirOf(base));
  clearDerived(dataDirOf(base));
  // Best-effort, alongside every other piece of attachment-derived state. The
  // SAME base this command resolved above — the LaunchAgent's label is keyed
  // on it, so passing anything else targets a different machine's job.
  (deps.uninstallBackgroundSync ?? uninstallBackgroundSync)(base);

  io.out(
    had
      ? 'Detached. This machine records locally only; that deployment is sent nothing.\n'
      : 'This machine was not attached; nothing to do.\n',
  );
}

/**
 * Everything derived from an attachment: the cached bundle, the recorded sync
 * outcome, the forward breaker's state, the count of events the batch budget
 * discarded, the last posture send's outcome, and how far the history drain had
 * got. All six are meaningless without one, and all six MISLEAD if they survive
 * it — the drop tally most legibly, since a freshly attached machine would
 * otherwise open by reporting events it lost to a deployment it no longer talks to.
 *
 * The breaker file is the one whose survival is more than cosmetic. Left
 * behind, a re-attach against a healthy plane opens with a stale `openedAtMs`,
 * so `forward.run` takes its early return and skips the network until the
 * cooldown elapses — while status renders a terminal-sounding refusal about a
 * deployment this machine no longer talks to.
 *
 * `force` swallows a missing file and still throws on a real failure, which is
 * the behaviour to want here: a detach that silently left the organization's
 * policy in place is the one outcome this function exists to prevent.
 */
// The list lives in @akasecurity/persistence, which both detach surfaces can
// reach — this one and the dashboard's settings action. A second copy here is
// how the two paths drift, and a file added to one of them silently outlives a
// detach on the other.
const clearDerived = clearAttachmentDerivedState;

/**
 * Hand the attached period over to the live path, and release the drain's
 * boundary so the next attachment can set its own.
 *
 * BEST-EFFORT, and deliberately silent. A detach's job is to stop this machine
 * reporting, and it has done that by the time this runs; failing it over
 * bookkeeping would report a detach that did happen as one that did not. The
 * store is opened here rather than in `attach` for the same asymmetry — a bad
 * store must never block ENROLMENT, but a detach that cannot update the ledger
 * simply leaves it as today's builds leave it.
 */
function closeHistoryWindow(base: string, attachedAt: string | undefined): void {
  if (attachedAt === undefined) return;
  const attachedAtMs = Date.parse(attachedAt);
  if (!Number.isFinite(attachedAtMs)) return;
  try {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.historySync.closeAttachedWindow(attachedAtMs, Date.now());
    } finally {
      db.close();
    }
  } catch {
    // See above: a ledger that cannot be updated is not a failed detach.
  }
}

/**
 * `aka status` — what this machine is attached to, read entirely from disk.
 *
 * Two renderers, because they have different shapes and the split is why the
 * policy line existed unused: `renderAttachedStatus` is synchronous and total,
 * and reading the cached bundle is neither. This command's own summary promises
 * "whether policy is current", and `renderPolicyLine` is the line that answers
 * it — the version in force and how old it is.
 *
 * Still no network, on either half.
 */
export async function runStatus(argv: string[], deps: AttachDeps = {}): Promise<void> {
  const io = deps.prompter ?? terminalPrompter();

  const args = parseAttachArgs(argv);
  if (isError(args)) {
    io.err(args.error);
    (deps.exit ?? ((code: number) => process.exit(code)))(2);
    return;
  }
  // Shared parser, as in runDetach: status reports the mode and never sets it.
  if (args.mode !== undefined) {
    io.err('aka status does not take --scoped or --machine.');
    (deps.exit ?? ((code: number) => process.exit(code)))(2);
    return;
  }
  const base = deps.base ?? homeBase(args.home);
  const dataDir = dataDirOf(base);

  const block = renderAttachedStatus({ base, settingsDir: settingsDirOf(base), dataDir });
  // Only for an attached machine: a standalone one has no policy to be current.
  const attached = !block.startsWith('AKA: standalone');
  io.out(attached ? `${block}\n${await renderPolicyLine(dataDir)}\n` : `${block}\n`);
  // The host's own version, and which of AKA's protections it is too old for.
  // This is one of the two surfaces carrying that detail: someone reading it has
  // come looking, which is why it names protections where the in-session notice
  // deliberately does not. Read from the cache a hook wrote, so it reports "last
  // seen" rather than probing — `claude --version` would answer for the install
  // on PATH, which need not be the one running any session.
  // Guarded, because `[]` means "nothing to say" and `[].join('\n')` is `''` —
  // which this template would turn into a bare newline. That is the COMMON case,
  // not an edge one: a CLI-only install, a Codex-only install, and any Claude
  // Code install before its first completed turn all have no cache to read.
  const hostLines = hostCompatibilityLines(readHostVersionCache(dataDir));
  if (hostLines.length > 0) io.out(`${hostLines.join('\n')}\n`);
}

/**
 * The real interactive attach: the two anonymous routes, this machine's device
 * identity, and the platform browser launcher.
 *
 * Thin on purpose — everything with a decision in it is in attach-device.ts,
 * which takes each of these as a seam so its tests need no socket, no home
 * directory and no browser.
 */
async function runDeviceAttach(input: {
  io: Prompter;
  endpoint: string;
  label?: string | undefined;
  base: string;
  verify: (endpoint: string, apiKey: string) => Promise<{ tenantName: string; userEmail: string }>;
}): Promise<DeviceAttachOutcome> {
  // Read through the posture store, so this machine presents the SAME identity
  // when attaching as when reporting posture. A separate id here would show one
  // laptop as two devices, and a later re-attach would add a machine record
  // rather than rotating the one it already has.
  const deviceId = await readDeviceIdentity(settingsDirOf(input.base));
  if (deviceId === null) {
    return {
      kind: 'failed',
      reason: 'this machine has no device identity and one could not be created — check ~/.aka.',
    };
  }
  return attachByDeviceCode({
    io: input.io,
    endpoint: input.endpoint,
    label: input.label,
    deviceId,
    // Reported to the deployment so an approval page can show which client is
    // asking. Unverified like everything else the device claims, and `unknown`
    // rather than an omission when the package metadata cannot be read — the
    // page renders a value either way.
    cliVersion: cliVersion() ?? 'unknown',
    client: createAttachClient({ endpoint: input.endpoint }),
    verify: input.verify,
    openBrowser: (url) => {
      openUrl(url);
    },
  });
}
