import { cliVersion } from '@akasecurity/local-ops';
import {
  applyOnboarding,
  clearAttachmentDerivedState,
  dataDir as dataDirOf,
  isSafeEndpoint,
  ManagedFieldError,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  readEffectiveSettings,
  readLocalHistoryPreview,
  readWorkspaceSettings,
  removeControlPlaneCredential,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  readDeviceIdentity,
  renderAttachedStatus,
  renderPolicyLine,
} from '@akasecurity/plugin-runtime';
import { createAttachClient, createRemoteClient } from '@akasecurity/remote';
import type { HistorySyncConsent, ManagedSettings } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';

import { homeBase } from '../lib/args.ts';
import { openUrl } from '../lib/open-url.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';
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

const USAGE = `Usage: aka attach --url <https-url> [--label <name>] [--key-stdin]

Registers this machine against your organization's AKA deployment.

  --url <url>     Where the deployment lives. https, or http on loopback.
  --label <name>  What to call it on screen. Defaults to the URL.
  --key-stdin     Read the access key from stdin instead of prompting.
  --home <dir>    Use an alternate AKA home instead of ~/.aka.

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
      return { error: `unknown option ${String(arg)}` };
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

const isError = (v: ParsedArgs | { error: string }): v is { error: string } => 'error' in v;

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
  if (!isSafeEndpoint(endpoint)) {
    io.err(
      `refusing to attach to ${endpoint}: an access key must not travel in the clear. ` +
        'Use an https URL (http is accepted only for a loopback deployment).',
    );
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

  if (!args.keyStdin) {
    const refusal = managedRefusal(base, endpoint, args.label, deps.managedSettings);
    if (refusal !== null) {
      io.err(refusal);
      exit(2);
      return;
    }

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
      `could not verify that key against ${endpoint}. Nothing was changed — ` +
        'check the URL and that the key has not been revoked.',
    );
    exit(1);
    return;
  }

  // ASKED AFTER VERIFICATION, ANSWERED BEFORE THE WRITES. After, so the machine
  // is never asked about a deployment it turns out not to join; before, so the
  // grant rides the same `applyOnboarding` call as the attachment itself and the
  // two either both land or both roll back.
  const historyConsent = await askAboutHistory(io, args.syncHistory, base, endpoint, identity);

  // What was there before, so a failed write can be put back. Re-attaching is
  // how a key is ROTATED, so this path routinely runs on a machine that is
  // already attached and working — and an unconditional rollback would take
  // that machine from "attached and forwarding" to "attached, no usable
  // credential" while printing that nothing was changed.
  // The WIDE read, because a rollback writes back the exact bytes that were
  // there. This runs in the CLI's own process; nothing here crosses to a
  // browser, which is the boundary the narrow state exists to protect.
  const previous = readControlPlaneCredentialFile(settingsDirOf(base));

  try {
    // The credential FIRST, then the descriptor. In the other order a machine
    // that fails on the second write is left claiming an attachment it has no
    // credential for — which reads to every later surface as a broken
    // attachment rather than as one that never happened.
    // NO `keyPrefix` DERIVED FROM THE KEY. The field exists so a deployment
    // can hand back a non-secret label for its own key list, and a prefix taken
    // from the secret here is not that: it is a contiguous run of the
    // credential, written to a file and then printed by `aka status` into
    // terminals, scrollback and CI logs. The suite catches it — the run-based
    // no-echo check fails on exactly this — and the fix is to stop producing it
    // rather than to shorten it under whatever window the check uses. What
    // identifies an attachment on screen is the deployment and when it
    // happened, neither of which is secret.
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: 1,
      endpoint,
      apiKey,
      mintedAt: new Date().toISOString(),
    });
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint,
          attachedAt: new Date().toISOString(),
          ...(args.label === undefined ? {} : { label: args.label }),
        },
        // SPELLED, never omitted. `undefined` on an optional key is how this
        // writer records a REVOCATION; leaving the key out instead merges over
        // the existing settings and preserves whatever grant is already there.
        // Re-attaching to the SAME deployment is the ordinary path — it is how a
        // key is rotated — so an omitted key would let a user who is asked again
        // and answers no keep sending, with their decline discarded.
        historySyncConsent: historyConsent,
      },
      base,
    );
  } catch (err) {
    // Put back exactly what was there, rather than removing unconditionally.
    // On a first attach that is "no credential"; on a rotation it is the key
    // the machine was working with, and restoring it is what makes the message
    // below true.
    try {
      if (previous.usable) writeControlPlaneCredential(settingsDirOf(base), previous.credential);
      else removeControlPlaneCredential(settingsDirOf(base));
    } catch {
      // The rollback itself failed. Nothing further to try, and the message
      // below is deliberately the weaker of the two — see its wording.
    }
    // An administrator can freeze `runMode`, and a machine they froze to
    // standalone is one this command must not talk around.
    io.err(
      err instanceof ManagedFieldError
        ? 'your organization manages this setting on this machine, so it cannot be attached here.'
        : 'could not save the attachment; this machine is left as it was.',
    );
    exit(1);
    return;
  }

  io.out(
    [
      `Attached to ${args.label ?? endpoint}.`,
      `  organization  ${identity.tenantName}`,
      `  you           ${identity.userEmail}`,
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
    ].join('\n'),
  );
}

/**
 * Whether this machine may also send the activity it recorded before attaching.
 *
 * Never throws and never blocks the attach: a store that cannot be read costs
 * the two numbers in the question, and no terminal costs the question itself.
 * Declining is the default everywhere — an empty answer, a non-TTY session, an
 * unreadable answer all decline, because sending cannot be undone.
 */
async function askAboutHistory(
  io: Prompter,
  flag: boolean | undefined,
  base: string,
  endpoint: string,
  identity: { tenantName: string },
): Promise<HistorySyncConsent | undefined> {
  const granted = (): HistorySyncConsent => ({
    acknowledgedAt: new Date().toISOString(),
    payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    endpoint,
  });

  if (flag === false) return undefined;
  if (flag === true) return granted();

  const preview = readLocalHistoryPreview(dataDirOf(base));
  // A readable store with nothing in it: there is no history to ask about, so
  // asking would be a question with no subject. An UNREADABLE store is a
  // different answer — it still gets asked, without the numbers.
  if (preview?.sessions === 0) return undefined;

  if (!io.isInteractive) {
    io.err(
      'Not asking about existing history: no terminal to prompt on. Nothing was sent.\n' +
        'Run `aka sync-history --on` later to send it.',
    );
    return undefined;
  }

  const scale =
    preview === undefined
      ? 'This machine also has activity already recorded locally.'
      : preview.days >= 1
        ? `This machine also has ${String(preview.days)} days of activity already recorded ` +
          `locally (${String(preview.sessions)} sessions).`
        : `This machine also has ${String(preview.sessions)} sessions of activity already ` +
          'recorded locally.';

  io.out(
    [
      '',
      `Verified against ${identity.tenantName}.`,
      '',
      'Activity from here on is sent to that deployment automatically.',
      `${scale} AKA can send that history too.`,
      'It can also keep anything a live send fails to deliver, instead of',
      'dropping it.',
      '',
      'What that sends:  which sessions ran, when, in which project, repo and',
      '                  git branch; token usage and model per call; which tools',
      '                  were called, with their inputs truncated and every',
      '                  detected secret already masked; and what AKA detected',
      '                  in those tool inputs.',
      '',
      'And, for anything a live send could not deliver — the deployment was',
      'unreachable, or refused the key — what was captured, which for a prompt,',
      'an assistant reply or a tool result INCLUDES ITS TEXT. Every secret AKA',
      'detects is masked before it is stored or sent; the rest goes as written.',
      '',
      'Saying no does not stop live sending — that is part of being attached.',
      'It means an undelivered item is dropped rather than kept and retried.',
      '',
      'It runs in the background over your next few sessions. Anything sent',
      'cannot be recalled.',
      '',
    ].join('\n'),
  );

  const answer = (await io.ask("Send this machine's existing activity history? [y/N]: "))
    .trim()
    .toLowerCase();
  return answer === 'y' || answer === 'yes' ? granted() : undefined;
}

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
 * while attached. The recorded sync outcome goes for the same reason: it
 * describes a deployment this machine is no longer talking to, and leaving it
 * would have status report a stale refusal after a later re-attach.
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
  const base = deps.base ?? homeBase(args.home);

  // THE DESCRIPTOR FIRST, and the credential only once it has actually gone.
  // The other order lets a refused detach still take effect in the way that
  // matters: an administrator can freeze `runMode`, so `applyOnboarding` throws
  // — but the credential is already deleted, settings still say `attached`, and
  // the machine silently stops forwarding while being told nothing happened.
  // That would let any user end reporting on a machine their organization
  // manages, by running a command that claims it did nothing.
  const had = readControlPlaneCredentialState(settingsDirOf(base)).usable;
  // BEFORE the descriptor is cleared, because it is what says when this
  // attachment began. The period since then belonged to the live forward path;
  // recording that hands it over and releases the history drain's boundary, so a
  // later re-attach to the same deployment freezes a new one and picks up the
  // window in which nothing was forwarding. Without it that window is delivered
  // by neither path and reported as outstanding by neither.
  closeHistoryWindow(base, readWorkspaceSettings(base).controlPlane?.attachedAt);
  try {
    // The history grant goes with the attachment it named. `undefined` on an
    // optional key is how this writer records a REVOCATION, so the key leaves
    // settings.json rather than lingering as a grant for a deployment this
    // machine no longer talks to.
    applyOnboarding(
      { runMode: 'standalone', controlPlane: undefined, historySyncConsent: undefined },
      base,
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

  io.out(
    had
      ? 'Detached. This machine records locally only; that deployment is sent nothing.\n'
      : 'This machine was not attached; nothing to do.\n',
  );
}

/**
 * Everything derived from an attachment: the cached bundle, the recorded sync
 * outcome, the forward breaker's state, the count of events the batch budget
 * discarded, and how far the history drain had got. All five are meaningless
 * without one, and all five MISLEAD if they survive it — the drop tally most legibly, since a freshly attached machine
 * would otherwise open by reporting events it lost to a deployment it no longer
 * talks to.
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
  const base = deps.base ?? homeBase(args.home);
  const dataDir = dataDirOf(base);

  const block = renderAttachedStatus({ base, settingsDir: settingsDirOf(base), dataDir });
  // Only for an attached machine: a standalone one has no policy to be current.
  const attached = !block.startsWith('AKA: standalone');
  io.out(attached ? `${block}\n${await renderPolicyLine(dataDir)}\n` : `${block}\n`);
}

/**
 * Why this machine may not be attached here, or null when it may.
 *
 * RUN BEFORE ANY NETWORK CALL, which is the whole point of it being separate
 * from the write-time `ManagedFieldError` further down. An administrator who
 * froze `runMode`, or pinned a different endpoint, has already decided; asking
 * a deployment for a grant and walking someone through a browser approval
 * before telling them so wastes their time and leaves a decided grant behind on
 * a deployment they were never going to join.
 *
 * Attaching to the endpoint an administrator PINNED is the supported path and
 * is not refused here — that is the managed-enrolment case, not a conflict.
 */
export function managedRefusal(
  base: string,
  endpoint: string,
  label: string | undefined,
  // The overlay, injectable. It lives at ABSOLUTE SYSTEM paths on purpose — a
  // lock inside `~` is removable by the party being locked — so a temp home
  // cannot make a machine look managed, and cannot make a managed one look
  // clean either. Without this seam a suite reads whatever the DEVELOPER'S
  // machine is enrolled in, and a test asserting "not refused" passes or fails
  // on who ran it.
  managedOverride?: ManagedSettings | null,
): string | null {
  let effective: ReturnType<typeof readEffectiveSettings>;
  try {
    effective = readEffectiveSettings(base, managedOverride);
  } catch {
    // An unreadable managed overlay leaves the machine UNMANAGED rather than
    // unusable — the same direction managed-settings.ts fails in, and for the
    // same reason: a typo in an MDM payload must not stop every machine
    // attaching at once.
    return null;
  }
  const locked = new Set(effective.managed.lockedFields);
  const org = effective.managed.organization;
  const who = org ?? 'your organization';

  if (locked.has('runMode') && effective.settings.runMode !== 'attached') {
    return `${who} manages this machine and has set it to standalone, so it cannot be attached here.`;
  }
  const pinned = effective.settings.controlPlane;
  if (locked.has('runMode') && pinned !== undefined && pinned.endpoint !== endpoint) {
    return (
      `${who} manages this machine and has pinned it to ${pinned.endpoint}. ` +
      `Attach to that endpoint, or ask them to change it.`
    );
  }
  // A label-only difference is still a change to a descriptor the administrator
  // owns, and the writer would refuse it after the browser approval rather than
  // before — so it is refused here, where nobody has been sent anywhere yet.
  if (
    locked.has('runMode') &&
    pinned?.label !== undefined &&
    label !== undefined &&
    pinned.label !== label
  ) {
    return `${who} manages this machine name, so it cannot be renamed here.`;
  }
  return null;
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
