import { parseArgs } from 'node:util';

import {
  applyOnboarding,
  captureBackfillScope,
  dataDir as dataDirOf,
  readControlPlaneAttachmentMode,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
  seedCaptureBacklogOwed,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import type { HistorySyncPassReport } from '@akasecurity/plugin-runtime';
import {
  endpointForTerminal,
  printableForTerminal,
  runHistorySyncPass,
} from '@akasecurity/plugin-runtime';
import type {
  ControlPlaneConnection,
  HistorySyncConsent,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  HISTORY_SYNC_PAYLOAD_VERSION,
  isAttached,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
} from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

// `aka sync-history` — the grant that lets this machine send the activity it
// recorded BEFORE it attached, separately from the attachment itself.
//
// `aka attach` asks this once. This command is how the answer is changed later:
// given at attach and regretted, declined at attach and wanted afterwards, or
// never asked at all because the enrolment had no terminal.
//
// The grant names the deployment it was given for, so it does not survive a
// detach and does not travel to a different deployment — re-attaching elsewhere
// asks again rather than carrying an old answer to a new recipient.
//
// On a machine attached as a personal device the grant is narrower, and every
// line here says so: only the repositories enrolled there send their history,
// and no activity from anywhere else is sent. The wording follows the mode of
// the credential held for the connection the settings name; anything short of a
// usable personal-device credential keeps the machine-wide wording, the one
// that says more is sent, never less.

const USAGE = `Usage: aka sync-history [--on | --off] [--run]

Whether this machine may send the activity it recorded before attaching.

  --on          Send it. Takes effect in the background, over later sessions.
  --off         Do not send it. Stops anything not already sent.
  --run         Send a slice now, in this process, instead of waiting.
  --home <dir>  Use an alternate AKA home instead of ~/.aka.

With no flag, prints what is currently in force. Activity recorded from now on
is sent because this machine is attached; that is not what this grant covers,
and turning it off does not stop it.`;

/**
 * The same help on a machine attached as a personal device. The flags are the
 * same; what they send is narrower: only the repositories enrolled there.
 */
const USAGE_SCOPED = `Usage: aka sync-history [--on | --off] [--run]

Whether this personal device may send what the repositories you enroll recorded before
you enrolled them. No activity from any other repository, or from outside one, is sent.

  --on          Send it. Takes effect in the background, over later sessions.
  --off         Do not send it. Stops anything not already sent.
  --run         Send a slice now, in this process, instead of waiting.
  --home <dir>  Use an alternate AKA home instead of ~/.aka.

With no flag, prints what is currently in force. Activity an enrolled repository
records from now on is sent because this machine is attached; that is not what this
grant covers, and turning it off does not stop it.`;

/**
 * Whether the machine at `base` is attached as a personal device: the credential
 * it holds for the connection `settings` names is scoped.
 *
 * `readControlPlaneAttachmentMode` never throws. It answers `undefined` for no
 * connection, no usable credential, or a credential for another endpoint, and
 * each of those keeps the machine-wide wording, which says more is sent, never
 * less.
 */
function isPersonalDevice(base: string, settings: WorkspaceSettings): boolean {
  return readControlPlaneAttachmentMode(settingsDirOf(base), settings.controlPlane) === 'scoped';
}

/** The help, worded for the machine at `base`. `readWorkspaceSettings` is fail-open. */
function usage(base: string): string {
  return isPersonalDevice(base, readWorkspaceSettings(base)) ? USAGE_SCOPED : USAGE;
}

/**
 * The `--home` an argument list names, read on its own, for the help printed
 * when the full set of flags does not parse: that help is worded for a home,
 * and it must be the one the command line named.
 *
 * `strict: false` records an unknown flag, a stray value or a positional
 * instead of rejecting it, so `--home <dir>` is found beside whatever made the
 * strict parse fail. `--home` with no value comes back `true`, not a string,
 * and reads as no `--home` at all.
 */
function lenientHome(argv: string[]): string | undefined {
  const { values } = parseArgs({
    args: argv,
    options: HOME_OPTION,
    strict: false,
    allowPositionals: true,
  });
  return typeof values.home === 'string' ? values.home : undefined;
}

/**
 * The deployment's name as this command prints it: the connection's label, or
 * its endpoint.
 *
 * Neither was written by this process, so neither is echoed raw. A label is
 * typed at attach or set by an administrator's overlay, and is free text: it
 * gets the plain strip every `aka` command echoes a stored string with, bounded
 * at 200 as `aka attach` prints it. With no label the name is the settings
 * address, which is checked when settings are saved through the product, not
 * when the file is edited by hand or an overlay pins it, so it goes through
 * `endpointForTerminal`, which also keeps userinfo, a query and a fragment off
 * the screen. That is the rule the `aka status` plane line follows.
 */
function deploymentName(connection: ControlPlaneConnection): string {
  return connection.label === undefined
    ? endpointForTerminal(connection.endpoint)
    : printableForTerminal(connection.label, 200);
}

export interface SyncHistoryDeps {
  base?: string;
  prompter?: Prompter;
  exit?: (code: number) => void;
}

export async function runSyncHistory(argv: string[], deps: SyncHistoryDeps = {}): Promise<void> {
  const io = deps.prompter ?? terminalPrompter();
  const exit = deps.exit ?? ((code: number) => process.exit(code));

  let values: {
    home?: string | undefined;
    on?: boolean | undefined;
    off?: boolean | undefined;
    run?: boolean | undefined;
  };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        ...HOME_OPTION,
        on: { type: 'boolean' },
        off: { type: 'boolean' },
        run: { type: 'boolean' },
      },
      allowPositionals: false,
    }));
  } catch {
    // The flags did not parse, so `values.home` was never set. The help is
    // still worded for the home the command line names, recovered on its own.
    io.err(usage(deps.base ?? homeBase(lenientHome(argv))));
    exit(2);
    return;
  }

  const base = deps.base ?? homeBase(values.home);

  // Which one wins is exactly what the person typing both cannot know, so
  // neither does.
  if (values.on === true && values.off === true) {
    io.err(`aka sync-history takes --on or --off, not both.\n\n${usage(base)}`);
    exit(2);
    return;
  }

  const settings = readWorkspaceSettings(base);
  // Read once, before anything is written: neither answer changes the mode, and
  // every line below is worded for it.
  const scoped = isPersonalDevice(base, settings);

  // The answer is recorded first, then --run acts on it, so `--on --run` grants
  // and then sends rather than granting and silently ignoring half the command.
  if (values.on === true && !grant(io, exit, base, settings, scoped)) return;
  if (values.off === true && !revoke(io, exit, base, scoped)) return;
  if (values.on === true || values.off === true) {
    if (values.run !== true) return;
    // Re-read: the pass reads the grant that was just written.
    const report = await runHistorySyncPass(base);
    io.out(`${reportLine(report)}\n${describe(readWorkspaceSettings(base), scoped)}\n`);
    return;
  }
  if (values.run === true) {
    // IN-PROCESS, not a spawn. The CLI builds as one bundle with no sibling
    // script beside it, and its single-executable build makes `process.execPath`
    // the `aka` binary rather than node — so a spawn from here would fail
    // silently, which is the one outcome a command called `--run` must not have.
    const report = await runHistorySyncPass(base);
    io.out(`${reportLine(report)}\n${describe(readWorkspaceSettings(base), scoped)}\n`);
    return;
  }
  io.out(`${describe(settings, scoped)}\n`);
}

/**
 * What the pass did, in one line.
 *
 * `--run` used to print only the consent sentence, which is the same before and
 * after a pass and is silent about seven different ways of doing nothing. Each
 * line below names the remedy where there is one, because "nothing happened" is
 * the answer a user is trying to get past.
 *
 * A RECORD rather than a switch with a `default`: the union is closed and this
 * package owns both halves of it (`HistorySyncOutcome` and
 * `HistorySyncSkipReason` both live in `@akasecurity/plugin-runtime`, inlined
 * into this bundle — `cli/tsup.config.ts`'s `noExternal` makes the CLI and that
 * package one typechecked artifact, never two skewed at runtime), so there is no
 * REPORT this build fails to recognise, only a MEMBER added later. A `default`
 * would answer that with a sentence that is wrong rather than merely vague — a
 * new outcome is far likelier to resemble `ok` than to resemble nothing — where
 * `satisfies Record<HistorySyncPassReport, string>` fails the build at the line
 * that has to change.
 */
const REPORT_LINES = {
  ok: 'This pass sent what was waiting.',
  interrupted: 'This pass sent some of what was waiting; run it again to continue.',
  unreachable: 'This pass could not reach the deployment. Nothing was sent; it stays queued.',
  refused: 'This pass was refused by the deployment. Re-attach with `aka attach --url <url>`.',
  'not-attached': 'This pass did nothing: there is no deployment to send to.',
  'no-consent': 'This pass did nothing: sending existing activity is switched off.',
  'credential-unusable':
    'This pass did nothing: the stored credential cannot be used. Re-attach to repair it.',
  'breaker-open':
    'This pass did nothing: forwarding is paused after repeated failures, and resumes on its own.',
  'attachment-unreadable':
    'This pass did nothing: the recorded attachment time is unreadable. Re-attach to repair it.',
  'already-running': 'This pass did nothing: another pass is already running.',
  failed: 'This pass could not complete. Nothing was lost; it stays queued for the next one.',
} as const satisfies Record<HistorySyncPassReport, string>;

function reportLine(report: HistorySyncPassReport): string {
  return REPORT_LINES[report];
}

function grant(
  io: Prompter,
  exit: (code: number) => void,
  base: string,
  settings: WorkspaceSettings,
  scoped: boolean,
): boolean {
  // A grant records the endpoint it was given for, so there has to be one. An
  // unattached machine has no recipient to name, and a grant with no recipient
  // would apply to whatever this machine attached to next.
  if (!isAttached(settings) || settings.controlPlane === undefined) {
    io.err(
      'This machine is not attached to a deployment, so there is nowhere to send its history. ' +
        'Run `aka attach --url <url>` first.',
    );
    exit(1);
    return false;
  }
  const grantedAt = Date.now();
  const consent: HistorySyncConsent = {
    acknowledgedAt: new Date(grantedAt).toISOString(),
    payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    endpoint: settings.controlPlane.endpoint,
  };
  try {
    applyOnboarding({ historySyncConsent: consent }, base);
  } catch {
    io.err('Could not record that; this machine is left as it was.');
    exit(1);
    return false;
  }
  // The capture half of the grant — see seedCaptureBacklogOwed. `aka attach`
  // does the same thing at its own grant site; this is the other place a
  // fresh grant is recorded. Marked under the scope the drain will read with
  // (see captureBackfillScope), taken from `settings`: the file as it stood
  // before this grant, which is the one that matters, because a grant changes
  // no scope. Passed as a function so the credential read behind it runs inside
  // the seed's own best-effort guard: the grant is already recorded, and a
  // throw there must not turn it into a failure.
  const connection = settings.controlPlane;
  seedCaptureBacklogOwed(dataDirOf(base), grantedAt, () =>
    captureBackfillScope(readControlPlaneCredentialFile(settingsDirOf(base), connection), settings),
  );
  const where = deploymentName(connection);
  if (scoped) {
    // A personal device. The seed above marked only what the enrolled
    // repositories hold (nothing, with none enrolled), and the drain's capture
    // read applies the same scope whatever was marked, so the subject is
    // theirs, and the line says no activity is sent until one is enrolled.
    io.out(
      `Sending the unsent activity of the repositories enrolled here to ${where}.\n` +
        'No activity from any other repository, or from outside one, is sent, and with none enrolled\n' +
        'no activity is sent at all: `aka enroll --list` shows what is enrolled. What is sent is some\n' +
        'of what an enrolled repository recorded here before you enrolled it and anything a live\n' +
        'send from one could not deliver, alike: for a captured prompt, reply or tool result,\n' +
        'either one includes its text. A value in that text is masked only where the policy\n' +
        'assigned to the detection that flagged it is redact or block; under monitor or warn it\n' +
        'goes as it was seen, and no detection ships on redact or block. It goes in the\n' +
        'background, a little at a time, starting with your next session. Anything already sent\n' +
        'cannot be recalled.\n',
    );
    return true;
  }
  io.out(
    `Sending this machine's unsent activity to ${where}.\n` +
      'That is the activity recorded before it attached and anything a live send could not\n' +
      'deliver, alike: for a captured prompt, reply or tool result, either one includes its\n' +
      'text. A value in that text is masked only where the policy assigned to the detection\n' +
      'that flagged it is redact or block; under monitor or warn it goes as it was seen, and\n' +
      'no detection ships on redact or block. It goes in the background, a little at a time,\n' +
      'starting with your next session. Anything already sent cannot be recalled.\n',
  );
  return true;
}

function revoke(
  io: Prompter,
  exit: (code: number) => void,
  base: string,
  scoped: boolean,
): boolean {
  try {
    // `undefined` on an optional key is how this writer records a revocation:
    // the key leaves settings.json rather than persisting as a false grant.
    applyOnboarding({ historySyncConsent: undefined }, base);
  } catch {
    io.err('Could not record that; this machine is left as it was.');
    exit(1);
    return false;
  }
  io.out(
    scoped
      ? 'Not sending the unsent activity of the repositories enrolled here. Anything already\n' +
          'sent stays sent — this stops what has not gone yet, and anything a live send cannot\n' +
          'deliver is dropped rather than kept. Live sending from enrolled repositories is part\n' +
          'of being attached and continues.\n'
      : "Not sending this machine's unsent activity. Anything already sent stays sent —\n" +
          'this stops what has not gone yet, and anything a live send cannot deliver is\n' +
          'dropped rather than kept. Live sending is part of being attached and continues.\n',
  );
  return true;
}

function describe(settings: WorkspaceSettings, scoped: boolean): string {
  if (!isAttached(settings) || settings.controlPlane === undefined) {
    return 'This machine is not attached to a deployment, so it sends nothing.';
  }
  const where = deploymentName(settings.controlPlane);
  // What the grant covers. On a personal device that is the enrolled
  // repositories' backlog, never the whole machine's.
  const subject = scoped
    ? 'the unsent activity of the repositories enrolled here'
    : "this machine's unsent activity";
  if (isHistorySyncConsentValid(settings.historySyncConsent, settings.controlPlane.endpoint)) {
    // On a personal device with nothing enrolled, "Sending" alone would describe
    // a send that cannot happen, so the line says so.
    return scoped
      ? `Sending ${subject} to ${where}.\n` +
          'With no repository enrolled, no activity is sent: `aka enroll --list` shows what is enrolled.'
      : `Sending ${subject} to ${where}.`;
  }
  // A grant that exists but does not apply — given for another deployment, or
  // for a narrower payload than what would be sent now — reads as absent, and
  // saying so is more useful than reporting a bare "off" the user cannot explain.
  // The two are separated because they are not the same news: a STALE grant is
  // this deployment's own, and what changed is the payload, so the line says
  // what widened. A grant naming somewhere else is not re-offered at all.
  if (settings.historySyncConsent === undefined) {
    return `Not sending ${subject} to ${where}.\n` + 'Run `aka sync-history --on` to send it.';
  }
  return isHistorySyncConsentStale(settings.historySyncConsent, settings.controlPlane.endpoint)
    ? `Not sending ${subject} to ${where}: your grant predates a change.\n` +
        (scoped
          ? 'It now also covers the text of what an enrolled repository recorded before you\n' +
            'enrolled it — not just what a live send from one failed to deliver afterward — in\n' +
            'which a value is masked only where the detection that flagged it is set to redact or\n' +
            'block, and no detection ships on redact or block.\n'
          : 'It now also covers the text of the activity recorded before this machine attached —\n' +
            'not just what a live send failed to deliver afterward — in which a value is masked\n' +
            'only where the detection that flagged it is set to redact or block, and no\n' +
            'detection ships on redact or block.\n') +
        'Run `aka sync-history --on` to grant it again.'
    : `Not sending ${subject} to ${where}: the earlier grant no longer\n` +
        'applies. Run `aka sync-history --on` to grant it again.';
}
