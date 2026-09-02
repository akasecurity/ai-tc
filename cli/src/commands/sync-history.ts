import { parseArgs } from 'node:util';

import { applyOnboarding, readWorkspaceSettings } from '@akasecurity/persistence';
import type { HistorySyncPassReport } from '@akasecurity/plugin-runtime';
import { runHistorySyncPass } from '@akasecurity/plugin-runtime';
import type { HistorySyncConsent, WorkspaceSettings } from '@akasecurity/schema';
import {
  controlPlaneName,
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

const USAGE = `Usage: aka sync-history [--on | --off] [--run]

Whether this machine may send the activity it recorded before attaching.

  --on          Send it. Takes effect in the background, over later sessions.
  --off         Do not send it. Stops anything not already sent.
  --run         Send a slice now, in this process, instead of waiting.
  --home <dir>  Use an alternate AKA home instead of ~/.aka.

With no flag, prints what is currently in force. Activity recorded from now on
is sent because this machine is attached; that is not what this grant covers,
and turning it off does not stop it.`;

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
    io.err(USAGE);
    exit(2);
    return;
  }

  // Which one wins is exactly what the person typing both cannot know, so
  // neither does.
  if (values.on === true && values.off === true) {
    io.err(`aka sync-history takes --on or --off, not both.\n\n${USAGE}`);
    exit(2);
    return;
  }

  const base = deps.base ?? homeBase(values.home);
  const settings = readWorkspaceSettings(base);

  // The answer is recorded first, then --run acts on it, so `--on --run` grants
  // and then sends rather than granting and silently ignoring half the command.
  if (values.on === true && !grant(io, exit, base, settings)) return;
  if (values.off === true && !revoke(io, exit, base)) return;
  if (values.on === true || values.off === true) {
    if (values.run !== true) return;
    // Re-read: the pass reads the grant that was just written.
    const report = await runHistorySyncPass(base);
    io.out(`${reportLine(report)}\n${describe(readWorkspaceSettings(base))}\n`);
    return;
  }
  if (values.run === true) {
    // IN-PROCESS, not a spawn. The CLI builds as one bundle with no sibling
    // script beside it, and its single-executable build makes `process.execPath`
    // the `aka` binary rather than node — so a spawn from here would fail
    // silently, which is the one outcome a command called `--run` must not have.
    const report = await runHistorySyncPass(base);
    io.out(`${reportLine(report)}\n${describe(readWorkspaceSettings(base))}\n`);
    return;
  }
  io.out(`${describe(settings)}\n`);
}

/**
 * What the pass did, in one line.
 *
 * `--run` used to print only the consent sentence, which is the same before and
 * after a pass and is silent about seven different ways of doing nothing. Each
 * line below names the remedy where there is one, because "nothing happened" is
 * the answer a user is trying to get past.
 *
 * Total over the union: a report this does not recognise still prints something
 * rather than falling through to an empty line.
 */
function reportLine(report: HistorySyncPassReport): string {
  switch (report) {
    case 'ok':
      return 'This pass sent what was waiting.';
    case 'interrupted':
      return 'This pass sent some of what was waiting; run it again to continue.';
    case 'unreachable':
      return 'This pass could not reach the deployment. Nothing was sent; it stays queued.';
    case 'refused':
      return 'This pass was refused by the deployment. Re-attach with `aka attach --url <url>`.';
    case 'not-attached':
      return 'This pass did nothing: there is no deployment to send to.';
    case 'no-consent':
      return 'This pass did nothing: sending existing activity is switched off.';
    case 'credential-unusable':
      return 'This pass did nothing: the stored credential cannot be used. Re-attach to repair it.';
    case 'breaker-open':
      return 'This pass did nothing: forwarding is paused after repeated failures, and resumes on its own.';
    case 'attachment-unreadable':
      return 'This pass did nothing: the recorded attachment time is unreadable. Re-attach to repair it.';
    case 'already-running':
      return 'This pass did nothing: another pass is already running.';
    case 'failed':
      return 'This pass could not complete. Nothing was lost; it stays queued for the next one.';
    default:
      return 'This pass sent nothing.';
  }
}

function grant(
  io: Prompter,
  exit: (code: number) => void,
  base: string,
  settings: WorkspaceSettings,
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
  const consent: HistorySyncConsent = {
    acknowledgedAt: new Date().toISOString(),
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
  io.out(
    `Sending this machine's unsent activity to ${controlPlaneName(settings.controlPlane)}.\n` +
      'That is the activity recorded before it attached, and anything a live send could not\n' +
      'deliver — which for a captured prompt, reply or tool result includes its text, with\n' +
      'detected secrets masked. It goes in the background, a little at a time, starting with\n' +
      'your next session. Anything already sent cannot be recalled.\n',
  );
  return true;
}

function revoke(io: Prompter, exit: (code: number) => void, base: string): boolean {
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
    "Not sending this machine's unsent activity. Anything already sent stays sent —\n" +
      'this stops what has not gone yet, and anything a live send cannot deliver is\n' +
      'dropped rather than kept. Live sending is part of being attached and continues.\n',
  );
  return true;
}

function describe(settings: WorkspaceSettings): string {
  if (!isAttached(settings) || settings.controlPlane === undefined) {
    return 'This machine is not attached to a deployment, so it sends nothing.';
  }
  const where = controlPlaneName(settings.controlPlane);
  if (isHistorySyncConsentValid(settings.historySyncConsent, settings.controlPlane.endpoint)) {
    return `Sending this machine's unsent activity to ${where}.`;
  }
  // A grant that exists but does not apply — given for another deployment, or
  // for a narrower payload than what would be sent now — reads as absent, and
  // saying so is more useful than reporting a bare "off" the user cannot explain.
  // The two are separated because they are not the same news: a STALE grant is
  // this deployment's own, and what changed is the payload, so the line says
  // what widened. A grant naming somewhere else is not re-offered at all.
  if (settings.historySyncConsent === undefined) {
    return (
      `Not sending this machine's unsent activity to ${where}.\n` +
      'Run `aka sync-history --on` to send it.'
    );
  }
  return isHistorySyncConsentStale(settings.historySyncConsent, settings.controlPlane.endpoint)
    ? `Not sending this machine's unsent activity to ${where}: your grant predates a change.\n` +
        'It now also covers the text of captured prompts, replies and tool results that no\n' +
        'live send delivered, with detected secrets masked.\n' +
        'Run `aka sync-history --on` to grant it again.'
    : `Not sending this machine's unsent activity to ${where}: the earlier grant no longer\n` +
        'applies. Run `aka sync-history --on` to grant it again.';
}
