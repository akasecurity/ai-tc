import { rmSync } from 'node:fs';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  isSafeEndpoint,
  ManagedFieldError,
  readControlPlaneCredentialState,
  removeControlPlaneCredential,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  FORWARD_STATE_FILENAME,
  renderAttachedStatus,
  renderPolicyLine,
  SYNC_STATE_FILENAME,
} from '@akasecurity/plugin-runtime';
import { createRemoteClient } from '@akasecurity/remote';

import { homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

// `aka attach` / `aka detach` / `aka status` — registering this machine against
// an organization's deployment, and saying so afterwards.
//
// THE CREDENTIAL NEVER TOUCHES ARGV. There is no `--key` flag and adding one is
// a defect rather than a convenience: argv is world-readable through `ps` for
// the life of the process and lands in shell history besides. It arrives on a
// hidden prompt, or on stdin for an automated enrolment. An unknown flag exits
// 2 rather than being ignored, because a mistyped `--key` that was silently
// dropped would be the exact failure this rule exists to prevent.

/** The cache the sync child writes; named here because detach owns removing it. */
const POLICY_CACHE_FILENAME = 'policy-cache.json';

const USAGE = `Usage: aka attach --url <https-url> [--label <name>] [--key-stdin]

Registers this machine against your organization's AKA deployment.

  --url <url>     Where the deployment lives. https, or http on loopback.
  --label <name>  What to call it on screen. Defaults to the URL.
  --key-stdin     Read the access key from stdin instead of prompting.
  --home <dir>    Use an alternate AKA home instead of ~/.aka.

The key is never accepted as a command-line argument — it would be visible to
every process on this machine and recorded in your shell history.`;

export interface AttachDeps {
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
  return parsed;
}

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

  const apiKey = (
    args.keyStdin
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
    identity = await (deps.verify ?? verifyWithControlPlane)(endpoint, apiKey);
  } catch {
    io.err(
      `could not verify that key against ${endpoint}. Nothing was changed — ` +
        'check the URL and that the key has not been revoked.',
    );
    exit(1);
    return;
  }

  // What was there before, so a failed write can be put back. Re-attaching is
  // how a key is ROTATED, so this path routinely runs on a machine that is
  // already attached and working — and an unconditional rollback would take
  // that machine from "attached and forwarding" to "attached, no usable
  // credential" while printing that nothing was changed.
  const previous = readControlPlaneCredentialState(settingsDirOf(base));

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
      '',
    ].join('\n'),
  );
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
  try {
    applyOnboarding({ runMode: 'standalone', controlPlane: undefined }, base);
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
      ? 'Detached. This machine records locally only; nothing is sent anywhere.\n'
      : 'This machine was not attached; nothing to do.\n',
  );
}

/**
 * Everything derived from an attachment: the cached bundle, the recorded sync
 * outcome, and the forward breaker's state. All three are meaningless without
 * one, and all three MISLEAD if they survive it.
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
function clearDerived(dir: string): void {
  for (const name of [POLICY_CACHE_FILENAME, SYNC_STATE_FILENAME, FORWARD_STATE_FILENAME]) {
    rmSync(join(dir, name), { force: true });
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
