import { rmSync } from 'node:fs';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  defaultDataDir,
  isSafeEndpoint,
  ManagedFieldError,
  removeControlPlaneCredential,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { renderAttachedStatus, SYNC_STATE_FILENAME } from '@akasecurity/plugin-runtime';
import { createRemoteClient } from '@akasecurity/remote';

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
  const base = deps.base ?? defaultDataDir();
  const io = deps.prompter ?? terminalPrompter();
  const exit = deps.exit ?? ((code: number) => process.exit(code));

  const args = parseAttachArgs(argv);
  if (isError(args)) {
    io.err(`${args.error}\n\n${USAGE}`);
    exit(2);
    return;
  }
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
    // An administrator can freeze `runMode`, and a machine they froze to
    // standalone is one this command must not talk around.
    removeControlPlaneCredential(settingsDirOf(base));
    io.err(
      err instanceof ManagedFieldError
        ? 'your organization manages this setting on this machine, so it cannot be attached here.'
        : 'could not save the attachment; nothing was changed.',
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
export function runDetach(_argv: string[], deps: AttachDeps = {}): void {
  const base = deps.base ?? defaultDataDir();
  const io = deps.prompter ?? terminalPrompter();
  const exit = deps.exit ?? ((code: number) => process.exit(code));

  const had = removeControlPlaneCredential(settingsDirOf(base));
  try {
    applyOnboarding({ runMode: 'standalone', controlPlane: undefined }, base);
  } catch (err) {
    io.err(
      err instanceof ManagedFieldError
        ? 'your organization manages this setting on this machine, so it cannot be detached here.'
        : 'could not clear the attachment.',
    );
    exit(1);
    return;
  }
  clearDerived(dataDirOf(base));

  io.out(
    had
      ? 'Detached. This machine records locally only; nothing is sent anywhere.'
      : 'This machine was not attached; nothing to do.',
  );
}

/**
 * The cached bundle and the recorded sync outcome — both derived from an
 * attachment, and both meaningless without one.
 *
 * `force` swallows a missing file and still throws on a real failure, which is
 * the behaviour to want here: a detach that silently left the organization's
 * policy in place is the one outcome this function exists to prevent.
 */
function clearDerived(dir: string): void {
  for (const name of [POLICY_CACHE_FILENAME, SYNC_STATE_FILENAME]) {
    rmSync(join(dir, name), { force: true });
  }
}

/** `aka status` — what this machine is attached to, read entirely from disk. */
export function runStatus(_argv: string[], deps: AttachDeps = {}): void {
  const base = deps.base ?? defaultDataDir();
  const io = deps.prompter ?? terminalPrompter();

  io.out(
    renderAttachedStatus({
      base,
      settingsDir: settingsDirOf(base),
      dataDir: dataDirOf(base),
    }),
  );
}
