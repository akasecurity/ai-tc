import { hostname as osHostname, platform, release } from 'node:os';

import type { AttachDeviceGrant, AttachTokenResponse } from '@akasecurity/schema';

import type { Prompter } from '../lib/prompter.ts';

// The interactive half of `aka attach`: obtaining a credential by approving in a
// browser, instead of pasting one a user copied out of a dashboard.
//
// NOTHING HERE WRITES ANYTHING. This module runs the conversation — start a
// grant, print the code, wait, verify who the credential belongs to, ask — and
// hands the caller a key. Writing the credential and the settings descriptor
// stays in attach.ts, which already owns the ordering and the rollback that
// makes a half-written attachment impossible.
//
// The design constraint that shapes the rest: this machine has NO credential
// while it talks to these two routes. That is the point of the flow, and it
// means every answer is from a deployment the client has not authenticated. The
// contract's charset caps are what make those answers safe to print; this module
// is what makes them safe to ACT on, by confirming the identity behind the
// credential before anything reaches disk.

/** How the interactive attempt ended, for the caller to act on. */
export type DeviceAttachOutcome =
  /**
   * A credential was obtained AND the user accepted the identity behind it.
   *
   * `identity` rides along so the caller does not ask `whoami` a second time
   * for an answer that has been on screen since before they confirmed.
   *
   * NO `endpoint`. The caller already holds the one the user typed and writes
   * the attachment against it; a second copy here could only ever be the one
   * the DEPLOYMENT named, and carrying a value nobody reads is what let that
   * one go unchecked in the first place.
   */
  | {
      kind: 'attached';
      apiKey: string;
      identity: { tenantName: string; userEmail: string };
    }
  /**
   * The deployment does not offer this flow — it predates it, or has it
   * switched off. Indistinguishable, and deliberately so: both mean "use the
   * key prompt", and a client that had to tell them apart would need a version
   * handshake this flow exists to avoid.
   */
  | { kind: 'not-offered' }
  /** The user, or the person approving, said no. Nothing was written. */
  | { kind: 'declined'; reason: string }
  /** Something went wrong. `reason` is safe to print. */
  | { kind: 'failed'; reason: string };

export interface DeviceAttachDeps {
  io: Prompter;
  endpoint: string;
  label?: string | undefined;
  deviceId: string;
  cliVersion: string;
  /** The two anonymous routes. Injected so tests need no socket. */
  client: {
    startGrant(request: {
      deviceId: string;
      hostname: string;
      os: string;
      cliVersion: string;
      label?: string;
    }): Promise<AttachDeviceGrant>;
    poll(deviceCode: string): Promise<AttachTokenResponse>;
  };
  /** Proves the credential and names who it belongs to, before it is written. */
  verify: (endpoint: string, apiKey: string) => Promise<{ tenantName: string; userEmail: string }>;
  /** Best-effort browser launch. Never required — the code works typed by hand. */
  openBrowser?: (url: string) => void;
  /** Injected so tests do not wait. */
  sleep?: (ms: number) => Promise<void>;
  /** Injected so a test can bound a poll loop deterministically. */
  now?: () => number;
}

/**
 * The floor on how often this client polls, whatever a deployment asks for.
 *
 * A deployment could answer `interval: 1` — the config allows it — and a client
 * that obeyed literally would spend sixty requests a minute per attach against
 * an anonymous endpoint. Honouring a floor is not distrust of the deployment so
 * much as refusing to let a misconfiguration turn every CLI into a load
 * generator.
 */
const MIN_POLL_SECONDS = 2;

/** Give up rather than poll forever if a deployment never says `expired`. */
const MAX_WAIT_MS = 15 * 60 * 1000;

export async function attachByDeviceCode(deps: DeviceAttachDeps): Promise<DeviceAttachOutcome> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = deps.now ?? (() => Date.now());

  let grant: AttachDeviceGrant;
  try {
    grant = await deps.client.startGrant({
      deviceId: deps.deviceId,
      // A placeholder rather than an omission when the host cannot say. The
      // approval page has to render SOMETHING, and the contract requires a
      // non-empty string, so a visible "unknown" is both the honest answer and
      // the only one that parses.
      //
      // Written as an explicit emptiness check rather than `||`: these are
      // typed `string`, so a truthiness fallback reads as dead code to the
      // type-aware linter and gets deleted — taking the guard with it.
      hostname: nonEmpty(osHostname()),
      os: nonEmpty(`${platform()} ${release()}`.trim()),
      cliVersion: deps.cliVersion,
      ...(deps.label === undefined ? {} : { label: deps.label }),
    });
  } catch (err) {
    if (statusOf(err) === 404) return { kind: 'not-offered' };
    return { kind: 'failed', reason: describe(err) };
  }

  deps.io.out(
    [
      '',
      `  Open  ${grant.verificationUriComplete ?? grant.verificationUri}`,
      `  Code  ${grant.userCode}`,
      '',
      // The code is printed even when the prefilled link is available, and that
      // is the anti-phishing step rather than a convenience: the reader is meant
      // to CHECK that the page shows this code. Following a link never approves
      // anything by itself.
      '  Check that the page shows the same code, then approve there.',
      '  Waiting…',
      '',
    ].join('\n'),
  );

  // Best-effort, and OPENED ONLY IF IT PASSES `safeToOpen`. A machine with no
  // browser — an SSH session, a container — is the case this whole flow exists
  // for, so a launcher that does nothing must change nothing.
  const openable = safeToOpen(
    deps.endpoint,
    grant.verificationUriComplete ?? grant.verificationUri,
  );
  if (openable !== null) {
    try {
      deps.openBrowser?.(openable);
    } catch {
      // The URL is on screen. Nothing to report.
    }
  }

  const deadline = now() + Math.min(MAX_WAIT_MS, grant.expiresIn * 1000);
  let waitSeconds = Math.max(MIN_POLL_SECONDS, grant.interval);

  while (now() < deadline) {
    await sleep(waitSeconds * 1000);

    let answer: AttachTokenResponse;
    try {
      answer = await deps.client.poll(grant.deviceCode);
    } catch (err) {
      // A PLATFORM 429 IS THE SAME EVENT AS `slow_down`, and treating them
      // differently is how a well-behaved client ends up looking like an
      // attacker. The flow defines a body for "you are asking too often"; a
      // rate limiter in front of the deployment expresses the same thing as a
      // status. Both mean back off and keep waiting.
      if (statusOf(err) === 429) {
        waitSeconds = Math.min(waitSeconds * 2, 60);
        continue;
      }
      return { kind: 'failed', reason: describe(err) };
    }

    // FIELDS ARE READ DEFENSIVELY, not by discriminating on `status` alone, and
    // that is the contract's leniency showing through rather than an
    // inconvenience. The parser's last member accepts any `{ status }`, so a
    // body can legitimately arrive saying `slow_down` with no interval or
    // `issued` with no key. Narrowing on the string alone would type those as
    // complete and read `undefined` as though it were a value.
    if (answer.status === 'expired') {
      return {
        kind: 'declined',
        reason: 'the request expired before it was approved. Run `aka attach` again.',
      };
    }
    if (answer.status === 'denied') {
      return {
        kind: 'declined',
        // Server-authored, and safe to print because the contract refuses
        // control characters in it. This is the message that tells a read-only
        // role its ROLE is the problem, rather than leaving them to read a
        // refusal as a mistake they made.
        reason: stringField(answer, 'message') ?? 'the request was declined in the browser.',
      };
    }
    if (answer.status === 'issued') {
      const apiKey = stringField(answer, 'apiKey');
      // An `issued` with no key is not an attach. Waiting is the only safe
      // reading — the alternative is writing an attachment with no credential,
      // which every later surface reports as broken.
      if (apiKey === undefined) continue;
      // THE ANSWER'S OWN `endpoint` IS READ AND DISCARDED. It is the one
      // server-supplied value in this flow with a bigger blast radius than the
      // browser URL `safeToOpen` already refuses, because it would decide where
      // the freshly-minted credential is PRESENTED.
      //
      // Trusting it broke the confirmation this flow is built around. The
      // identity below is fetched from wherever it points, while the caller
      // writes the attachment against the endpoint the USER typed — so the
      // organization somebody says yes to and the deployment their machine ends
      // up talking to would be read from two different hosts, with nothing
      // comparing them. It also walks around `isSafeEndpoint`, which runs once
      // against the typed URL and is never re-applied: an issued
      // `http://10.0.0.5:8080` would reach the socket with `x-api-key` on it,
      // in plaintext.
      //
      // The contract's reason for echoing it — the deployment is the party that
      // knows its own canonical origin — is real, and it is not worth this. A
      // trailing slash is not worth a credential.
      return confirmAndReturn(deps, apiKey);
    }
    if (answer.status === 'slow_down') {
      waitSeconds = Math.max(MIN_POLL_SECONDS, numberField(answer, 'interval') ?? waitSeconds * 2);
      continue;
    }
    // Falls through for `pending` AND for anything this client has never heard
    // of, which is the same action for both by design: the contract is parsed
    // leniently precisely so a newer deployment can add a state without
    // breaking older clients, and the only safe reading of a state one does not
    // recognise is that nothing has been decided yet.
  }

  return {
    kind: 'declined',
    reason: 'nobody approved the request in time. Run `aka attach` again.',
  };
}

/**
 * Prove the credential, show who it belongs to, and ask.
 *
 * THE STEP THAT CLOSES THE REVERSE HIJACK. Classic device-code phishing is met
 * at the approval page; the reverse — someone who learned this machine's code
 * approving it from THEIR organization — would point this machine at a control
 * plane its owner never chose, and nothing on this side would look wrong. The
 * only moment that becomes visible is here, when the credential can be asked
 * whose it is.
 *
 * So the identity is fetched and SHOWN, and the user says yes, before anything
 * is written. A user who did not expect that organization has one obvious
 * answer, and declining costs them nothing: no credential has reached disk.
 *
 * TAKES NO ENDPOINT, deliberately. It reads `deps.endpoint` — the URL the user
 * typed and the only one `isSafeEndpoint` has checked — so there is no
 * parameter through which a caller could pass the one the deployment named.
 * That closes the gap structurally rather than by remembering: the host whose
 * identity is shown here is now necessarily the host the caller attaches to,
 * and this step cannot vouch for a deployment other than the one being
 * attached to.
 */
async function confirmAndReturn(
  deps: DeviceAttachDeps,
  apiKey: string,
): Promise<DeviceAttachOutcome> {
  let identity: { tenantName: string; userEmail: string };
  try {
    identity = await deps.verify(deps.endpoint, apiKey);
  } catch (err) {
    return {
      kind: 'failed',
      reason: `the credential could not be verified against ${deps.endpoint}: ${describe(err)}`,
    };
  }

  deps.io.out(
    [
      '',
      '  Approved by:',
      `    organization  ${identity.tenantName}`,
      `    account       ${identity.userEmail}`,
      '',
    ].join('\n'),
  );

  // A non-interactive run cannot be asked, and must not be assumed to consent.
  // It gets the identity printed above and a refusal, which is the same answer
  // a person would have given if this were not the organization they meant.
  if (!deps.io.isInteractive) {
    return {
      kind: 'declined',
      reason:
        'not attaching without confirmation. Re-run in a terminal to confirm the organization above, ' +
        'or use --key-stdin to attach with a key you already hold.',
    };
  }

  const answer = (await deps.io.ask('  Attach this machine to that organization? [y/N] ')).trim();
  if (!/^y(es)?$/i.test(answer)) {
    return { kind: 'declined', reason: 'not attaching. Nothing was changed.' };
  }
  return { kind: 'attached', apiKey, identity };
}

/** The HTTP status behind a transport error, when it carried one. */
function statusOf(err: unknown): number | undefined {
  const status: unknown = (err as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : undefined;
}

/**
 * A printable one-liner for a failure.
 *
 * The transport deliberately carries a STATUS and not a server-authored body,
 * so there is nothing here a hostile deployment could use to write its own
 * message into this terminal — which is the same reason `okBody` throws away
 * the body of a non-2xx.
 */
function describe(err: unknown): string {
  const status = statusOf(err);
  if (status !== undefined) return `the deployment answered ${String(status)}.`;
  return 'the deployment could not be reached.';
}

/** A string member of a leniently-parsed body, or undefined if absent. */
function stringField(body: AttachTokenResponse, key: string): string | undefined {
  const value: unknown = (body as Record<string, unknown>)[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** A positive number member of a leniently-parsed body, or undefined. */
function numberField(body: AttachTokenResponse, key: string): number | undefined {
  const value: unknown = (body as Record<string, unknown>)[key];
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : undefined;
}

/**
 * The verification URL, if it is safe to hand to a browser launcher.
 *
 * TWO REASONS a server-supplied URL cannot go straight to `openUrl`, and both
 * are about this being the first caller whose URL this repo did not build.
 *
 * COMMAND SPLITTING. The win32 opener is `cmd /c start "" <url>`, and cmd
 * re-parses that line: node quotes an argument only when it holds a space, a
 * tab or a quote, so `&`, `|`, `^`, `<` and `>` arrive unquoted and SPLIT the
 * command — `start "" http://h/p?a=1&b=2` opens `?a=1` and then RUNS `b=2`.
 * `openUrl`'s own comment states that constraint and says every caller so far
 * passes a URL this repo built. This one does not: it comes from the
 * deployment, and the contract's charset guard bans control characters, not
 * shell metacharacters. Refusing them here keeps that constraint true rather
 * than quietly becoming its first violation.
 *
 * REDIRECTION. The URL says where to go and approve, and a user who typed one
 * endpoint should not have their browser opened somewhere else — a compromised
 * or misconfigured deployment answering with a link to a site that merely LOOKS
 * like an approval page is the whole shape of a phishing step. So the origin
 * must match the endpoint the user named.
 *
 * A refusal is not an error. The URL and the code are already printed, and
 * typing them is the flow's documented path — the launcher is a convenience,
 * and declining it costs a user one paste.
 */
export function safeToOpen(endpoint: string, candidate: string): string | null {
  let url: URL;
  let base: URL;
  try {
    url = new URL(candidate);
    base = new URL(endpoint);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  // Same deployment the user named, scheme, host and port alike.
  if (url.origin !== base.origin) return null;
  // The cmd metacharacters `openUrl`'s win32 branch cannot quote. Checked on
  // every platform: what is refused should not depend on where the CLI runs,
  // or a link works for one developer and rewrites another's shell.
  if (/[&|^<>"]/.test(candidate)) return null;
  return candidate;
}

/** A non-empty stand-in, since the contract refuses an empty string. */
function nonEmpty(value: string): string {
  return value === '' ? 'unknown' : value;
}
