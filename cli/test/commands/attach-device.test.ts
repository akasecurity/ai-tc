import type { AttachDeviceGrant, AttachTokenResponse } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { attachByDeviceCode, safeToOpen } from '../../src/commands/attach-device.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// The interactive attach's decisions, driven with no socket, no home directory
// and no browser. Everything with a decision in it lives in this module
// precisely so it can be exercised this way.

const ENDPOINT = 'https://aka.acme.test';
// High-entropy and deliberately NOT credential-shaped: this repo is public, and
// a fixture that looks like a real secret does not belong in it. What the
// echo helper needs is a value ordinary output cannot collide with.
const ISSUED_KEY = 'zq7fvkxm2rjt9wbn4hdc6sylp3g8';

const GRANT: AttachDeviceGrant = {
  deviceCode: 'd'.repeat(43),
  userCode: 'BCDF-GHJK',
  verificationUri: `${ENDPOINT}/attach`,
  verificationUriComplete: `${ENDPOINT}/attach?code=BCDF-GHJK`,
  expiresIn: 600,
  interval: 5,
};

function prompter(answers: string[] = [], interactive = true): Prompter & { output(): string } {
  let out = '';
  const queue = [...answers];
  return {
    out: (t) => (out += t),
    err: (t) => (out += t),
    isInteractive: interactive,
    ask: () => Promise.resolve(queue.shift() ?? ''),
    askHidden: () => Promise.resolve(''),
    readAllStdin: () => Promise.resolve(''),
    output: () => out,
  };
}

/** A client that answers a scripted sequence of poll results. */
function client(
  answers: (AttachTokenResponse | Error)[],
  grant: AttachDeviceGrant | Error = GRANT,
) {
  const queue = [...answers];
  return {
    calls: 0,
    startGrant: () => (grant instanceof Error ? Promise.reject(grant) : Promise.resolve(grant)),
    poll(): Promise<AttachTokenResponse> {
      const next = queue.shift() ?? { status: 'pending' as const };
      return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
    },
  };
}

const identity = { tenantName: 'Acme', userEmail: 'dev@acme.test' };
const verifyOk = () => Promise.resolve(identity);

/** Deps with every seam stubbed and no waiting. */
function deps(overrides: Partial<Parameters<typeof attachByDeviceCode>[0]> = {}) {
  return {
    io: prompter(['y']),
    endpoint: ENDPOINT,
    deviceId: 'device-1',
    cliVersion: '0.9.8',
    client: client([{ status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT }]),
    verify: verifyOk,
    sleep: () => Promise.resolve(),
    ...overrides,
  } as Parameters<typeof attachByDeviceCode>[0];
}

describe('starting the flow', () => {
  it('prints the code and the link, and says to check they match', async () => {
    const io = prompter(['y']);
    await attachByDeviceCode(deps({ io }));
    expect(io.output()).toContain('BCDF-GHJK');
    expect(io.output()).toContain(`${ENDPOINT}/attach?code=BCDF-GHJK`);
    // The match-check is the anti-phishing step, not a nicety: following a link
    // must never be what approves anything.
    expect(io.output()).toMatch(/same code/i);
  });

  // A deployment that predates the flow, or has it switched off, answers 404.
  // Both mean "use the key prompt", and the caller must not have to tell them
  // apart — there is no version handshake anywhere in this flow.
  it('reports not-offered on a 404 rather than failing', async () => {
    const notFound = Object.assign(new Error('nope'), { status: 404 });
    const outcome = await attachByDeviceCode(deps({ client: client([], notFound) }));
    expect(outcome.kind).toBe('not-offered');
  });

  it('reports a failure for any other start error', async () => {
    const boom = Object.assign(new Error('nope'), { status: 500 });
    const outcome = await attachByDeviceCode(deps({ client: client([], boom) }));
    expect(outcome.kind).toBe('failed');
  });
});

describe('polling', () => {
  it('waits through pending answers and then issues', async () => {
    const outcome = await attachByDeviceCode(
      deps({
        client: client([
          { status: 'pending' },
          { status: 'pending' },
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT },
        ]),
      }),
    );
    expect(outcome).toMatchObject({ kind: 'attached', apiKey: ISSUED_KEY });
  });

  it('reports a denial as declined, carrying the reason the deployment gave', async () => {
    const outcome = await attachByDeviceCode(
      deps({
        client: client([{ status: 'denied', message: 'your role cannot attach machines' }]),
      }),
    );
    expect(outcome).toMatchObject({ kind: 'declined' });
    expect(outcome.kind === 'declined' ? outcome.reason : '').toContain('role cannot attach');
  });

  it('reports an expiry as declined', async () => {
    const outcome = await attachByDeviceCode(deps({ client: client([{ status: 'expired' }]) }));
    expect(outcome).toMatchObject({ kind: 'declined' });
  });

  // A platform 429 and a `slow_down` body are the SAME event reaching the
  // client by two routes — one from the deployment, one from a limiter in front
  // of it. Treating the status as a failure is how a well-behaved client ends
  // up looking like an attacker.
  it('treats a 429 as back-off rather than as a failure', async () => {
    const tooMany = Object.assign(new Error('slow'), { status: 429 });
    const outcome = await attachByDeviceCode(
      deps({
        client: client([tooMany, { status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT }]),
      }),
    );
    expect(outcome).toMatchObject({ kind: 'attached' });
  });

  it('backs off when told to slow down, and carries on', async () => {
    const slept: number[] = [];
    const outcome = await attachByDeviceCode(
      deps({
        client: client([
          { status: 'slow_down', interval: 30 },
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT },
        ]),
        sleep: (ms) => {
          slept.push(ms);
          return Promise.resolve();
        },
      }),
    );
    expect(outcome).toMatchObject({ kind: 'attached' });
    // First wait is the grant's own interval; the second honours the new one.
    expect(slept).toEqual([5000, 30_000]);
  });

  // The contract's last member accepts any `{ status }`, so this is a body a
  // newer deployment may legitimately send. Failing on it would make every
  // older client break the day a sixth state ships.
  it('keeps waiting through a status it has never heard of', async () => {
    const outcome = await attachByDeviceCode(
      deps({
        client: client([
          { status: 'authorization_pending' },
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT },
        ]),
      }),
    );
    expect(outcome).toMatchObject({ kind: 'attached' });
  });

  // The safe degradation the union's member ORDER buys: an `issued` with no key
  // parses as an unrecognised status, and attaching with nothing would write an
  // attachment every later surface reports as broken.
  it('does not attach on an issued body carrying no key', async () => {
    const outcome = await attachByDeviceCode(
      deps({
        client: client([
          { status: 'issued' },
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT },
        ]),
      }),
    );
    // It waited, then took the well-formed one.
    expect(outcome).toMatchObject({ kind: 'attached', apiKey: ISSUED_KEY });
  });

  // THE ANSWER'S OWN `endpoint` IS NOT WHERE THE CREDENTIAL GOES.
  //
  // It is the one server-supplied value in this flow with a bigger blast radius
  // than the browser URL `safeToOpen` refuses: it would decide where the
  // freshly-minted key is presented. Trusting it split the flow in half — the
  // organization shown at the confirmation came from the deployment's host
  // while the caller wrote the attachment against the user's, with nothing
  // comparing them — and it walked around `isSafeEndpoint`, which runs once
  // against the typed URL and is never re-applied, so an issued
  // `http://10.0.0.5:8080` reached the socket with `x-api-key` on it.
  //
  // Asserted through `verify`, because that is the seam the credential actually
  // crosses. Asserting on the outcome would not have caught it: the outcome
  // carried an `endpoint` field nobody read.
  it('verifies against the endpoint the user typed, never the one the answer names', async () => {
    const verifiedAgainst: string[] = [];
    const outcome = await attachByDeviceCode(
      deps({
        client: client([
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: 'https://attacker.example' },
        ]),
        verify: (endpoint: string) => {
          verifiedAgainst.push(endpoint);
          return Promise.resolve(identity);
        },
      }),
    );
    expect(verifiedAgainst).toEqual([ENDPOINT]);
    expect(outcome).toMatchObject({ kind: 'attached', apiKey: ISSUED_KEY });
  });

  // The same value in the shape that would slip past an origin comparison but
  // not past `isSafeEndpoint`: a private address, over plaintext, which the
  // check on the typed URL is there to refuse and which nothing re-checks.
  it('does not present the credential to a private plaintext host the answer names', async () => {
    const verifiedAgainst: string[] = [];
    await attachByDeviceCode(
      deps({
        client: client([
          { status: 'issued', apiKey: ISSUED_KEY, endpoint: 'http://10.0.0.5:8080' },
        ]),
        verify: (endpoint: string) => {
          verifiedAgainst.push(endpoint);
          return Promise.resolve(identity);
        },
      }),
    );
    expect(verifiedAgainst).toEqual([ENDPOINT]);
  });

  it('gives up once the grant lifetime is spent', async () => {
    let clock = 0;
    const outcome = await attachByDeviceCode(
      deps({
        client: client([{ status: 'pending' }]),
        sleep: () => {
          clock += 60_000;
          return Promise.resolve();
        },
        now: () => clock,
      }),
    );
    expect(outcome).toMatchObject({ kind: 'declined' });
  });
});

describe('the confirmation before anything is written', () => {
  // THE STEP THAT CLOSES THE REVERSE HIJACK: someone who learned this machine's
  // code and approved it from THEIR organization would otherwise point this
  // machine at a control plane its owner never chose, with nothing on this side
  // looking wrong.
  it('shows which organization and account the credential belongs to', async () => {
    const io = prompter(['y']);
    await attachByDeviceCode(deps({ io }));
    expect(io.output()).toContain('Acme');
    expect(io.output()).toContain('dev@acme.test');
  });

  it('does not attach when the user declines', async () => {
    const outcome = await attachByDeviceCode(deps({ io: prompter(['n']) }));
    expect(outcome).toMatchObject({ kind: 'declined' });
  });

  it('treats anything but yes as a decline', async () => {
    for (const answer of ['', 'no', 'later', 'Y E S']) {
      const outcome = await attachByDeviceCode(deps({ io: prompter([answer]) }));
      expect(outcome.kind, answer).toBe('declined');
    }
  });

  // A run that cannot be asked must not be assumed to consent — the identity is
  // exactly what a non-interactive caller cannot check.
  it('refuses rather than assuming consent when it cannot ask', async () => {
    const outcome = await attachByDeviceCode(deps({ io: prompter([], false) }));
    expect(outcome).toMatchObject({ kind: 'declined' });
    expect(outcome.kind === 'declined' ? outcome.reason : '').toContain('--key-stdin');
  });

  it('fails rather than attaching when the credential cannot be verified', async () => {
    const outcome = await attachByDeviceCode(
      deps({ verify: () => Promise.reject(new Error('nope')) }),
    );
    expect(outcome).toMatchObject({ kind: 'failed' });
  });

  // The credential is what this whole flow exists to obtain, and the terminal
  // it lands in is scrolled, pasted into bug reports and captured by CI logs.
  it('never prints the credential', async () => {
    const io = prompter(['y']);
    const outcome = await attachByDeviceCode(deps({ io }));
    expect(outcome).toMatchObject({ kind: 'attached' });
    expectNoEchoOf(io.output(), ISSUED_KEY);
  });
});

describe('safeToOpen', () => {
  // `openUrl`'s win32 branch is `cmd /c start "" <url>`, and cmd re-parses that
  // line: node quotes an argument only when it holds a space, a tab or a quote,
  // so these arrive unquoted and SPLIT the command. This is the first caller
  // whose URL the deployment supplies rather than this repo building it.
  it.each(['&', '|', '^', '<', '>', '"'])('refuses a URL carrying %s', (ch) => {
    expect(safeToOpen(ENDPOINT, `${ENDPOINT}/attach?code=AB${ch}calc`)).toBeNull();
  });

  // The URL says where to go and approve. A user who typed one endpoint should
  // not have their browser opened somewhere else.
  it('refuses a URL pointing at another origin', () => {
    expect(safeToOpen(ENDPOINT, 'https://evil.test/attach?code=BCDF-GHJK')).toBeNull();
    expect(safeToOpen(ENDPOINT, 'https://aka.acme.test.evil.test/attach')).toBeNull();
    expect(safeToOpen(ENDPOINT, 'http://aka.acme.test/attach')).toBeNull();
  });

  it.each(['javascript:alert(1)', 'file:///etc/passwd', 'not a url'])('refuses %s', (candidate) => {
    expect(safeToOpen(ENDPOINT, candidate)).toBeNull();
  });

  it('accepts the ordinary prefilled link', () => {
    expect(safeToOpen(ENDPOINT, `${ENDPOINT}/attach?code=BCDF-GHJK`)).toBe(
      `${ENDPOINT}/attach?code=BCDF-GHJK`,
    );
  });

  it('does not launch a browser for a URL it refused', async () => {
    const openBrowser = vi.fn();
    await attachByDeviceCode(
      deps({
        openBrowser,
        client: client([{ status: 'issued', apiKey: ISSUED_KEY, endpoint: ENDPOINT }], {
          ...GRANT,
          verificationUriComplete: 'https://evil.test/attach?code=BCDF-GHJK',
        }),
      }),
    );
    expect(openBrowser).not.toHaveBeenCalled();
  });

  it('launches the browser for one it accepted', async () => {
    const openBrowser = vi.fn();
    await attachByDeviceCode(deps({ openBrowser }));
    expect(openBrowser).toHaveBeenCalledWith(`${ENDPOINT}/attach?code=BCDF-GHJK`);
  });
});
