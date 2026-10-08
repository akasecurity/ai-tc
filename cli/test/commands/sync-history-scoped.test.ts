import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  readWorkspaceSettings,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as PluginRuntime from '@akasecurity/plugin-runtime';
import { runHistorySyncPass } from '@akasecurity/plugin-runtime';
import type { HistorySyncConsent } from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  HISTORY_SYNC_PAYLOAD_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runSyncHistory } from '../../src/commands/sync-history.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// What `aka sync-history` prints on a machine attached as a personal device,
// and that the machine-wide wording is byte for byte what it was.
//
// A personal device sends the history of the repositories enrolled on it and
// nothing else: the grant's seed marks only their captures, and the drain reads
// with the same scope. So on one, no line may describe the whole machine's
// backlog, and with nothing enrolled no line may leave "Sending" standing alone.
//
// The settings file and the credential file are real, in a temp home. Only the
// pass is replaced: `--run` would otherwise try to reach the deployment, and
// what is under test is the line printed beside the pass's report.
vi.mock('@akasecurity/plugin-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof PluginRuntime>()),
  runHistorySyncPass: vi.fn(),
}));

const ENDPOINT = 'https://aka.acme.test';
const OTHER_ENDPOINT = 'https://aka.other.test';
const TEST_KEY = 'not-a-real-key';
const ESC = String.fromCharCode(0x1b);
// A part of a recorded address that must never reach the screen.
const HIDDEN = 'hiddenpart';

let base: string;
let exits: number[];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-history-scoped-'));
  exits = [];
  vi.mocked(runHistorySyncPass).mockReset();
});

afterEach(() => {
  removeTree(base);
});

function recorder(): Prompter & { output: () => string; errors: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  const unscripted = (): Promise<string> => Promise.reject(new Error('unscripted prompt'));
  return {
    output: () => out.join(''),
    errors: () => err.join(''),
    out: (text) => {
      out.push(text);
    },
    err: (text) => {
      err.push(text);
    },
    isInteractive: true,
    ask: unscripted,
    askHidden: unscripted,
    readAllStdin: () => Promise.resolve(''),
  };
}

async function run(argv: string[]): Promise<ReturnType<typeof recorder>> {
  const io = recorder();
  await runSyncHistory(argv, {
    base,
    prompter: io,
    exit: (code: number) => {
      exits.push(code);
    },
  });
  return io;
}

type CredentialKind = 'scoped' | 'machine' | 'scoped-for-another-deployment' | 'none';

/**
 * Attach the temp home to ENDPOINT (or `options.endpoint`), labelled `Acme` unless a label is
 * given (`null` attaches with none), holding the credential `credential` names: a personal
 * device's, a machine-wide one's, a personal device's for another deployment (which this machine
 * cannot use), or none at all.
 */
function attach(
  credential: CredentialKind,
  options: { label?: string | null; endpoint?: string; consent?: HistorySyncConsent } = {},
): void {
  const endpoint = options.endpoint ?? ENDPOINT;
  const label = options.label === undefined ? 'Acme' : options.label;
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint,
        ...(label === null ? {} : { label }),
        attachedAt: '2026-10-01T09:00:00.000Z',
      },
      ...(options.consent === undefined ? {} : { historySyncConsent: options.consent }),
    },
    base,
    null,
  );
  if (credential === 'none') return;
  writeControlPlaneCredential(
    settingsDirOf(base),
    credential === 'machine'
      ? { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint, apiKey: TEST_KEY }
      : {
          specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
          mode: 'scoped',
          endpoint: credential === 'scoped' ? endpoint : OTHER_ENDPOINT,
          apiKey: TEST_KEY,
        },
  );
}

const consent = (over: Partial<HistorySyncConsent> = {}): HistorySyncConsent => ({
  acknowledgedAt: '2026-10-02T09:00:00.000Z',
  payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
  endpoint: ENDPOINT,
  ...over,
});
const STALE = { payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 };
const ELSEWHERE = { endpoint: OTHER_ENDPOINT };

// The machine-wide wording as it stood before personal devices had their own,
// copied out of the source. Literals rather than the source's own strings, so a
// change to the machine-wide text fails here instead of travelling with it.
const MACHINE = {
  usage: [
    'Usage: aka sync-history [--on | --off] [--run]',
    '',
    'Whether this machine may send the activity it recorded before attaching.',
    '',
    '  --on          Send it. Takes effect in the background, over later sessions.',
    '  --off         Do not send it. Stops anything not already sent.',
    '  --run         Send a slice now, in this process, instead of waiting.',
    '  --home <dir>  Use an alternate AKA home instead of ~/.aka.',
    '',
    'With no flag, prints what is currently in force. Activity recorded from now on',
    'is sent because this machine is attached; that is not what this grant covers,',
    'and turning it off does not stop it.',
  ].join('\n'),
  granted: [
    "Sending this machine's unsent activity to Acme.",
    'That is the activity recorded before it attached and anything a live send could not',
    'deliver, alike: for a captured prompt, reply or tool result, either one includes its',
    'text. A value in that text is masked only where the policy assigned to the detection',
    'that flagged it is redact or block; under monitor or warn it goes as it was seen, and',
    'no detection ships on redact or block. It goes in the background, a little at a time,',
    'starting with your next session. Anything already sent cannot be recalled.',
    '',
  ].join('\n'),
  revoked: [
    "Not sending this machine's unsent activity. Anything already sent stays sent —",
    'this stops what has not gone yet, and anything a live send cannot deliver is',
    'dropped rather than kept. Live sending is part of being attached and continues.',
    '',
  ].join('\n'),
  inForce: "Sending this machine's unsent activity to Acme.\n",
  notGranted: [
    "Not sending this machine's unsent activity to Acme.",
    'Run `aka sync-history --on` to send it.',
    '',
  ].join('\n'),
  stale: [
    "Not sending this machine's unsent activity to Acme: your grant predates a change.",
    'It now also covers the text of the activity recorded before this machine attached —',
    'not just what a live send failed to deliver afterward — in which a value is masked',
    'only where the detection that flagged it is set to redact or block, and no',
    'detection ships on redact or block.',
    'Run `aka sync-history --on` to grant it again.',
    '',
  ].join('\n'),
  elsewhere: [
    "Not sending this machine's unsent activity to Acme: the earlier grant no longer",
    'applies. Run `aka sync-history --on` to grant it again.',
    '',
  ].join('\n'),
};

// The personal-device wording, frozen the same way.
const SCOPED = {
  usage: [
    'Usage: aka sync-history [--on | --off] [--run]',
    '',
    'Whether this personal device may send what the repositories you enroll recorded before',
    'you enrolled them. No activity from any other repository, or from outside one, is sent.',
    '',
    '  --on          Send it. Takes effect in the background, over later sessions.',
    '  --off         Do not send it. Stops anything not already sent.',
    '  --run         Send a slice now, in this process, instead of waiting.',
    '  --home <dir>  Use an alternate AKA home instead of ~/.aka.',
    '',
    'With no flag, prints what is currently in force. Activity an enrolled repository',
    'records from now on is sent because this machine is attached; that is not what this',
    'grant covers, and turning it off does not stop it.',
  ].join('\n'),
  granted: [
    'Sending the unsent activity of the repositories enrolled here to Acme.',
    'No activity from any other repository, or from outside one, is sent, and with none enrolled',
    'no activity is sent at all: `aka enroll --list` shows what is enrolled. What is sent is some',
    'of what an enrolled repository recorded here before you enrolled it and anything a live',
    'send from one could not deliver, alike: for a captured prompt, reply or tool result,',
    'either one includes its text. A value in that text is masked only where the policy',
    'assigned to the detection that flagged it is redact or block; under monitor or warn it',
    'goes as it was seen, and no detection ships on redact or block. It goes in the',
    'background, a little at a time, starting with your next session. Anything already sent',
    'cannot be recalled.',
    '',
  ].join('\n'),
  revoked: [
    'Not sending the unsent activity of the repositories enrolled here. Anything already',
    'sent stays sent — this stops what has not gone yet, and anything a live send cannot',
    'deliver is dropped rather than kept. Live sending from enrolled repositories is part',
    'of being attached and continues.',
    '',
  ].join('\n'),
  inForce: [
    'Sending the unsent activity of the repositories enrolled here to Acme.',
    'With no repository enrolled, no activity is sent: `aka enroll --list` shows what is enrolled.',
    '',
  ].join('\n'),
  notGranted: [
    'Not sending the unsent activity of the repositories enrolled here to Acme.',
    'Run `aka sync-history --on` to send it.',
    '',
  ].join('\n'),
  stale: [
    'Not sending the unsent activity of the repositories enrolled here to Acme: your grant predates a change.',
    'It now also covers the text of what an enrolled repository recorded before you',
    'enrolled it — not just what a live send from one failed to deliver afterward — in',
    'which a value is masked only where the detection that flagged it is set to redact or',
    'block, and no detection ships on redact or block.',
    'Run `aka sync-history --on` to grant it again.',
    '',
  ].join('\n'),
  elsewhere: [
    'Not sending the unsent activity of the repositories enrolled here to Acme: the earlier grant no longer',
    'applies. Run `aka sync-history --on` to grant it again.',
    '',
  ].join('\n'),
};

describe('aka sync-history on a personal device', () => {
  it('grants for the enrolled repositories, and says no activity is sent with none enrolled', async () => {
    attach('scoped');
    const io = await run(['--on']);
    expect(exits).toEqual([]);
    expect(io.output()).toBe(SCOPED.granted);
    expect(readWorkspaceSettings(base).historySyncConsent?.endpoint).toBe(ENDPOINT);
  });

  it('revokes in the same terms', async () => {
    attach('scoped', { consent: consent() });
    const io = await run(['--off']);
    expect(exits).toEqual([]);
    expect(io.output()).toBe(SCOPED.revoked);
  });

  it('describes a grant in force', async () => {
    attach('scoped', { consent: consent() });
    expect((await run([])).output()).toBe(SCOPED.inForce);
  });

  it('describes no grant', async () => {
    attach('scoped');
    expect((await run([])).output()).toBe(SCOPED.notGranted);
  });

  it('describes a grant that predates a change to what is sent', async () => {
    attach('scoped', { consent: consent(STALE) });
    expect((await run([])).output()).toBe(SCOPED.stale);
  });

  it('describes a grant given to another deployment', async () => {
    attach('scoped', { consent: consent(ELSEWHERE) });
    expect((await run([])).output()).toBe(SCOPED.elsewhere);
  });

  it('prints the same line under a pass report', async () => {
    attach('scoped', { consent: consent() });
    vi.mocked(runHistorySyncPass).mockResolvedValue('ok');
    expect((await run(['--run'])).output()).toBe(
      `This pass sent what was waiting.\n${SCOPED.inForce}`,
    );
  });

  it('prints its own help when both answers are given', async () => {
    attach('scoped');
    const io = await run(['--on', '--off']);
    expect(exits).toEqual([2]);
    expect(io.errors()).toBe(`aka sync-history takes --on or --off, not both.\n\n${SCOPED.usage}`);
  });

  it('prints its own help for a flag it does not know', async () => {
    attach('scoped');
    const io = await run(['--bogus']);
    expect(exits).toEqual([2]);
    expect(io.errors()).toBe(SCOPED.usage);
  });

  // No `deps.base` here: the home comes from the command line alone. The flags
  // do not parse, and the help must still describe the home --home names, not
  // the default one.
  it('prints the help for the home --home names when another flag does not parse', async () => {
    attach('scoped');
    const io = recorder();
    await runSyncHistory(['--home', base, '--bogus'], {
      prompter: io,
      exit: (code: number) => {
        exits.push(code);
      },
    });
    expect(exits).toEqual([2]);
    expect(io.errors()).toBe(SCOPED.usage);
  });

  // A check on the frozen fixture, not on the source: it reads only the
  // literals above, so a later edit to SCOPED cannot bring the whole-machine
  // phrasing back into a case above unnoticed.
  it.each(Object.entries(SCOPED))(
    'the %s wording names the enrolled repositories only',
    (_name, text) => {
      expect(text).toContain('enroll');
      expect(text).not.toContain("this machine's unsent activity");
      expect(text).not.toContain('before it attached');
      expect(text).not.toContain('before attaching');
    },
  );
});

describe('aka sync-history on a machine-wide attachment keeps its wording', () => {
  it('grants', async () => {
    attach('machine');
    expect((await run(['--on'])).output()).toBe(MACHINE.granted);
  });

  it('revokes', async () => {
    attach('machine', { consent: consent() });
    expect((await run(['--off'])).output()).toBe(MACHINE.revoked);
  });

  it('describes a grant in force', async () => {
    attach('machine', { consent: consent() });
    expect((await run([])).output()).toBe(MACHINE.inForce);
  });

  it('describes no grant', async () => {
    attach('machine');
    expect((await run([])).output()).toBe(MACHINE.notGranted);
  });

  it('describes a grant that predates a change to what is sent', async () => {
    attach('machine', { consent: consent(STALE) });
    expect((await run([])).output()).toBe(MACHINE.stale);
  });

  it('describes a grant given to another deployment', async () => {
    attach('machine', { consent: consent(ELSEWHERE) });
    expect((await run([])).output()).toBe(MACHINE.elsewhere);
  });

  it('prints the same line under a pass report', async () => {
    attach('machine', { consent: consent() });
    vi.mocked(runHistorySyncPass).mockResolvedValue('ok');
    expect((await run(['--run'])).output()).toBe(
      `This pass sent what was waiting.\n${MACHINE.inForce}`,
    );
  });

  it('prints its help when both answers are given', async () => {
    attach('machine');
    const io = await run(['--on', '--off']);
    expect(exits).toEqual([2]);
    expect(io.errors()).toBe(`aka sync-history takes --on or --off, not both.\n\n${MACHINE.usage}`);
  });

  it('prints its help for a flag it does not know', async () => {
    attach('machine');
    const io = await run(['--bogus']);
    expect(exits).toEqual([2]);
    expect(io.errors()).toBe(MACHINE.usage);
  });

  // Anything short of a usable personal-device credential is described as
  // machine-wide: the wording that says more is sent, never less.
  it('keeps the machine-wide wording when the machine holds no credential', async () => {
    attach('none');
    expect((await run([])).output()).toBe(MACHINE.notGranted);
  });

  it('keeps the machine-wide wording when its personal-device credential is for another deployment', async () => {
    attach('scoped-for-another-deployment');
    expect((await run([])).output()).toBe(MACHINE.notGranted);
  });
});

// The name comes from settings.json: a label typed at attach, an administrator's
// overlay, or the endpoint, and the schema refuses no character in any of them.
describe('aka sync-history prints the deployment name through the terminal strip', () => {
  it.each(['scoped', 'machine'] as const)(
    'strips control characters from the name on a %s attachment',
    async (credential) => {
      attach(credential, { label: `Acme${ESC}[2J`, consent: consent() });
      const out = (await run([])).output();
      expect(out).not.toContain(ESC);
      expect(out).toContain('to Acme[2J.\n');
    },
  );

  it('strips them from the grant line too', async () => {
    attach('machine', { label: `Acme${ESC}[2J` });
    const out = (await run(['--on'])).output();
    expect(out).not.toContain(ESC);
    expect(out.split('\n')[0]).toBe("Sending this machine's unsent activity to Acme[2J.");
  });

  it('prints a name of 200 characters whole', async () => {
    const name = 'x'.repeat(200);
    attach('machine', { label: name });
    expect((await run([])).output()).toBe(
      `Not sending this machine's unsent activity to ${name}.\nRun \`aka sync-history --on\` to send it.\n`,
    );
  });

  it('cuts a longer name at 200 characters', async () => {
    attach('machine', { label: 'x'.repeat(201) });
    expect((await run([])).output()).toBe(
      `Not sending this machine's unsent activity to ${'x'.repeat(200)}….\nRun \`aka sync-history --on\` to send it.\n`,
    );
  });
});

// With no label the name IS the settings address. That address is checked when
// settings are saved through the product, not when the file is edited by hand or
// an overlay pins it, so a plain control-character strip would let userinfo, a
// query or a fragment reach the terminal. The rule is the one `aka status`
// follows for its plane line.
describe('aka sync-history prints a label-less deployment by its address', () => {
  // The edit the product's own save path would refuse: the address is rewritten
  // in the stored file after the attach.
  function editEndpoint(endpoint: string): void {
    const file = join(settingsDirOf(base), SETTINGS_FILENAME);
    const stored = JSON.parse(readFileSync(file, 'utf8')) as {
      controlPlane: Record<string, unknown>;
    };
    stored.controlPlane.endpoint = endpoint;
    writeFileSync(file, JSON.stringify(stored));
  }

  it.each<[string, string, string]>([
    ['a username', `https://${HIDDEN}@aka.acme.test`, 'https://aka.acme.test, rest not shown'],
    ['a query', `https://aka.acme.test/?t=${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['a fragment', `https://aka.acme.test/#${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['no scheme', `${HIDDEN}@aka.acme.test`, 'address not shown'],
  ])(
    'names a deployment whose address has %s without echoing it',
    async (_name, endpoint, shown) => {
      attach('machine', { label: null });
      editEndpoint(endpoint);
      const out = (await run([])).output();
      expect(out).toContain(`Not sending this machine's unsent activity to ${shown}.\n`);
      expect(out).not.toContain(HIDDEN);
    },
  );

  it.each(['https://aka.acme.test', 'https://aka.acme.test/', 'https://AKA.acme.test'])(
    'prints the clean address %s as stored',
    async (endpoint) => {
      attach('machine', { label: null, endpoint });
      expect((await run([])).output()).toBe(
        `Not sending this machine's unsent activity to ${endpoint}.\nRun \`aka sync-history --on\` to send it.\n`,
      );
    },
  );
});
