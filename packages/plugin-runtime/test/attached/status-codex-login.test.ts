import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  readAttachedIdentity,
  recordValidatedWorkAccount,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { CODEX_ACCOUNT_ENV_NAMES } from '@akasecurity/plugin-sdk/account';
import { ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { writeCodexAuth } from '../../../plugin-sdk/test/helpers/fake-jwt.ts';
import { fixtureEmail } from '../../../plugin-sdk/test/helpers/transcript-builder.ts';
import type { CodexLoginState } from '../../src/attached/status.ts';
import { codexLoginView, renderAttachedStatus } from '../../src/attached/status.ts';

// What `aka status` says about the Codex login signed in now, and the view it
// is drawn from. Every identity is generated per run, and the login file is
// written into a home inside the test's own directory, never the developer's.

const ENDPOINT = 'https://plane.example.com';
const KEY = `test-${randomUUID()}`;
const WORKSPACE = randomUUID();
const CHATGPT_KEY = `chatgpt:${WORKSPACE}`;
const MEMBER = fixtureEmail(`member-${randomUUID().slice(0, 8)}`);
const SOMEONE_ELSE = fixtureEmail(`other-${randomUUID().slice(0, 8)}`);
const NOW = 1_800_000_000_000;
const STAMP = new Date(NOW).toISOString();
// `as const`: the credential writers take the version as the literal `2`.
const SCOPED_CREDENTIAL = {
  specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
} as const;

let base: string;
let codexHome: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-status-codex-'));
  codexHome = mkdtempSync(join(tmpdir(), 'aka-status-codex-home-'));
  // A key, a token or a gateway in the developer's own environment would veto every login here.
  for (const name of CODEX_ACCOUNT_ENV_NAMES) vi.stubEnv(name, '');
});

afterEach(() => {
  vi.unstubAllEnvs();
  removeTree(base);
  removeTree(codexHome);
});

function signIn(plan: unknown, email: string = MEMBER) {
  return writeCodexAuth(codexHome, {
    accountId: WORKSPACE,
    email,
    ...(plan === undefined ? {} : { plan }),
  });
}

/** A scoped attachment; the device knows who attached it unless `known` is false. */
function attachScoped(
  entries: unknown[] = [],
  extra: Record<string, unknown> = {},
  known = true,
): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label: 'Acme', attachedAt: STAMP },
      attachmentScope: {
        endpoint: ENDPOINT,
        tenantName: 'Acme',
        userEmail: MEMBER,
        entries,
        ...extra,
      },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), SCOPED_CREDENTIAL);
  if (!known) return;
  writeAttachedIdentity(dataDirOf(base), {
    endpoint: ENDPOINT,
    apiKey: KEY,
    tenantName: 'Acme',
    userEmail: MEMBER,
  });
}

function learn(key: string): void {
  recordValidatedWorkAccount(dataDirOf(base), {
    endpoint: ENDPOINT,
    credential: SCOPED_CREDENTIAL,
    key,
  });
}

function render(isTTY = true): string {
  return renderAttachedStatus({
    base,
    settingsDir: settingsDirOf(base),
    dataDir: dataDirOf(base),
    codexHome,
    isTTY,
    now: () => NOW,
  });
}

/** The Codex line of a status block, or an empty string when it has none. */
const codexLine = (text: string): string =>
  text.split('\n').find((line) => line.includes('Codex —')) ?? '';

describe('aka status — the Codex login', () => {
  it.each<[string, () => void, string]>([
    [
      'a workspace plan under the attached address',
      () => {
        signIn('business');
      },
      'Codex — a work subscription for the attached user — its new threads forward from any folder',
    ],
    [
      'a personal plan',
      () => {
        signIn('plus');
      },
      'Codex — not a ChatGPT workspace plan — threads follow the repository rule',
    ],
    [
      'the service-account plan',
      () => {
        signIn('enterprise_cbp_automation');
      },
      'Codex — not a ChatGPT workspace plan — threads follow the repository rule',
    ],
    [
      'another address',
      () => {
        signIn('business', SOMEONE_ELSE);
      },
      'Codex — signed in with a different email than the AKA user who attached this device',
    ],
    [
      'a login that shows no plan',
      () => {
        signIn(undefined);
      },
      `Codex — plan not shown in Codex's login — run \`aka enroll --account ${CHATGPT_KEY}\` if this is a work subscription`,
    ],
    ['no login file', () => undefined, 'Codex — login file not found'],
  ])('says why %s does or does not count', (_name, arrange, line) => {
    attachScoped();
    arrange();
    expect(codexLine(render())).toContain(line);
  });

  it('says a recognised login is not sent while work subscriptions are off', () => {
    attachScoped([], { workSubscriptions: 'off' });
    signIn('business');
    expect(codexLine(render())).toContain(
      'Codex — a work subscription for the attached user — not sent, because work subscriptions are off on this device',
    );
  });

  it('says an account enrolled by hand forwards, whatever the plan or address', () => {
    attachScoped([
      {
        kind: 'account',
        identity: CHATGPT_KEY,
        enrolledAt: STAMP,
        codingAgents: true,
      },
    ]);
    signIn('plus', SOMEONE_ELSE);
    expect(codexLine(render())).toContain(
      'Codex — an account you enrolled by hand — its new threads forward from any folder',
    );
  });

  it('says nothing is checked until this device knows who attached it', () => {
    attachScoped([], {}, false);
    signIn('business');
    expect(codexLine(render())).toContain('Codex — not checked until this machine syncs');
  });

  it('collapses the reason off a terminal, as the Claude Code line does', () => {
    attachScoped();
    signIn('business');
    const shown = render(false);
    expect(shown).toContain('  this login details on an interactive terminal');
    expect(codexLine(shown)).toBe('');
    expect(shown.includes(CHATGPT_KEY)).toBe(false);
  });

  it('never prints the login address, the plan string or anything the login file holds', () => {
    attachScoped();
    const login = signIn('business');
    const shown = render();
    expect(shown.includes(MEMBER)).toBe(false);
    expect(shown.includes('business')).toBe(false);
    for (const secret of [login.jwt.token, ...login.secrets]) {
      expect(shown.includes(secret)).toBe(false);
    }
  });

  it('prints the veto line under a key, and names neither the workspace nor its plan', () => {
    attachScoped();
    signIn('plus');
    vi.stubEnv('CODEX_API_KEY', randomUUID());
    const shown = render();
    expect(codexLine(shown)).toContain('Codex — an API key or another provider is in use');
    expect(shown.includes(CHATGPT_KEY)).toBe(false);
    expect(codexLine(shown).includes('workspace plan')).toBe(false);
  });

  it('prints the Codex line, as no login file, when the caller asks with no usable home', () => {
    attachScoped();
    signIn('business');
    const shown = renderAttachedStatus({
      base,
      settingsDir: settingsDirOf(base),
      dataDir: dataDirOf(base),
      codexHome: null,
      isTTY: true,
      now: () => NOW,
    });
    expect(codexLine(shown)).toContain('Codex — login file not found');
  });

  it('reads no login and prints no Codex line unless the caller names a Codex home', () => {
    attachScoped();
    signIn('business');
    const shown = renderAttachedStatus({
      base,
      settingsDir: settingsDirOf(base),
      dataDir: dataDirOf(base),
      isTTY: true,
      now: () => NOW,
    });
    expect(codexLine(shown)).toBe('');
    expect(shown.includes('  this login')).toBe(false);
  });
});

describe('codexLoginView', () => {
  const SCOPE = { endpoint: ENDPOINT, tenantName: 'Acme', userEmail: MEMBER, entries: [] };

  /** The view of an attachment, read the way `aka status` reads it. */
  function view(scope: unknown = SCOPE) {
    return codexLoginView({
      identity: readAttachedIdentity(dataDirOf(base)),
      scope,
      endpoint: ENDPOINT,
      codexHome,
    });
  }

  it.each<[string, unknown, CodexLoginState]>([
    ['a team plan', 'team', 'would-validate'],
    ['the hc alias', 'hc', 'would-validate'],
    ['a mixed-case plan', 'Team', 'plan'],
    ['a plan that is not a string', 42, 'plan'],
    ['no plan claim', undefined, 'plan-unconfirmed'],
  ])('reads %s as %s', (_name, plan, state) => {
    attachScoped();
    signIn(plan);
    expect(view().state).toBe(state);
  });

  // The key and the plan state are read before the address can be compared, so the
  // personal-plan guard in aka enroll holds before the first sync.
  it('names the login but checks nothing while the device does not know who attached it', () => {
    signIn('plus');
    const read = codexLoginView({
      identity: undefined,
      scope: undefined,
      endpoint: ENDPOINT,
      codexHome,
    });
    expect(read.key === CHATGPT_KEY).toBe(true);
    expect(read.planState).toBe('other');
    expect(read.state).toBe('attached-user-unknown');
  });

  it('names the key and the plan state, never the plan', () => {
    attachScoped();
    signIn('business');
    const read = view();
    expect(read.key === CHATGPT_KEY).toBe(true);
    expect(read.planState).toBe('company');
    expect(read.state).toBe('would-validate');
    expect(Object.keys(read).sort()).toEqual(['key', 'planState', 'state']);
  });

  it('reads a work account this device learned as remembered', () => {
    attachScoped();
    signIn('business');
    learn(CHATGPT_KEY);
    expect(view().state).toBe('remembered');
  });

  it('reads a ninth work account as over the cap', () => {
    attachScoped();
    signIn('business');
    for (let i = 0; i < 8; i += 1) learn(`chatgpt:${randomUUID()}`);
    expect(view().state).toBe('cap-reached');
  });

  it('reads a login that would be over the cap as off while work subscriptions are off', () => {
    attachScoped();
    signIn('business');
    for (let i = 0; i < 8; i += 1) learn(`chatgpt:${randomUUID()}`);
    expect(view({ ...SCOPE, workSubscriptions: 'off' }).state).toBe('off');
  });

  it('reads a scope that is not a record as work subscriptions off', () => {
    attachScoped();
    signIn('business');
    expect(view(42).state).toBe('off');
  });

  it('reads a personal plan as one while work subscriptions are off', () => {
    attachScoped();
    signIn('plus');
    expect(view({ ...SCOPE, workSubscriptions: 'off' }).state).toBe('plan');
  });

  it('answers unreadable, and does not throw, when the stored record cannot be read', () => {
    attachScoped();
    signIn('business');
    const stored = readAttachedIdentity(dataDirOf(base));
    if (stored === undefined) throw new Error('the identity record was not written');
    const broken = Object.defineProperty({ ...stored }, 'workAccounts', {
      get: () => {
        throw new Error('the record cannot be read');
      },
    });
    const read = codexLoginView({
      identity: broken,
      scope: SCOPE,
      endpoint: ENDPOINT,
      codexHome,
    });
    expect(read.state).toBe('unreadable');
    expect(read.key).toBeUndefined();
  });

  describe('under a key, a token or a gateway in the Codex environment', () => {
    const vetoes: [string, () => void][] = [
      [
        'a key',
        () => {
          vi.stubEnv('CODEX_API_KEY', randomUUID());
        },
      ],
      [
        'a token',
        () => {
          vi.stubEnv('CODEX_ACCESS_TOKEN', randomUUID());
        },
      ],
      [
        'a gateway address',
        () => {
          vi.stubEnv('OPENAI_BASE_URL', 'https://gateway.example.com/v1');
        },
      ],
    ];

    it.each(vetoes)('reads %s as a veto, and still names the login and its plan', (_name, set) => {
      attachScoped();
      signIn('plus');
      set();
      const read = view();
      expect(read.state).toBe('veto');
      expect(read.key === CHATGPT_KEY).toBe(true);
      expect(read.planState).toBe('other');
      expect(Object.keys(read).sort()).toEqual(['key', 'planState', 'state']);
    });

    it('names a workspace plan as one, so the veto never reads as a personal plan', () => {
      attachScoped();
      signIn('business');
      vi.stubEnv('CODEX_API_KEY', randomUUID());
      expect(view().planState).toBe('company');
    });

    it('names the login before the device knows who attached it', () => {
      signIn('plus');
      vi.stubEnv('CODEX_API_KEY', randomUUID());
      const read = codexLoginView({
        identity: undefined,
        scope: undefined,
        endpoint: ENDPOINT,
        codexHome,
      });
      expect(read.state).toBe('veto');
      expect(read.key === CHATGPT_KEY).toBe(true);
      expect(read.planState).toBe('other');
    });

    it('names nothing when there is no login to read, and still reads as a veto', () => {
      attachScoped();
      vi.stubEnv('CODEX_API_KEY', randomUUID());
      const read = view();
      expect(read.state).toBe('veto');
      expect(read.key).toBeUndefined();
      expect(read.planState).toBeUndefined();
    });

    it('names nothing for a login of another mode, and still reads as a veto', () => {
      attachScoped();
      writeCodexAuth(codexHome, { accountId: WORKSPACE, email: MEMBER, authMode: 'apikey' });
      vi.stubEnv('CODEX_API_KEY', randomUUID());
      const read = view();
      expect(read.state).toBe('veto');
      expect(read.key).toBeUndefined();
    });

    it('names nothing when no Codex home is given, and still reads as a veto', () => {
      attachScoped();
      vi.stubEnv('CODEX_API_KEY', randomUUID());
      const read = codexLoginView({
        identity: readAttachedIdentity(dataDirOf(base)),
        scope: SCOPE,
        endpoint: ENDPOINT,
        codexHome: undefined,
      });
      expect(read.state).toBe('veto');
      expect(read.key).toBeUndefined();
    });
  });

  it('reads a login of another mode as unreadable', () => {
    attachScoped();
    writeCodexAuth(codexHome, { accountId: WORKSPACE, email: MEMBER, authMode: 'apikey' });
    expect(view().state).toBe('unreadable');
  });

  it('reads a missing login file as absent', () => {
    attachScoped();
    expect(view().state).toBe('absent');
  });
});
