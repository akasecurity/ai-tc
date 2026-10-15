import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  readAttachedIdentity,
  readBoundAttachedIdentity,
  recordValidatedWorkAccount,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { CLAUDE_ACCOUNT_ENV_NAMES } from '@akasecurity/plugin-sdk/account';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  ManagedSettings,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { fixtureEmail, workConfig } from '../../../plugin-sdk/test/helpers/transcript-builder.ts';
import type { ClaudeCodeLoginState } from '../../src/attached/status.ts';
import { claudeCodeLoginView, renderAttachedStatus } from '../../src/attached/status.ts';

// What `aka status` says on a personal device about work subscriptions: whether
// they are on and how to change that, whether an administrator fixed the choice,
// and why the Claude Code login signed in now does or does not count. Every
// identity is generated per run, and the Claude Code login is read from a home
// inside the test's own directory, never the developer's.

const ENDPOINT = 'https://plane.example.com';
const KEY = `test-${randomUUID()}`;
const ORG = randomUUID();
const CLAUDE_KEY = `claude:${ORG}`;
const OTHER_ORG = randomUUID();
const MEMBER = fixtureEmail(`member-${randomUUID().slice(0, 8)}`);
const SOMEONE_ELSE = fixtureEmail(`other-${randomUUID().slice(0, 8)}`);
const NOW = Date.parse('2026-10-14T09:00:00.000Z');
// `as const`: the credential writers take the version as the literal `2`.
const SCOPED_CREDENTIAL = {
  specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
} as const;

const FORWARDS = 'a work subscription for the attached user — its sessions forward from any folder';
const ON_LINE =
  '  work       subscriptions on — `aka unenroll --work-subscriptions` turns them off on this device';
const OFF_LINE =
  '  work       subscriptions off — you turned them off; `aka enroll --work-subscriptions` turns them back on';
const FIXED =
  "— fixed while an administrator manages this machine's connection; re-attaching makes it machine-wide";
const MANAGED_MACHINE =
  "  personal device  not available — an administrator manages this machine's connection, so it is attached machine-wide and there is no work-subscription opt-out";

let base: string;
let home: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-status-work-'));
  home = mkdtempSync(join(tmpdir(), 'aka-status-claude-home-'));
  // A key, a provider flag or a desktop login in the developer's own environment
  // would change every answer here.
  for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, '');
});

afterEach(() => {
  vi.unstubAllEnvs();
  removeTree(base);
  removeTree(home);
});

function attachScoped(scope: Readonly<Record<string, unknown>> = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label: 'Acme', attachedAt: '2026-10-01T09:00:00.000Z' },
      attachmentScope: {
        endpoint: ENDPOINT,
        tenantName: 'Acme',
        userEmail: MEMBER,
        entries: [],
        ...scope,
      },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), SCOPED_CREDENTIAL);
}

function attachMachineWide(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label: 'Acme', attachedAt: '2026-10-01T09:00:00.000Z' },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION,
    endpoint: ENDPOINT,
    apiKey: KEY,
  });
}

/** The record a scoped attach writes: this device knows the AKA user who attached it. */
function knowMember(): void {
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

/** Claude Code's login file: a Team plan on ORG under `email`, with `account` laid over it. */
function signIn(
  account: Readonly<Record<string, unknown>> = {},
  email: string = MEMBER,
  extra: Readonly<Record<string, unknown>> = {},
): void {
  writeFileSync(join(home, '.claude.json'), JSON.stringify(workConfig(ORG, email, account, extra)));
}

const governed = (): ManagedSettings =>
  ManagedSettings.parse({
    organization: 'Acme IT',
    values: { controlPlane: { endpoint: ENDPOINT } },
  });

const claudePaths = (): { home: string; managedSettings: string } => ({
  home,
  managedSettings: join(home, 'managed-settings.json'),
});

function render(
  options: { isTTY?: boolean; managedSettings?: ManagedSettings | null; readLogin?: boolean } = {},
): string {
  return renderAttachedStatus({
    base,
    settingsDir: settingsDirOf(base),
    dataDir: dataDirOf(base),
    isTTY: options.isTTY ?? true,
    managedSettings: options.managedSettings ?? null,
    ...(options.readLogin === false ? {} : { claudePaths: claudePaths() }),
    cwd: home,
    now: () => NOW,
  });
}

const lines = (out: string): string[] => out.split('\n');

describe('aka status — work subscriptions on a personal device', () => {
  it('says how to turn them off while they are on', () => {
    attachScoped();
    knowMember();
    expect(lines(render())).toContain(ON_LINE);
  });

  it.each<[string, unknown]>([
    ['off', 'off'],
    ['a value this version does not know', 'paused'],
  ])('says how to turn them back on for a stored %s', (_name, value) => {
    attachScoped({ workSubscriptions: value });
    knowMember();
    expect(lines(render())).toContain(OFF_LINE);
  });

  // A personal device whose connection an administrator began managing keeps its
  // scoped credential, and its choice, until it is re-attached; both commands
  // refuse there, so the line names neither.
  it.each<[string, Readonly<Record<string, unknown>>]>([
    ['on', {}],
    ['off', { workSubscriptions: 'off' }],
  ])(
    'says the choice is fixed while an administrator manages the connection (%s)',
    (state, scope) => {
      attachScoped(scope);
      knowMember();
      const out = render({ managedSettings: governed() });
      expect(lines(out)).toContain(`  work       subscriptions ${state} ${FIXED}`);
      expect(out).not.toContain('--work-subscriptions');
    },
  );

  it('adds one line, and only one, to a machine-wide attachment an administrator manages', () => {
    attachMachineWide();
    const managed = lines(render({ managedSettings: governed() }));
    const unmanaged = lines(render());
    expect(managed.filter((line) => !unmanaged.includes(line))).toEqual([MANAGED_MACHINE]);
  });

  it('adds no line to a machine-wide attachment no administrator manages', () => {
    attachMachineWide();
    signIn();
    const out = render();
    expect(out).not.toContain('personal device  not available');
    expect(out).not.toMatch(/^ {2}(work|this login) /m);
    expect(out).not.toContain('Claude Code —');
  });

  it('names work-subscription sessions on the mode line', () => {
    attachScoped();
    expect(lines(render())).toContain(
      '  mode       scoped (activity from what is enrolled, and from work-subscription sessions)',
    );
  });

  it('says an account enrolled without the coding-agent marker covers claude.ai chats only, and how to include Claude Code sessions', () => {
    attachScoped({
      entries: [{ kind: 'account', identity: CLAUDE_KEY, enrolledAt: '2026-10-02T09:00:00.000Z' }],
    });
    expect(render()).toContain(
      `             ${CLAUDE_KEY}, enrolled 2026-10-02 — claude.ai chats only — run \`aka enroll --account ${CLAUDE_KEY}\` again to include Claude Code sessions`,
    );
  });

  it('says an account enrolled for coding sessions covers Claude Code sessions', () => {
    attachScoped({
      entries: [
        {
          kind: 'account',
          identity: CLAUDE_KEY,
          enrolledAt: '2026-10-02T09:00:00.000Z',
          codingAgents: true,
        },
      ],
    });
    expect(render()).toContain(
      `             ${CLAUDE_KEY}, enrolled 2026-10-02 — covers Claude Code sessions`,
    );
  });

  it('points at aka enroll --account for a work subscription this device does not recognise', () => {
    attachScoped();
    expect(lines(render())).toContain(
      '             (run `aka enroll` inside a work repository to add it, or `aka enroll --account <key>` for a work subscription this device does not recognise)',
    );
  });
});

describe('aka status — this login', () => {
  it.each<[string, () => void, string]>([
    [
      'a Team plan under the attached address',
      () => {
        signIn();
      },
      FORWARDS,
    ],
    [
      'an Enterprise plan',
      () => {
        signIn({ organizationType: 'claude_enterprise' });
      },
      FORWARDS,
    ],
    [
      'a Max plan',
      () => {
        signIn({ organizationType: 'claude_max' });
      },
      'personal plan — sessions follow the repository rule',
    ],
    [
      'another address',
      () => {
        signIn({}, SOMEONE_ELSE);
      },
      'signed in with a different email than the AKA user who attached this device',
    ],
    [
      'a login that shows no plan',
      () => {
        signIn({ organizationType: undefined });
      },
      `plan not confirmed by Claude Code — run \`aka enroll --account ${CLAUDE_KEY}\` if this is a work subscription`,
    ],
    [
      'a provider flag',
      () => {
        signIn();
        vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '1');
      },
      'an API key or another provider is in use',
    ],
    ['no login file', () => undefined, 'login file not found'],
  ])('says why %s does or does not count', (_name, arrange, reason) => {
    attachScoped();
    knowMember();
    arrange();
    expect(lines(render())).toContain(`  this login Claude Code — ${reason}`);
  });

  it('says a recognised login is not sent while work subscriptions are off', () => {
    attachScoped({ workSubscriptions: 'off' });
    knowMember();
    signIn();
    expect(lines(render())).toContain(
      '  this login Claude Code — a work subscription for the attached user — not sent, because work subscriptions are off on this device',
    );
  });

  // Off on this device, a login that would not count anyway says why, not that
  // recognition is off.
  it('still says why a login would not count while work subscriptions are off', () => {
    attachScoped({ workSubscriptions: 'off' });
    knowMember();
    signIn({ organizationType: 'claude_max' });
    const out = render();
    expect(lines(out)).toContain(
      '  this login Claude Code — personal plan — sessions follow the repository rule',
    );
    expect(out).not.toContain('not sent, because work subscriptions are off');
  });

  it('says a learned organization still forwards when the login shows no plan', () => {
    attachScoped();
    knowMember();
    learn(CLAUDE_KEY);
    signIn({ organizationType: undefined });
    expect(lines(render())).toContain(`  this login Claude Code — ${FORWARDS}`);
  });

  it('says an account enrolled by hand forwards, whatever the plan or the address', () => {
    attachScoped({
      entries: [
        {
          kind: 'account',
          identity: CLAUDE_KEY,
          enrolledAt: '2026-10-02T09:00:00.000Z',
          codingAgents: true,
        },
      ],
    });
    knowMember();
    signIn({ organizationType: 'claude_max' }, SOMEONE_ELSE);
    expect(lines(render())).toContain(
      '  this login Claude Code — an account you enrolled by hand — its sessions forward from any folder',
    );
  });

  it('says the login is not checked while this device does not know who attached it', () => {
    attachScoped();
    signIn();
    expect(lines(render())).toContain(
      '  this login Claude Code — not checked — this device does not know yet which AKA user attached it',
    );
  });

  // A coding agent's own terminal output is recorded, and a reason can tell its
  // reader that the user has a personal plan.
  it('collapses the reason off a terminal, and prints no key', () => {
    attachScoped();
    knowMember();
    signIn({ organizationType: 'claude_max' });
    const out = render({ isTTY: false });
    expect(lines(out)).toContain('  this login details on an interactive terminal');
    expect(out).not.toContain('Claude Code —');
    expect(out).not.toContain('personal plan');
    expect(out).not.toContain(CLAUDE_KEY);
  });

  it('never prints the login address, the record digests or the scope tag', () => {
    attachScoped();
    knowMember();
    signIn();
    const record = readAttachedIdentity(dataDirOf(base));
    if (record === undefined) throw new Error('no identity record was written');
    const out = render();
    for (const hidden of [
      MEMBER,
      record.attachedUserDigest,
      record.credentialDigest,
      record.scopeTag,
    ]) {
      expect(out).not.toContain(hidden);
    }
  });

  it('reads no login file unless the caller names where to look', () => {
    attachScoped();
    knowMember();
    signIn();
    expect(render({ readLogin: false })).not.toMatch(/^ {2}this login /m);
  });

  it('prints no this-login line on a machine-wide attachment', () => {
    attachMachineWide();
    signIn();
    expect(render()).not.toMatch(/^ {2}this login /m);
  });
});

describe('claudeCodeLoginView', () => {
  const view = () =>
    claudeCodeLoginView({
      identity: readBoundAttachedIdentity(dataDirOf(base), ENDPOINT, SCOPED_CREDENTIAL),
      scope: { endpoint: ENDPOINT, entries: [] },
      endpoint: ENDPOINT,
      cwd: home,
      paths: claudePaths(),
    });

  it.each<[string, unknown, ClaudeCodeLoginState]>([
    ['a Team plan', 'claude_team', 'would-validate'],
    ['an Enterprise plan', 'claude_enterprise', 'would-validate'],
    ['a Pro plan', 'claude_pro', 'plan'],
    ['a plan type of null', null, 'plan-unconfirmed'],
  ])('reads %s (organizationType %j) as %s', (_name, organizationType, state) => {
    attachScoped();
    knowMember();
    signIn({ organizationType });
    expect(view().state).toBe(state);
  });

  it('reads a plan cached for another organization as not confirmed for this one', () => {
    attachScoped();
    knowMember();
    signIn({}, MEMBER, {
      clientDataCacheSlots: { newer: { data: null, at: NOW, org: OTHER_ORG } },
    });
    expect(view().state).toBe('plan-stale');
  });

  // The personal-plan guard in aka enroll reads the key and the plan state before
  // the device has learned who attached it.
  it('names the key and the plan state before the device knows who attached it', () => {
    attachScoped();
    signIn({ organizationType: 'claude_max' });
    expect(view()).toEqual({ key: CLAUDE_KEY, planState: 'other', state: 'attached-user-unknown' });
  });

  it('says there is no login when the file is absent', () => {
    attachScoped();
    knowMember();
    expect(view()).toEqual({ key: undefined, planState: undefined, state: 'absent' });
  });
});
