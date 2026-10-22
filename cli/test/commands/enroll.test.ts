import { randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  DB_FILENAME,
  readAttachedIdentity,
  recordDetectedWebAccount,
  recordValidatedWorkAccount,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { attachmentScopeLines, WORK_SUBSCRIPTION_COMMANDS } from '@akasecurity/plugin-runtime';
import { CLAUDE_ACCOUNT_ENV_NAMES, CODEX_ACCOUNT_ENV_NAMES } from '@akasecurity/plugin-sdk/account';
import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  connectionRefusalMessage,
  HISTORY_SYNC_PAYLOAD_VERSION,
  ManagedSettings,
  SOURCE_TOOL,
  WEB_CHAT_ACCOUNT_CONSENT_VERSION,
  WEB_CHAT_CAPTURE_CONSENT_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Reached by relative path: the seam is deliberately not re-exported from the
// package barrel, the same way the managed-settings pin is not.
import { UNSAFE_TEST_ONLY_setSshHostAliases } from '../../../packages/persistence/src/ssh-hosts.ts';
import { writeCodexAuth } from '../../../packages/plugin-sdk/test/helpers/fake-jwt.ts';
import {
  fixtureEmail,
  workConfig,
} from '../../../packages/plugin-sdk/test/helpers/transcript-builder.ts';
import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { COMMAND_SPECS } from '../../src/command-manifest.ts';
import { runAttach, runStatus } from '../../src/commands/attach.ts';
import { defaultLabel, quotedForShell, runEnroll, runUnenroll } from '../../src/commands/enroll.ts';
import type { ExternalSpawn } from '../../src/lib/external-dispatch.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { main } from '../../src/main.ts';

// `aka enroll` / `aka unenroll` / `aka enroll --list` against a real settings
// file and a real credential file in a temp home.
//
// Three seams in the persistence module, all pass-through until a case arms
// them. `seedEnrolledCapturesOwed` records what it was asked to queue and
// answers `seed.answer`, so the consent gate and the copy are pinned without a
// store (the queue itself is pinned in @akasecurity/persistence's own suite).
// `applyOnboarding` counts its calls, can run `settingsWrite.before` once ahead
// of the real write (a concurrent re-attach landing between the command's check
// and its write), or throw `settingsWrite.failure` (a write that fails).
// `forgetWorkAccounts` answers false without touching the record while
// `forgetSeam.fails` is set, as it does when the record's lock cannot be taken.
interface SeedCall {
  dataDir: string;
  keys: string[];
}
const seed = vi.hoisted((): { calls: SeedCall[]; answer: number | undefined } => ({
  calls: [],
  answer: 0,
}));
const forgetSeam = vi.hoisted((): { fails: boolean } => ({ fails: false }));
const settingsWrite = vi.hoisted(
  (): { calls: number; before: (() => void) | undefined; failure: Error | undefined } => ({
    calls: 0,
    before: undefined,
    failure: undefined,
  }),
);

vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    seedEnrolledCapturesOwed: (dataDir: string, keys: readonly string[]): number | undefined => {
      seed.calls.push({ dataDir, keys: [...keys] });
      return seed.answer;
    },
    forgetWorkAccounts: (
      ...args: Parameters<typeof actual.forgetWorkAccounts>
    ): ReturnType<typeof actual.forgetWorkAccounts> =>
      forgetSeam.fails ? false : actual.forgetWorkAccounts(...args),
    applyOnboarding: (
      ...args: Parameters<typeof actual.applyOnboarding>
    ): ReturnType<typeof actual.applyOnboarding> => {
      settingsWrite.calls += 1;
      if (settingsWrite.failure !== undefined) throw settingsWrite.failure;
      const before = settingsWrite.before;
      settingsWrite.before = undefined;
      before?.();
      return actual.applyOnboarding(...args);
    },
  };
});

const ENDPOINT = 'https://aka.acme.test';
const OTHER_ENDPOINT = 'https://aka.other.test';
const PINNED_ENDPOINT = 'https://aka.pinned.test';
const TEST_KEY = 'not-a-real-key';
const NOW = '2026-10-07T09:30:00.000Z';
const WORK_REPO = 'github.com/acme/payments-api';
const WORK_REMOTE = 'https://github.com/acme/payments-api.git';
// The scp form, written without a user name; git reads `host:path` the same way.
const WORK_REMOTE_SCP = 'github.com:acme/payments-api.git';
const SECOND_REPO = 'github.com/acme/billing-worker';
// The binding a scoped attach records. The account is any printable string to
// the schema; nothing here reads it as an address.
const MEMBER = { tenantName: 'Acme', userEmail: 'member-of-acme' } as const;
const ESC = String.fromCharCode(0x1b);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
const GRINNING_FACE = String.fromCodePoint(0x1f600);

let base: string;
let work: string;
let claudeHome: string;
let codexHome: string;
let exits: number[];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-enroll-home-'));
  work = mkdtempSync(join(tmpdir(), 'aka-enroll-work-'));
  claudeHome = mkdtempSync(join(tmpdir(), 'aka-enroll-claude-'));
  codexHome = mkdtempSync(join(tmpdir(), 'aka-enroll-codex-'));
  // A key, a provider flag or a desktop login in the developer's own environment
  // would change what the Claude Code login check answers.
  for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, '');
  // A key, a token or a gateway there would veto every Codex login.
  for (const name of CODEX_ACCOUNT_ENV_NAMES) vi.stubEnv(name, '');
  exits = [];
  seed.calls = [];
  seed.answer = 0;
  forgetSeam.fails = false;
  settingsWrite.calls = 0;
  settingsWrite.before = undefined;
  settingsWrite.failure = undefined;
});

afterEach(() => {
  removeTree(base);
  removeTree(work);
  removeTree(claudeHome);
  removeTree(codexHome);
  vi.unstubAllEnvs();
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

function deps(
  io: ReturnType<typeof recorder>,
  options: { cwd?: string; managedSettings?: ManagedSettings | null; now?: Date } = {},
) {
  return {
    base,
    claudePaths: { home: claudeHome, managedSettings: join(claudeHome, 'managed-settings.json') },
    codexHome,
    prompter: io,
    managedSettings: options.managedSettings ?? null,
    exit: (code: number) => {
      exits.push(code);
    },
    cwd: () => options.cwd ?? work,
    now: () => options.now ?? new Date(NOW),
  };
}

function attach(
  options: {
    mode?: 'machine' | 'scoped';
    scope?: unknown;
    label?: string;
    /** The deployment the settings name. The credential is for it too, unless it is given. */
    endpoint?: string;
    credentialEndpoint?: string;
    extra?: Partial<WorkspaceSettings>;
  } = {},
): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: options.endpoint ?? ENDPOINT,
        label: options.label ?? 'Acme',
        attachedAt: '2026-10-01T09:00:00.000Z',
      },
      ...(options.scope === undefined ? {} : { attachmentScope: options.scope }),
      ...options.extra,
    },
    base,
    null,
  );
  const endpoint = options.credentialEndpoint ?? options.endpoint ?? ENDPOINT;
  writeControlPlaneCredential(
    settingsDirOf(base),
    (options.mode ?? 'scoped') === 'scoped'
      ? {
          specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
          mode: 'scoped',
          endpoint,
          apiKey: TEST_KEY,
        }
      : { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint, apiKey: TEST_KEY },
  );
  // The setup above is not the command's own write; the count starts afresh.
  settingsWrite.calls = 0;
}

// A stored entry. `null` leaves the label off; leaving the argument out gives
// the slug label an enrollment of the work repository carries.
function enrolled(identity = WORK_REPO, label: string | null = 'payments-api') {
  return { kind: 'repo', identity, enrolledAt: NOW, ...(label === null ? {} : { label }) };
}

function fresh(entries: unknown[] = []) {
  return { endpoint: ENDPOINT, ...MEMBER, entries };
}

function consent(overrides: { payloadVersion?: number; endpoint?: string } = {}) {
  return {
    historySyncConsent: {
      acknowledgedAt: '2026-10-01T09:00:00.000Z',
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: ENDPOINT,
      ...overrides,
    },
  };
}

function stored(): Record<string, unknown> | undefined {
  const file = join(settingsDirOf(base), SETTINGS_FILENAME);
  if (!existsSync(file)) return undefined;
  return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
}

const storedScope = (): unknown => stored()?.attachmentScope;

function identities(): string[] {
  const scope = storedScope() as { entries?: { identity: string }[] } | undefined;
  return (scope?.entries ?? []).map((entry) => entry.identity);
}

// A checkout as git lays one out on disk: `.git/config` with an origin remote.
// The attribution reads files only, so no `git` binary is involved.
function gitRepo(dir: string, remote?: string): string {
  mkdirSync(join(dir, '.git'), { recursive: true });
  const origin = remote === undefined ? '' : `[remote "origin"]\n\turl = ${remote}\n`;
  writeFileSync(join(dir, '.git', 'config'), `[core]\n\tbare = false\n${origin}`);
  return dir;
}

// A linked worktree: a `.git` FILE pointing at an admin dir whose `commondir`
// leads back to the main checkout's `.git`.
function linkedWorktree(checkout: string, dir: string): string {
  const admin = join(checkout, '.git', 'worktrees', 'payments-api-review');
  mkdirSync(admin, { recursive: true });
  writeFileSync(join(admin, 'commondir'), '../..\n');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, '.git'), `gitdir: ${admin}\n`);
  return dir;
}

// A submodule: a `.git` FILE pointing into the superproject's
// `.git/modules/<name>`, which holds the submodule's own config and remote.
function submodule(superproject: string, name: string, remote: string): string {
  const gitdir = join(superproject, '.git', 'modules', name);
  mkdirSync(gitdir, { recursive: true });
  writeFileSync(join(gitdir, 'config'), `[remote "origin"]\n\turl = ${remote}\n`);
  const dir = join(superproject, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, '.git'), `gitdir: ../.git/modules/${name}\n`);
  return dir;
}

// The connection pinned by an administrator, nothing locked: the shape of a
// fleet-managed machine, which `aka attach --scoped` refuses.
function governedBy(organization = 'Acme IT'): ManagedSettings {
  return ManagedSettings.parse({
    organization,
    values: { controlPlane: { endpoint: ENDPOINT } },
  });
}

describe('aka enroll — usage', () => {
  it.each<[string, readonly string[]]>([
    ['a path and --repo together', ['payments-api', '--repo', WORK_REPO]],
    ['two paths', ['payments-api', 'billing-worker']],
    ['--list with a repository', ['--list', '--repo', WORK_REPO]],
    ['--repo with no value', ['--repo']],
    ['--repo with an empty value', ['--repo=']],
    ['--repo with only spaces', ['--repo', '   ']],
    ['an option it does not know', ['--everything']],
    ['a path and --account together', ['payments-api', '--account', 'claude:x']],
    ['--repo and --account together', ['--repo', WORK_REPO, '--account', 'claude:x']],
    ['--account with an empty value', ['--account=']],
    ['--account with only spaces', ['--account', '   ']],
    ['--list with an account', ['--list', '--account', 'claude:x']],
    ['--list-detected with a repository', ['--list-detected', '--repo', WORK_REPO]],
    ['--list and --list-detected together', ['--list', '--list-detected']],
    ['--work-subscriptions with a repository', ['--work-subscriptions', '--repo', WORK_REPO]],
    ['--work-subscriptions with --list', ['--work-subscriptions', '--list']],
    ['--work-subscriptions with an account', ['--work-subscriptions', '--account', 'claude:x']],
    ['--yes with no account', ['--yes']],
    ['--yes with a repository', ['--yes', '--repo', WORK_REPO]],
  ])('refuses %s as a usage error, before reading anything', async (_name, argv) => {
    const io = recorder();
    expect(await runEnroll(argv, deps(io))).toBe(2);
    expect(exits).toEqual([2]);
    expect(io.errors()).toContain('Usage: aka enroll');
    expect(stored()).toBeUndefined();
  });

  it('says the scoped limit applies to activity, and that the report and policy pull do not stop', async () => {
    const io = recorder();
    expect(await runEnroll(['--everything'], deps(io))).toBe(2);
    expect(flat(io.errors())).toContain(
      "activity is sent to the deployment only from the repositories and Claude accounts enrolled here (an account's Claude Code sessions and its claude.ai chat replies), and from Claude Code and Codex sessions signed in to a work subscription (a Claude Team or Enterprise plan, or a ChatGPT Business, Team, Enterprise or Edu plan) that this device recognises; activity anywhere else stays on this machine.",
    );
    // Only the ChatGPT workspace plans count, so the usage never names a service account.
    expect(io.errors()).not.toMatch(/service account|enterprise_cbp_automation/i);
    expect(flat(io.errors())).toContain(
      "The policy pull, the sighting-key fetch, the command check and the device report are not limited to them: the report's finding counts and dates are for everything recorded on the machine.",
    );
    expect(io.errors()).not.toContain('across every repository');
    expect(io.errors()).not.toContain('only activity in');
  });

  it('limits what unenroll promises in its usage to sessions and scans started afterwards', async () => {
    const io = recorder();
    expect(await runUnenroll(['--everything'], deps(io))).toBe(2);
    expect(flat(io.errors())).toContain(
      'Stops sending a repository or a Claude account from a scoped attachment: sessions, scans and chats started afterwards keep its activity on this machine, except a Claude Code or Codex session signed in to a recognised work subscription or to another account enrolled by hand, which forwards from any folder.',
    );
    expect(io.errors()).not.toContain('from then on');
  });

  it('aka unenroll takes no --list', async () => {
    const io = recorder();
    expect(await runUnenroll(['--list'], deps(io))).toBe(2);
    expect(io.errors()).toContain('Usage: aka unenroll');
  });

  it('aka unenroll takes no --list-detected', async () => {
    const io = recorder();
    expect(await runUnenroll(['--list-detected'], deps(io))).toBe(2);
    expect(io.errors()).toContain('Usage: aka unenroll');
  });

  it('aka unenroll takes no --yes', async () => {
    const io = recorder();
    expect(await runUnenroll(['--account', 'claude:x', '--yes'], deps(io))).toBe(2);
    expect(io.errors()).toContain('Usage: aka unenroll');
  });

  // The usage text is printed whoever asks, including on a machine where an
  // administrator governs the connection and a scoped attach is refused, so it
  // can never be the place that suggests one.
  it.each<[string, ManagedSettings | null]>([
    ['an unmanaged machine', null],
    ['a machine whose connection is governed', governedBy()],
  ])('names no scoped attach in its usage text on %s', async (_name, managedSettings) => {
    const enrollUsage = recorder();
    expect(await runEnroll(['--everything'], deps(enrollUsage, { managedSettings }))).toBe(2);
    expect(enrollUsage.errors()).toContain('Usage: aka enroll');
    expect(enrollUsage.errors()).not.toContain('--scoped');
    const unenrollUsage = recorder();
    expect(await runUnenroll(['--everything'], deps(unenrollUsage, { managedSettings }))).toBe(2);
    expect(unenrollUsage.errors()).toContain('Usage: aka unenroll');
    expect(unenrollUsage.errors()).not.toContain('--scoped');
  });
});

describe('aka enroll — who may enroll', () => {
  it('refuses on a machine that is not attached, and writes nothing', async () => {
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('not attached to a deployment');
    expect(io.errors()).toContain('aka attach --url <url> --scoped');
    expect(io.output()).toBe('');
    expect(stored()).toBeUndefined();
  });

  it('refuses on a machine-wide attachment and names the scoped re-attach', async () => {
    attach({ mode: 'machine' });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(io.errors()).toContain('machine-wide');
    expect(io.errors()).toContain('nothing is enrolled');
    // What a machine-wide attachment sends is activity from anywhere on the
    // machine, sessions outside any repository included, not every repository.
    expect(io.errors()).toContain(
      'machine-wide, so activity from\nanywhere on this machine is sent and nothing is enrolled.',
    );
    expect(io.errors()).not.toContain('every repository');
    expect(flat(io.errors())).toContain(
      'To send activity only from what you enroll and from recognised work subscriptions, re-attach with',
    );
    expect(io.errors()).toContain(`aka attach --url ${ENDPOINT} --scoped`);
    expect(storedScope()).toBeUndefined();
  });

  it('does not suggest a scoped re-attach where an administrator governs the connection', async () => {
    attach({ mode: 'machine' });
    const io = recorder();
    expect(await runEnroll(['--list'], deps(io, { managedSettings: governedBy() }))).toBe(1);
    expect(io.errors()).toContain(
      connectionRefusalMessage({ reason: 'scoped-managed', organization: 'Acme IT' }),
    );
    expect(io.errors()).not.toContain('--scoped');
  });

  it('names no scoped attach on a governed machine that is not attached', async () => {
    // The fleet shape: the deployment pinned, nothing attached yet.
    const io = recorder();
    expect(
      await runEnroll(['--repo', WORK_REPO], deps(io, { managedSettings: governedBy() })),
    ).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain(
      connectionRefusalMessage({ reason: 'scoped-managed', organization: 'Acme IT' }),
    );
    expect(io.errors()).not.toContain('--scoped');
    expect(stored()).toBeUndefined();
  });

  it('says a machine held standalone cannot attach, not that it attaches machine-wide', async () => {
    // The mode pinned standalone: `aka attach` itself is refused here.
    const held = ManagedSettings.parse({
      organization: 'Acme IT',
      values: { runMode: 'standalone' },
    });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io, { managedSettings: held }))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain(
      connectionRefusalMessage({ reason: 'held-standalone', organization: 'Acme IT' }),
    );
    expect(io.errors()).not.toContain('attaches machine-wide');
    expect(io.errors()).not.toContain('--scoped');
    expect(stored()).toBeUndefined();
  });

  it('names no scoped re-attach on a governed machine whose credential is unusable', async () => {
    attach({ scope: fresh(), credentialEndpoint: OTHER_ENDPOINT });
    const governed = ManagedSettings.parse({ organization: 'Acme IT', lockedFields: ['runMode'] });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io, { managedSettings: governed }))).toBe(1);
    expect(io.errors()).toContain('cannot be used (it is for another deployment)');
    expect(io.errors()).toContain(
      connectionRefusalMessage({ reason: 'scoped-managed', organization: 'Acme IT' }),
    );
    expect(io.errors()).not.toContain('--scoped');
    expect(storedScope()).toEqual(fresh());
  });

  it('refuses when the credential is for another deployment', async () => {
    attach({ scope: fresh(), credentialEndpoint: OTHER_ENDPOINT });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(io.errors()).toContain('cannot be used (it is for another deployment)');
    expect(io.errors()).toContain(`aka attach --url ${ENDPOINT} --scoped`);
    expect(storedScope()).toEqual(fresh());
  });

  it('applies the same rule to unenroll and to --list', async () => {
    attach({ mode: 'machine' });
    const unenroll = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(unenroll))).toBe(1);
    expect(unenroll.errors()).toContain('machine-wide');
    expect(unenroll.errors()).toContain('activity from\nanywhere on this machine is sent');
    expect(unenroll.errors()).not.toContain('every repository');
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(1);
    expect(list.errors()).toContain('machine-wide');
    expect(list.errors()).toContain('activity from\nanywhere on this machine is sent');
    expect(list.errors()).not.toContain('every repository');
  });
});

// The organization's name is whatever the administrator wrote; the schema does
// not keep control characters out of it, so every refusal that names it strips it.
describe('aka enroll — the organization named in a refusal', () => {
  const ORGANIZATION = `Acme${ESC}[2J IT`;
  const pinned = { controlPlane: { endpoint: ENDPOINT } };

  it.each<[string, () => void, Record<string, unknown>]>([
    ['a governed machine that is not attached', () => undefined, { values: pinned }],
    ['a machine held standalone', () => undefined, { values: { runMode: 'standalone' } }],
    [
      'a governed machine whose credential is unusable',
      () => {
        attach({ scope: fresh(), credentialEndpoint: OTHER_ENDPOINT });
      },
      { lockedFields: ['runMode'] },
    ],
    [
      'a governed machine attached machine-wide',
      () => {
        attach({ mode: 'machine' });
      },
      { values: pinned },
    ],
  ])('strips it on %s', async (_name, setup, managed) => {
    setup();
    const io = recorder();
    const governed = ManagedSettings.parse({ organization: ORGANIZATION, ...managed });
    expect(await runEnroll(['--list'], deps(io, { managedSettings: governed }))).toBe(1);
    expect(io.errors()).toContain('Acme[2J IT manages this machine');
    expect(io.errors()).not.toContain(ESC);
  });
});

// The command a refusal suggests is one to paste, or it is not a command: the
// whole endpoint, quoted for a shell, or the form with a placeholder.
describe('aka enroll — the re-attach command a refusal suggests', () => {
  const attachCommand = (endpoint: string): string =>
    `aka attach --url ${quotedForShell(endpoint)} --scoped`;
  // An ampersand is accepted in the path of an endpoint, and a shell would take
  // it for the end of the command.
  const WITH_AMPERSAND = 'https://aka.acme.test/gateway/a&b';
  const LONG = `https://aka.acme.test/${'p'.repeat(300)}`;
  const WITH_ESCAPE = `https://aka.acme.test/gateway${ESC}[2J`;

  it.each<[string, string]>([
    ['an ampersand in its path', WITH_AMPERSAND],
    ['more than two hundred characters', LONG],
  ])(
    'suggests a command that carries the whole endpoint when it has %s',
    async (_name, endpoint) => {
      attach({ mode: 'machine', endpoint });
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
      expect(io.errors()).toContain(attachCommand(endpoint));
      expect(io.errors()).not.toContain('…');
    },
  );

  it('suggests the same command when the credential cannot be used', async () => {
    attach({ scope: fresh(), endpoint: WITH_AMPERSAND, credentialEndpoint: OTHER_ENDPOINT });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(io.errors()).toContain(`Re-attach with \`${attachCommand(WITH_AMPERSAND)}\``);
  });

  it.each<[string, (endpoint: string) => void]>([
    [
      'a machine-wide attachment',
      (endpoint) => {
        attach({ mode: 'machine', endpoint });
      },
    ],
    [
      'a credential that cannot be used',
      (endpoint) => {
        attach({ scope: fresh(), endpoint, credentialEndpoint: OTHER_ENDPOINT });
      },
    ],
  ])(
    'names the form, with no command, when the endpoint has a control character (%s)',
    async (_name, arrange) => {
      arrange(WITH_ESCAPE);
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
      expect(io.errors()).toContain('`aka attach --url <url> --scoped`');
      expect(io.errors()).not.toContain('gateway');
      expect(io.errors()).not.toContain(ESC);
    },
  );
});

/**
 * Edits the stored settings by hand, as a person or an overlay could: the label
 * is dropped and the deployment's address becomes `endpoint`, which no check
 * made when settings are saved through the product has looked at.
 */
function editPlaneEndpoint(endpoint: string): void {
  const file = join(settingsDirOf(base), SETTINGS_FILENAME);
  const settings = JSON.parse(readFileSync(file, 'utf8')) as {
    controlPlane: Record<string, unknown>;
  };
  delete settings.controlPlane.label;
  settings.controlPlane.endpoint = endpoint;
  writeFileSync(file, JSON.stringify(settings));
}

// The settings address is checked when settings are saved through the product,
// not when the file is edited by hand or an overlay pins it. With no label the
// command names the deployment by that address, so a refusal must not echo what
// an address must never show: userinfo, a query, a fragment. The machine here is
// governed so that the refusal carries no re-attach command, which the describe
// after this one covers on a machine nobody governs.
describe('aka enroll — the deployment named by a settings address with no label', () => {
  const HIDDEN = 'hiddenpart';
  const governed = ManagedSettings.parse({ organization: 'Acme IT', lockedFields: ['runMode'] });

  it.each<[string, string, string]>([
    ['a username', `https://${HIDDEN}@aka.acme.test`, 'https://aka.acme.test, rest not shown'],
    ['a query', `https://aka.acme.test/?t=${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['a fragment', `https://aka.acme.test/#${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['no scheme', `${HIDDEN}@aka.acme.test`, 'address not shown'],
  ])(
    'names a deployment whose address has %s without echoing it, in every verb',
    async (_name, endpoint, shown) => {
      attach({ scope: fresh() });
      editPlaneEndpoint(endpoint);
      const options = { managedSettings: governed };
      const list = recorder();
      const add = recorder();
      const remove = recorder();
      expect(await runEnroll(['--list'], deps(list, options))).toBe(1);
      expect(await runEnroll(['--repo', WORK_REPO], deps(add, options))).toBe(1);
      expect(await runUnenroll(['--repo', WORK_REPO], deps(remove, options))).toBe(1);
      for (const io of [list, add, remove]) {
        expect(`${io.output()}${io.errors()}`).not.toContain(HIDDEN);
        expect(io.errors()).toContain(`the stored credential for ${shown} cannot be used`);
      }
    },
  );

  // The last is longer than the eighty characters a label is cut to, and is not
  // cut: an address is printed whole up to two hundred, as `aka status` prints
  // it. The describe at the end of this group pins both bounds.
  it.each([
    'https://aka.acme.test',
    'https://aka.acme.test/gateway',
    'https://AKA.acme.test',
    `https://aka.acme.test/${'g'.repeat(100)}`,
  ])('prints the clean address %s as stored, in a result and in a refusal', async (endpoint) => {
    attach({ scope: { endpoint, ...MEMBER, entries: [] }, endpoint });
    editPlaneEndpoint(endpoint);
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(0);
    expect(list.output()).toContain(`Enrolled with ${endpoint}:\n`);

    const refused = recorder();
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
      mode: 'scoped',
      endpoint: OTHER_ENDPOINT,
      apiKey: TEST_KEY,
    });
    expect(await runEnroll(['--list'], deps(refused, { managedSettings: governed }))).toBe(1);
    expect(refused.errors()).toContain(`the stored credential for ${endpoint} cannot be used`);
  });
});

// On a machine nobody governs a refusal also suggests the command that attaches
// again. An address `aka attach` would refuse (userinfo, a query, a fragment, a
// scheme that is not https, an address that is not a web address) cannot be
// attached to by that command, so the suggestion carries the placeholder for it
// and none of what the address held. An address it accepts is typed whole.
describe('aka enroll — the re-attach command for a settings address aka attach would refuse', () => {
  const HIDDEN = 'hiddenpart';
  const PLACEHOLDER = '`aka attach --url <url> --scoped`';

  const refused: [string, string][] = [
    ['userinfo', `https://${HIDDEN}@aka.acme.test`],
    ['a query', `https://aka.acme.test/?t=${HIDDEN}`],
    ['a fragment', `https://aka.acme.test/#${HIDDEN}`],
    ['a scheme that is not https', 'http://aka.acme.test'],
    ['no scheme', `${HIDDEN}@aka.acme.test`],
  ];

  it.each(refused)('aka attach refuses an address with %s', async (_name, endpoint) => {
    const io = recorder();
    await runAttach(['--url', endpoint, '--scoped'], {
      base,
      prompter: io,
      managedSettings: null,
      exit: (code) => {
        exits.push(code);
      },
    });
    expect(exits).toEqual([2]);
    expect(io.errors()).toContain('refusing to attach to');
    expect(io.errors()).not.toContain(HIDDEN);
  });

  it.each(refused)(
    'suggests the placeholder, never the address, when it has %s',
    async (_name, endpoint) => {
      attach({ scope: fresh() });
      editPlaneEndpoint(endpoint);
      const list = recorder();
      const add = recorder();
      const remove = recorder();
      expect(await runEnroll(['--list'], deps(list))).toBe(1);
      expect(await runEnroll(['--repo', WORK_REPO], deps(add))).toBe(1);
      expect(await runUnenroll(['--repo', WORK_REPO], deps(remove))).toBe(1);
      for (const io of [list, add, remove]) {
        expect(`${io.output()}${io.errors()}`).not.toContain(HIDDEN);
        expect(io.errors()).toContain(PLACEHOLDER);
        expect(io.errors()).not.toContain('--url http');
      }
    },
  );

  it.each([
    'https://aka.acme.test',
    'https://aka.acme.test/gateway',
    'http://localhost:4100',
    'http://127.0.0.1:4100',
  ])('still suggests a command that carries the address %s', async (endpoint) => {
    attach({ mode: 'machine', endpoint });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(io.errors()).toContain(`aka attach --url ${quotedForShell(endpoint)} --scoped`);
    expect(io.errors()).not.toContain('<url>');
  });
});

// `aka status` cuts a label at eighty characters and an address at two hundred,
// and the deployment named on the lines aka enroll prints is cut at the same
// two bounds, so one deployment reads the same on every command.
describe('aka enroll — how much of the deployment name is printed', () => {
  const CUT_AT_EIGHTY = `${'L'.repeat(80)}…`;

  function credentialFor(endpoint: string): void {
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
      mode: 'scoped',
      endpoint,
      apiKey: TEST_KEY,
    });
  }

  it('cuts a label at eighty characters, in a result and in a refusal', async () => {
    attach({ scope: fresh(), label: 'L'.repeat(150) });
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(0);
    expect(list.output()).toContain(`Enrolled with ${CUT_AT_EIGHTY}:\n`);
    expect(list.output()).not.toContain('L'.repeat(81));

    credentialFor(OTHER_ENDPOINT);
    const refused = recorder();
    expect(await runEnroll(['--list'], deps(refused))).toBe(1);
    expect(refused.errors()).toContain(`the stored credential for ${CUT_AT_EIGHTY} cannot be used`);
    expect(refused.errors()).not.toContain('L'.repeat(81));
  });

  it('prints an address whole where a label would be cut, and cuts it at two hundred', async () => {
    const endpoint = `https://aka.acme.test/${'g'.repeat(300)}`;
    attach({ scope: { endpoint, ...MEMBER, entries: [] }, endpoint });
    editPlaneEndpoint(endpoint);
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(0);
    expect(list.output()).toContain(`Enrolled with ${endpoint.slice(0, 200)}…:\n`);
    expect(list.output()).not.toContain(endpoint.slice(0, 201));

    // Longer than a label may print and shorter than the address bound.
    const shorter = `https://aka.acme.test/${'g'.repeat(100)}`;
    attach({ scope: { endpoint: shorter, ...MEMBER, entries: [] }, endpoint: shorter });
    editPlaneEndpoint(shorter);
    const again = recorder();
    expect(await runEnroll(['--list'], deps(again))).toBe(0);
    expect(again.output()).toContain(`Enrolled with ${shorter}:\n`);
  });
});

describe('aka enroll [path]', () => {
  it('enrolls the repository the working directory is in, echoing it before the write', async () => {
    attach({ scope: fresh() });
    const repo = gitRepo(join(work, 'payments-api'), WORK_REMOTE);
    const io = recorder();
    expect(await runEnroll([], deps(io, { cwd: repo }))).toBe(0);
    expect(exits).toEqual([]);
    expect(storedScope()).toEqual(fresh([enrolled()]));
    const shown = io.output();
    expect(shown).toContain(`Enrolling ${WORK_REPO} (payments-api) with Acme.\n`);
    expect(shown).toContain('Enrolled. Activity in this repository is sent to Acme from now on.\n');
    expect(shown.indexOf('Enrolling')).toBeLessThan(shown.indexOf('Enrolled.'));
    expect(shown).not.toContain('not tied to the account');
    expect(stored()?.controlPlane).toEqual({
      endpoint: ENDPOINT,
      label: 'Acme',
      attachedAt: '2026-10-01T09:00:00.000Z',
    });
  });

  it('resolves a relative path against the working directory before keying it', async () => {
    attach({ scope: fresh() });
    const repo = gitRepo(join(work, 'payments-api'), WORK_REMOTE);
    mkdirSync(join(repo, 'src'));
    const io = recorder();
    expect(await runEnroll([join('payments-api', 'src')], deps(io, { cwd: work }))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
  });

  it('keys an scp-style remote like its https twin', async () => {
    attach({ scope: fresh() });
    const repo = gitRepo(join(work, 'payments-api'), WORK_REMOTE_SCP);
    const io = recorder();
    expect(await runEnroll([repo], deps(io))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
  });

  it('keys a linked worktree as its main checkout', async () => {
    attach({ scope: fresh() });
    const checkout = gitRepo(join(work, 'payments-api'), WORK_REMOTE);
    const worktree = linkedWorktree(checkout, join(work, 'payments-api-review'));
    const io = recorder();
    expect(await runEnroll([worktree], deps(io))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
  });

  it('keys a submodule by its own remote', async () => {
    attach({ scope: fresh() });
    const superproject = gitRepo(join(work, 'payments-api'), WORK_REMOTE);
    const lib = submodule(superproject, 'shared-lib', 'https://github.com/acme/shared-lib.git');
    const io = recorder();
    expect(await runEnroll([lib], deps(io))).toBe(0);
    expect(identities()).toEqual(['github.com/acme/shared-lib']);
  });

  it.each<[string, string | undefined]>([
    ['no remote at all', undefined],
    ['a remote that is a path on this machine', '../payments-api.git'],
  ])('refuses a repository whose remote is not on a code host (%s)', async (_name, remote) => {
    attach({ scope: fresh() });
    const repo = gitRepo(join(work, 'scratch'), remote);
    const io = recorder();
    expect(await runEnroll([repo], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('has no remote on a code host');
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(fresh());
  });

  it('refuses a directory outside any repository', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll([], deps(io, { cwd: work }))).toBe(1);
    expect(io.errors()).toContain('is not inside a git repository');
    expect(storedScope()).toEqual(fresh());
  });

  it('cuts a long repository name to the label bound', async () => {
    attach({ scope: fresh() });
    const name = 'r'.repeat(100);
    const repo = gitRepo(join(work, 'long'), `https://github.com/acme/${name}.git`);
    const io = recorder();
    expect(await runEnroll([repo], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([enrolled(`github.com/acme/${name}`, 'r'.repeat(80))]));
  });
});

describe('aka enroll --repo', () => {
  it.each([
    'https://github.com/acme/payments-api.git',
    'https://GitHub.com/acme/payments-api/',
    WORK_REMOTE_SCP,
    'ssh://github.com/acme/payments-api.git',
    WORK_REPO,
  ])('stores %s as the canonical key', async (input) => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', input], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([enrolled()]));
  });

  it('keeps the case of a path on a host that tells case apart', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', 'git.example.com/Acme/Payments-API'], deps(io))).toBe(0);
    expect(identities()).toEqual(['git.example.com/Acme/Payments-API']);
  });

  // On a forge that ignores case the same spelling names a key no checkout
  // stamps, so it is refused and the real key is named — the same near-miss
  // correction an alias gets.
  it('refuses a capitalised path on a forge that folds case', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', 'github.com/Acme/Payments-API'], deps(io))).toBe(1);
    expect(io.errors()).toContain('is not how that repository is keyed');
    expect(io.errors()).toContain(`its key is ${WORK_REPO}`);
    expect(storedScope()).toEqual(fresh());
  });

  it.each([
    ['GitHub.com/acme/payments-api'],
    [' GitHub.com/acme/payments-api '],
    [`${WORK_REPO}/`],
    [`${WORK_REPO}.git`],
  ])('refuses the typed key %s and names its canonical spelling', async (typed) => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', typed], deps(io))).toBe(1);
    expect(io.errors()).toContain(`its key is ${WORK_REPO}`);
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(fresh());
  });

  // The first two re-spell to `github.com/acme`, which differs from what was
  // typed and is itself not enrollable (one path segment): the cases that hold
  // the refusal to never suggesting a key the command would then refuse. The
  // other three re-spell to themselves or to nothing.
  it.each([
    ['GitHub.com/acme'],
    ['github.com/acme/'],
    ['github.com/acme'],
    ['github.com./acme/payments-api'],
    ['not a repository'],
  ])('refuses %s with no suggestion', async (typed) => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', typed], deps(io))).toBe(1);
    expect(io.errors()).toContain('does not name a repository that can be enrolled');
    expect(io.errors()).not.toContain('its key is');
    expect(storedScope()).toEqual(fresh());
  });

  // An SSH `Host` alias is resolved to the host it names, so every clone of one
  // repository keys the same way (see Architecture principles §8). The reason
  // that matters HERE is that enrolment is matched by exact string: a key no
  // checkout on this machine can produce enrols nothing and reports nothing —
  // the repository reads as covered while that developer forwards none of their
  // activity. These two shapes are exactly that near miss, and the existing
  // re-spelling refusal is what turns each of them into a visible correction.
  describe('a key whose host this machine resolves elsewhere', () => {
    afterEach(() => {
      UNSAFE_TEST_ONLY_setSshHostAliases(new Map());
    });

    it('refuses an alias spelling and names the key checkouts really produce', async () => {
      UNSAFE_TEST_ONLY_setSshHostAliases(new Map([['github-personal', 'github.com']]));
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', 'github-personal/acme/payments-api'], deps(io))).toBe(1);
      expect(io.errors()).toContain('is not how that repository is keyed');
      expect(io.errors()).toContain(`its key is ${WORK_REPO}`);
      expect(storedScope()).toEqual(fresh());
    });

    // The other half, and it lands the OPPOSITE way on purpose. A `Host` block
    // on a real forge name redirects the transport, not the repository (it is
    // how GitHub documents working around a blocked port 22), so the forge name
    // stays the key and the obvious spelling is the right one. Enrolling it
    // must therefore succeed, not be "corrected" to an endpoint no other
    // machine shares.
    it('accepts the forge key even where a block rewrites that host', async () => {
      UNSAFE_TEST_ONLY_setSshHostAliases(new Map([['github.com', 'ssh.github.com']]));
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
      expect(identities()).toEqual([WORK_REPO]);
    });

    // The control: with no alias in force the same key enrols cleanly, so the
    // two refusals above are the alias doing it and not the command refusing
    // every typed key.
    it('enrols the same key when no alias is in force', async () => {
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
      const scope = storedScope() as { entries?: { identity: string }[] } | undefined;
      expect(scope?.entries?.map((entry) => entry.identity)).toContain(WORK_REPO);
    });
  });

  // A repository kept at the top of its host cannot be enrolled by naming its
  // clone URL, since from the text alone it cannot be told from an owner. Its
  // checkout resolves the key for itself, so that is where it is enrolled, and
  // the refusal says so instead of asking for the clone URL that was just given.
  describe('given a clone URL for a repository at the top of its host', () => {
    const CHECKOUT_ROUTE = 'is enrolled from inside its checkout';

    it.each([
      ['an scp clone URL', 'git@git.example.test:payments.git'],
      ['an ssh:// clone URL', 'ssh://git@git.example.test:29418/payments'],
      ['an https clone URL ending in .git', 'https://git.example.test/payments.git'],
    ])('sends %s to the checkout', async (_name, typed) => {
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', typed], deps(io))).toBe(1);
      expect(exits).toEqual([1]);
      expect(io.errors()).toContain(
        `aka enroll: ${typed} names a repository kept at the top of its host. Such a repository ${CHECKOUT_ROUTE}:\n` +
          'run `aka enroll` there, which stores the key the checkout itself resolves.\n',
      );
      expect(io.errors()).not.toContain('Give its clone');
      expect(io.output()).not.toContain('Enrolled.');
      expect(storedScope()).toEqual(fresh());
    });

    it('is true: the checkout of that repository enrolls under its own key', async () => {
      attach({ scope: fresh() });
      const repo = gitRepo(join(work, 'payments'), 'git@git.example.test:payments.git');
      const io = recorder();
      expect(await runEnroll([repo], deps(io))).toBe(0);
      expect(identities()).toEqual(['git.example.test/payments']);
    });

    it.each([
      ['an owner URL', 'https://github.com/acme'],
      ['an owner URL with a trailing slash', 'https://github.com/acme/'],
      [
        'an https URL with one path segment and no .git, which may be an owner',
        'https://git.example.test/payments',
      ],
      ['a path with a dot-dot segment', 'ssh://git@git.example.test/a/../b.git'],
      ['a path with an empty segment', 'git@git.example.test:a//b.git'],
    ])('keeps the old refusal for %s', async (_name, typed) => {
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', typed], deps(io))).toBe(1);
      expect(io.errors()).toBe(
        `aka enroll: ${typed} does not name a repository that can be enrolled. Give its clone\n` +
          'URL, or its key, as in github.com/acme/payments-api.\n',
      );
      expect(io.errors()).not.toContain(CHECKOUT_ROUTE);
      expect(storedScope()).toEqual(fresh());
    });
  });

  // A relative path such as `src/acme/payments-api` reads as a key whose host
  // has no dot, and the key check alone would store it as a repository that
  // matches nothing. A name that is a directory here is a path, so it is sent
  // to the form that reads one.
  describe('given text that names a directory on this machine', () => {
    it('refuses a relative directory and says to pass it as a path', async () => {
      attach({ scope: fresh() });
      mkdirSync(join(work, 'src', 'acme', 'payments-api'), { recursive: true });
      const io = recorder();
      expect(await runEnroll(['--repo', 'src/acme/payments-api'], deps(io, { cwd: work }))).toBe(1);
      expect(exits).toEqual([1]);
      expect(io.errors()).toContain('is a directory on this machine');
      expect(io.errors()).toContain('aka enroll src/acme/payments-api');
      expect(io.output()).toBe('');
      expect(storedScope()).toEqual(fresh());
      expect(settingsWrite.calls).toBe(0);
    });

    it('refuses an absolute directory the same way', async () => {
      attach({ scope: fresh() });
      const dir = join(work, 'payments-api');
      mkdirSync(dir);
      const io = recorder();
      expect(await runEnroll(['--repo', dir], deps(io))).toBe(1);
      expect(io.errors()).toContain('is a directory on this machine');
      expect(io.errors()).not.toContain('does not name a repository');
      expect(storedScope()).toEqual(fresh());
    });

    it.each(['my projects/payments-api', 'src/acme/pay(v2)&ments', 'src/$HOME/payments-api'])(
      'quotes the shell metacharacters in %s in the command it suggests',
      async (typed) => {
        attach({ scope: fresh() });
        mkdirSync(join(work, typed), { recursive: true });
        const io = recorder();
        expect(await runEnroll(['--repo', typed], deps(io, { cwd: work }))).toBe(1);
        const escaped = typed.replace(/[$()&/]/g, (character) => `\\${character}`);
        expect(io.errors()).toMatch(new RegExp(`\`aka enroll ["']${escaped}["']\``));
      },
    );

    // The suggested command is built from the whole text. A name past the width
    // an echo is cut to must not be cut in the command, or pasting it would name
    // another directory.
    it.skipIf(process.platform === 'win32')(
      'suggests the whole path, not the cut one it echoes',
      async () => {
        attach({ scope: fresh() });
        const long = ['a', 'b', 'c'].map((letter) => letter.repeat(70)).join('/');
        mkdirSync(join(work, long), { recursive: true });
        const io = recorder();
        expect(await runEnroll(['--repo', long], deps(io, { cwd: work }))).toBe(1);
        expect(io.errors()).toContain(`\`aka enroll ${long}\``);
        expect(io.errors()).toContain('…');
      },
    );

    it.skipIf(process.platform === 'win32')(
      'names no command for a directory whose name holds a control character',
      async () => {
        attach({ scope: fresh() });
        mkdirSync(join(work, 'src', `pay${ESC}[2Jments`), { recursive: true });
        const io = recorder();
        expect(await runEnroll(['--repo', `src/pay${ESC}[2Jments`], deps(io, { cwd: work }))).toBe(
          1,
        );
        expect(io.errors()).toContain('is a directory on this machine');
        expect(io.errors()).toContain('pass the directory as a path instead of --repo');
        expect(io.errors()).not.toContain('`aka enroll src');
        expect(io.errors()).not.toContain(ESC);
      },
    );

    // A tree laid out by host, owner and repository (the way Go and ghq keep
    // clones) has the checkout at the very path the key spells.
    it('accepts a directory that is the checkout of the repository the text spells', async () => {
      attach({ scope: fresh() });
      gitRepo(join(work, 'github.com', 'acme', 'payments-api'), WORK_REMOTE);
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io, { cwd: work }))).toBe(0);
      expect(storedScope()).toEqual(fresh([enrolled()]));
      expect(io.errors()).toBe('');
    });

    it.each<[string, string | undefined]>([
      ['a plain directory', undefined],
      ['the checkout of another repository', 'https://github.com/acme/billing-worker.git'],
    ])('refuses %s that merely shares the text', async (_name, remote) => {
      attach({ scope: fresh() });
      const dir = join(work, 'github.com', 'acme', 'payments-api');
      if (remote === undefined) mkdirSync(dir, { recursive: true });
      else gitRepo(dir, remote);
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io, { cwd: work }))).toBe(1);
      expect(io.errors()).toContain('is a directory on this machine');
      expect(storedScope()).toEqual(fresh());
    });

    it('keeps a key whose host has no dot when no such directory exists', async () => {
      attach({ scope: fresh() });
      const io = recorder();
      expect(await runEnroll(['--repo', 'src/acme/payments-api'], deps(io, { cwd: work }))).toBe(0);
      expect(identities()).toEqual(['src/acme/payments-api']);
    });

    it('does not take a file for a directory', async () => {
      attach({ scope: fresh() });
      mkdirSync(join(work, 'src', 'acme'), { recursive: true });
      writeFileSync(join(work, 'src', 'acme', 'payments-api'), 'not a directory');
      const io = recorder();
      expect(await runEnroll(['--repo', 'src/acme/payments-api'], deps(io, { cwd: work }))).toBe(0);
      expect(identities()).toEqual(['src/acme/payments-api']);
    });
  });
});

describe('aka enroll — the stored record', () => {
  it('says so and changes nothing when the repository is already enrolled', async () => {
    attach({ scope: fresh([enrolled(WORK_REPO, 'payments-api')]), extra: consent() });
    const before = storedScope();
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(before);
    expect(seed.calls).toEqual([]);
  });

  it('keeps entries and envelope keys a newer build wrote', async () => {
    const newer = { kind: 'workspace', identity: 'acme-workspace', enrolledAt: NOW };
    attach({ scope: { ...fresh([newer]), retention: 'held' } });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(storedScope()).toEqual({ ...fresh([newer, enrolled()]), retention: 'held' });
  });

  it('starts a stripped record again, tied to no account, and says what that means', async () => {
    attach();
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(storedScope()).toEqual({ endpoint: ENDPOINT, entries: [enrolled()] });
    expect(io.output()).toContain('not tied to the account');
    expect(io.output()).toContain('next `aka attach` starts it empty');
  });

  it('binds the record to the endpoint an administrator pinned, not the one in the user file', async () => {
    attach({ credentialEndpoint: PINNED_ENDPOINT });
    const governed = ManagedSettings.parse({
      organization: 'Acme IT',
      values: { controlPlane: { endpoint: PINNED_ENDPOINT } },
    });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io, { managedSettings: governed }))).toBe(0);
    expect(storedScope()).toEqual({ endpoint: PINNED_ENDPOINT, entries: [enrolled()] });
  });

  it('saves an enrollment when an administrator locks the mode', async () => {
    // A scoped attachment made before the lock arrived. The lock governs the
    // connection; an enrollment writes only the scope record, so it must save
    // (or fail loudly), never report success with nothing saved.
    attach({ scope: fresh() });
    const locked = ManagedSettings.parse({ organization: 'Acme IT', lockedFields: ['runMode'] });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io, { managedSettings: locked }))).toBe(0);
    expect(exits).toEqual([]);
    expect(storedScope()).toEqual(fresh([enrolled()]));
    expect(io.output()).toContain('Enrolled.');
  });

  it('writes nothing when the attachment moves between the check and the write', async () => {
    attach({ scope: fresh() });
    const elsewhere = { endpoint: OTHER_ENDPOINT, ...MEMBER, entries: [] };
    settingsWrite.before = () => {
      applyOnboarding(
        {
          controlPlane: { endpoint: OTHER_ENDPOINT, label: 'Other', attachedAt: NOW },
          attachmentScope: elsewhere,
        },
        base,
        null,
      );
    };
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('changed while that was being saved, so nothing was enrolled');
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(elsewhere);
    expect(seed.calls).toEqual([]);
    // The refusal is thrown from inside the settings lock. A lock it left held
    // would make this later write throw (or wait out its timeout).
    expect(() => applyOnboarding({}, base, null)).not.toThrow();
  });

  // The endpoint is not the only thing a concurrent attach can change: the same
  // deployment attached machine-wide leaves the endpoint as it was.
  it.each<[string, Parameters<typeof writeControlPlaneCredential>[1]]>([
    [
      'attached machine-wide',
      { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint: ENDPOINT, apiKey: TEST_KEY },
    ],
    [
      'given a credential for another deployment',
      {
        specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
        mode: 'scoped',
        endpoint: OTHER_ENDPOINT,
        apiKey: TEST_KEY,
      },
    ],
  ])(
    'writes nothing when the deployment is %s between the check and the write',
    async (_name, credential) => {
      attach({ scope: fresh() });
      settingsWrite.before = () => {
        writeControlPlaneCredential(settingsDirOf(base), credential);
      };
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
      expect(exits).toEqual([1]);
      expect(io.errors()).toContain('changed while that was being saved, so nothing was enrolled');
      expect(io.output()).not.toContain('Enrolled.');
      expect(storedScope()).toEqual(fresh());
      expect(seed.calls).toEqual([]);
      expect(() => applyOnboarding({}, base, null)).not.toThrow();
    },
  );

  it('exits non-zero with no success line when the write fails', async () => {
    attach({ scope: fresh(), extra: consent() });
    settingsWrite.failure = new Error('disk full');
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('Could not save that, so nothing was enrolled.');
    expect(io.output()).not.toContain('Enrolled.');
    expect(seed.calls).toEqual([]);
  });

  // The record is validated here, before the settings lock is taken: the raw
  // edit throws for an entry the store would drop, and a throw from inside the
  // lock would read as a failed write instead of saying what was wrong.
  it('refuses an entry the store would not read back before it writes anything', async () => {
    attach({ scope: fresh(), extra: consent() });
    // Year 10000 prints with a sign, which is not a date the record accepts.
    const io = recorder();
    expect(
      await runEnroll(['--repo', WORK_REPO], deps(io, { now: new Date(Date.UTC(10000, 0, 1)) })),
    ).toBe(1);
    expect(exits).toEqual([1]);
    expect(settingsWrite.calls).toBe(0);
    expect(io.errors()).toContain('so nothing was enrolled');
    expect(io.errors()).not.toContain('Could not save that');
    expect(io.output()).toBe('');
    expect(storedScope()).toEqual(fresh());
    expect(seed.calls).toEqual([]);
  });

  it('refuses a clock that gives no date, without throwing', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io, { now: new Date(Number.NaN) }))).toBe(1);
    expect(settingsWrite.calls).toBe(0);
    expect(io.errors()).toContain('so nothing was enrolled');
    expect(storedScope()).toEqual(fresh());
  });
});

// A record whose binding this version cannot read: the organization's name is
// longer than the schema allows, as a newer version might write it. Adding to it
// would start a new record over the entries already there, so enrolling refuses;
// removing from it loses nothing, so unenrolling still works.
describe('aka enroll — a list this version cannot read', () => {
  const UNREADABLE = { ...fresh([enrolled()]), tenantName: 't'.repeat(201) };
  const FIRST_LINE =
    'aka enroll: this version of aka cannot read the list of repositories enrolled with Acme, ' +
    'so nothing was enrolled and the list was left as it is.';

  it('refuses to enroll into it, names how to start the list again, and leaves it as written', async () => {
    attach({ scope: UNREADABLE, extra: consent() });
    const io = recorder();
    expect(await runEnroll(['--repo', SECOND_REPO], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toBe(
      `${FIRST_LINE}\n` +
        'A newer version of aka may have written it. Enroll with that version, or start the ' +
        `list again with \`aka attach --url ${ENDPOINT} --scoped\`, which leaves it empty.\n`,
    );
    expect(io.errors()).not.toContain('Could not save that');
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(UNREADABLE);
    expect(seed.calls).toEqual([]);
  });

  it('names no scoped attach on a governed machine, and says what governs it instead', async () => {
    attach({ scope: UNREADABLE, extra: consent() });
    const io = recorder();
    expect(
      await runEnroll(['--repo', SECOND_REPO], deps(io, { managedSettings: governedBy() })),
    ).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toBe(
      `${FIRST_LINE}\n` +
        `${connectionRefusalMessage({ reason: 'scoped-managed', organization: 'Acme IT' })}\n`,
    );
    expect(io.errors()).not.toContain('--scoped');
    expect(io.output()).not.toContain('Enrolled.');
    expect(storedScope()).toEqual(UNREADABLE);
    expect(seed.calls).toEqual([]);
  });

  it('still removes an entry from it, and keeps the binding as written', async () => {
    attach({ scope: UNREADABLE });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(io.output()).toContain(`Unenrolled ${WORK_REPO}.`);
    expect(storedScope()).toEqual({ ...UNREADABLE, entries: [] });
  });

  // The usual tail says enrolling it again makes it sendable. Over a list this
  // version cannot read that is not so: enrolling is refused, so the tail says
  // that instead and keeps only what is still true.
  it('says enrolling it again is refused, not that it makes it sendable, when it removes an entry', async () => {
    attach({ scope: UNREADABLE });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(io.output()).toBe(
      `Unenrolled ${WORK_REPO}. From now on, sessions and scans you start do not send its activity to Acme, except a Claude Code session or a new Codex thread signed in to a recognised work subscription or to an account enrolled by hand, which forward from any folder. A Codex thread whose login Codex keeps outside its login file (in the system keychain, for one) is not sent.\n` +
        'Anything from it that was waiting to be sent stays unsent while it is not enrolled.\n' +
        'This version of aka cannot read the list it was removed from, so `aka enroll` will refuse to\n' +
        'add to it. Attaching this machine machine-wide to the same deployment makes it sendable again.\n',
    );
    expect(io.output()).not.toContain('enrolling it again');
  });
});

describe('aka enroll — what was recorded before', () => {
  it('queues the earlier captures of exactly the repository it added, under a grant', async () => {
    attach({ scope: fresh([enrolled(SECOND_REPO, null)]), extra: consent() });
    seed.answer = 3;
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(seed.calls).toEqual([{ dataDir: dataDirOf(base), keys: [WORK_REPO] }]);
    const shown = io.output();
    expect(shown).toContain('Queued 3 earlier captured prompts, replies and tool results');
    expect(shown).toContain('still kept on this machine');
    // Captures that were already waiting to be sent go too; the count is only
    // what this enrollment newly queued.
    expect(shown).toContain('Captures already queued for it are sent as well.');
    // The history drain re-reads the scope on every pass, so a repository
    // enrolled under a grant also has its activity from before the attachment
    // sent. Only what it recorded between attaching and enrolling stays.
    expect(shown).toContain(
      'The history sync also sends the rest of its activity recorded before this machine attached',
    );
    expect(flat(shown)).toContain(
      'other than those captures and what a Claude Code or Codex session of a recognised work subscription or of an account enrolled by hand there already sent, stays on this machine.',
    );
    expect(shown).not.toContain('Other activity recorded in it before now stays on this machine.');
  });

  it('says one capture in the singular', async () => {
    attach({ scope: fresh(), extra: consent() });
    seed.answer = 1;
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(io.output()).toContain('Queued 1 earlier captured prompt, reply or tool result');
    expect(io.output()).not.toContain('Queued 1 earlier captured prompts');
  });

  it('does not say nothing was waiting when no capture needed queueing', async () => {
    attach({ scope: fresh(), extra: consent() });
    seed.answer = 0;
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    const shown = io.output();
    // Captures already owed are sent by the drain too, so a count of zero is
    // "none newly queued", never "none waiting".
    expect(shown).toContain(
      'No earlier captured prompts, replies or tool results from it needed queueing.',
    );
    expect(shown).toContain('Captures already queued for it are sent as well.');
    expect(shown).toContain('recorded before this machine attached');
    expect(shown).not.toMatch(/were waiting|nothing was waiting|Queued 0|0 queued/i);
  });

  it('reports a failed queue as not queued, never as a failed enrollment', async () => {
    attach({ scope: fresh(), extra: consent() });
    // A store is there, and the queue still could not be written.
    mkdirSync(dataDirOf(base), { recursive: true });
    writeFileSync(join(dataDirOf(base), DB_FILENAME), '');
    seed.answer = undefined;
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(io.output()).toContain('Enrolled.');
    expect(io.output()).toContain('were not queued: the local store could not be read');
    expect(io.output()).toContain('The enrollment itself is saved.');
  });

  it('says nothing was recorded here when there is no store', async () => {
    attach({ scope: fresh(), extra: consent() });
    seed.answer = undefined;
    const io = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(io.output()).toContain(
      'were not queued: nothing was recorded on this machine before now',
    );
    expect(io.output()).toContain('The enrollment itself is saved.');
    expect(io.output()).not.toContain('could not be read');
  });

  it.each<[string, Partial<WorkspaceSettings>]>([
    ['no grant', {}],
    ['a grant for an older payload', consent({ payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 })],
    ['a grant for another deployment', consent({ endpoint: OTHER_ENDPOINT })],
  ])(
    'queues nothing without a grant in force (%s) and names sync-history',
    async (_name, extra) => {
      attach({ scope: fresh(), extra });
      const io = recorder();
      expect(await runEnroll(['--repo', WORK_REPO], deps(io))).toBe(0);
      expect(seed.calls).toEqual([]);
      expect(flat(io.output())).toContain(
        'Nothing recorded in it before it was enrolled is sent, apart from captured prompts, replies and tool results a live send could not deliver since this machine attached. To send its earlier history as well, run `aka sync-history --on`.',
      );
      expect(io.output()).not.toContain('before now');
    },
  );
});

describe('aka unenroll', () => {
  const newer = { kind: 'workspace', identity: 'acme-workspace', enrolledAt: NOW };

  it('removes the repository the working directory is in and keeps every other entry', async () => {
    attach({ scope: fresh([enrolled(), enrolled(SECOND_REPO, null), newer]) });
    const repo = gitRepo(join(work, 'payments-api'), WORK_REMOTE);
    const io = recorder();
    expect(await runUnenroll([], deps(io, { cwd: repo }))).toBe(0);
    expect(storedScope()).toEqual(fresh([enrolled(SECOND_REPO, null), newer]));
    const shown = io.output();
    expect(shown).toContain(
      `Unenrolled ${WORK_REPO}. From now on, sessions and scans you start do not send its activity to Acme, except a Claude Code session or a new Codex thread signed in to a recognised work subscription or to an account enrolled by hand, which forward from any folder. A Codex thread whose login Codex keeps outside its login file (in the system keychain, for one) is not sent.\n`,
    );
    // Said as far as it is true: a scan already running may have read the scope
    // before the edit, so nothing promises it stops; and what was waiting is
    // not held for good, since enrolling again or a machine-wide attach to the
    // same deployment makes it sendable.
    expect(shown).toContain(
      'Anything from it that was waiting to be sent stays unsent while it is not enrolled;',
    );
    expect(shown).toContain(
      'enrolling it again, or attaching this machine machine-wide to the same deployment,',
    );
    expect(shown).toContain('makes it sendable again.');
    // The usual tail, for a list this version can read: enrolling it again works.
    expect(shown).not.toContain('cannot read');
    expect(shown).not.toContain('no longer sent');
    // The promise is for what the user starts: work already under way, a
    // background sync included, may have read the scope before the edit.
    expect(shown).not.toContain('new sessions');
    expect(shown).not.toContain('until you detach');
    expect(shown).not.toContain('held on this machine');
  });

  it('takes a clone URL', async () => {
    attach({ scope: fresh([enrolled()]) });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REMOTE_SCP], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
  });

  it('removes every stored entry the typed clone URL stands for, and keeps the rest', async () => {
    attach({
      scope: fresh([enrolled(WORK_REMOTE_SCP, null), enrolled(), enrolled(SECOND_REPO, null)]),
    });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REMOTE_SCP], deps(io))).toBe(0);
    expect(identities()).toEqual([SECOND_REPO]);
    expect(io.output()).toContain(`Unenrolled ${WORK_REMOTE_SCP}, ${WORK_REPO}. `);
  });

  it('removes a key enrollableRepoKey refuses, as listed', async () => {
    attach({ scope: fresh() });
    // A single-segment scp remote keys as `host/repo`: a checkout stores that key
    // for itself, and `aka enroll --repo` would refuse it as typed.
    const repo = gitRepo(join(work, 'payments'), 'git.acme.test:payments.git');
    expect(await runEnroll([repo], deps(recorder()))).toBe(0);
    expect(identities()).toEqual(['git.acme.test/payments']);
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(0);
    expect(list.output()).toContain('git.acme.test/payments');
    // From anywhere, not only from inside that checkout.
    const io = recorder();
    expect(await runUnenroll(['--repo', ' git.acme.test/payments '], deps(io, { cwd: base }))).toBe(
      0,
    );
    expect(identities()).toEqual([]);
    expect(io.output()).toContain('Unenrolled git.acme.test/payments.');
    expect(io.errors()).toBe('');
  });

  // Matching is on the stored identity, byte for byte. A key stored under a
  // different normalization form is removable exactly as listed, and a different
  // spelling of it is a different key.
  it('matches the stored identity exactly, and only that', async () => {
    const listed = 'GitHub.com/Acme/Payments';
    attach({ scope: fresh([enrolled(listed, null)]) });
    const wrongCase = recorder();
    expect(await runUnenroll(['--repo', 'github.com/acme/payments'], deps(wrongCase))).toBe(0);
    expect(wrongCase.output()).toContain('is not enrolled with Acme; nothing changed.');
    expect(identities()).toEqual([listed]);
    const exact = recorder();
    expect(await runUnenroll(['--repo', `  ${listed}  `], deps(exact))).toBe(0);
    expect(exact.output()).toContain(`Unenrolled ${listed}.`);
    expect(identities()).toEqual([]);
  });

  it('writes nothing when the deployment is attached machine-wide before the write', async () => {
    attach({ scope: fresh([enrolled()]) });
    settingsWrite.before = () => {
      writeControlPlaneCredential(settingsDirOf(base), {
        specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION,
        endpoint: ENDPOINT,
        apiKey: TEST_KEY,
      });
    };
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(io.errors()).toContain('changed while that was being saved, so nothing was unenrolled');
    expect(io.output()).not.toContain('Unenrolled');
    expect(identities()).toEqual([WORK_REPO]);
  });

  it('says so and changes nothing when the repository is not enrolled', async () => {
    attach({ scope: fresh([enrolled(SECOND_REPO, null)]) });
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(0);
    expect(io.output()).toContain(`${WORK_REPO} is not enrolled with Acme; nothing changed.`);
    expect(io.output()).toContain('aka enroll --list');
    expect(identities()).toEqual([SECOND_REPO]);
  });

  it('exits non-zero with no success line when the write fails', async () => {
    attach({ scope: fresh([enrolled()]) });
    settingsWrite.failure = new Error('disk full');
    const io = recorder();
    expect(await runUnenroll(['--repo', WORK_REPO], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain('Could not save that, so nothing was unenrolled.');
    expect(io.output()).not.toContain('Unenrolled');
  });

  it('points a checkout with no code-host remote at --repo', async () => {
    attach({ scope: fresh([enrolled()]) });
    const repo = gitRepo(join(work, 'scratch'));
    const io = recorder();
    expect(await runUnenroll([repo], deps(io))).toBe(1);
    expect(io.errors()).toContain('has no remote on a code host');
    expect(io.errors()).toContain('--repo');
    expect(identities()).toEqual([WORK_REPO]);
  });
});

describe('aka enroll --list', () => {
  it('lists what is enrolled for the deployment in force', async () => {
    attach({ scope: fresh([enrolled(), enrolled(SECOND_REPO, null)]) });
    const io = recorder();
    expect(await runEnroll(['--list'], deps(io))).toBe(0);
    const shown = io.output();
    expect(shown).toContain('Enrolled with Acme:\n');
    expect(shown).toContain(
      '2 enrolled — anything else stays on this machine, except sessions signed in to a recognised work subscription',
    );
    expect(shown).toContain(`             ${WORK_REPO} (payments-api), enrolled 2026-10-07`);
    expect(shown).toContain(`             ${SECOND_REPO}, enrolled 2026-10-07`);
    expect(settingsWrite.calls).toBe(0);
  });

  // A build before the enrolled list existed rewrites settings through a schema
  // that drops `attachmentScope`, so a scoped machine can be left with no list at
  // all. The list command prints the status block's lines for that state, which
  // differ from the lines for an empty list, and writes nothing.
  it('shows a missing list the way aka status does, not as an empty one', async () => {
    attach();
    const io = recorder();
    expect(await runEnroll(['--list'], deps(io))).toBe(0);
    const missing = attachmentScopeLines(undefined, ENDPOINT);
    expect(io.output()).toBe(`Enrolled with Acme:\n${missing.join('\n')}\n`);
    expect(missing).not.toEqual(attachmentScopeLines(fresh(), ENDPOINT));
    expect(settingsWrite.calls).toBe(0);
  });

  it('strips control characters from the deployment name it echoes', async () => {
    attach({ scope: fresh(), label: `Acme${ESC}[2J` });
    const list = recorder();
    expect(await runEnroll(['--list'], deps(list))).toBe(0);
    expect(list.output()).toContain('Enrolled with Acme[2J:');
    const add = recorder();
    expect(await runEnroll(['--repo', WORK_REPO], deps(add))).toBe(0);
    expect(add.output()).toContain(`Enrolling ${WORK_REPO} (payments-api) with Acme[2J.`);
    expect(`${list.output()}${add.output()}`).not.toContain(ESC);
  });

  // Everything else a refusal or a result puts on the terminal that a person,
  // a remote or a file can write: the text typed after --repo, a path, the key
  // a remote spells, and a stored key the command removes.
  describe('and from everything else it echoes', () => {
    const TYPED = `github.com/acme/evil${ESC}[2J`;

    it('strips the text typed after --repo, to enroll and to unenroll', async () => {
      attach({ scope: fresh() });
      const enroll = recorder();
      expect(await runEnroll(['--repo', TYPED], deps(enroll))).toBe(1);
      expect(enroll.errors()).toContain('github.com/acme/evil[2J does not name a repository');
      const unenroll = recorder();
      expect(await runUnenroll(['--repo', TYPED], deps(unenroll))).toBe(0);
      expect(unenroll.output()).toContain('github.com/acme/evil[2J is not enrolled with Acme');
      expect(`${enroll.errors()}${unenroll.output()}`).not.toContain(ESC);
    });

    it('strips a path in a refusal', async () => {
      attach({ scope: fresh() });
      const io = recorder();
      const cwd = join(base, 'no-such-directory', `dir${ESC}[2J`);
      expect(await runEnroll([], deps(io, { cwd }))).toBe(1);
      expect(io.errors()).toContain('dir[2J is not inside a git repository');
      expect(io.errors()).not.toContain(ESC);
    });

    it('never stores or echoes a key or name a remote spells with a control character', async () => {
      attach({ scope: fresh() });
      const repo = gitRepo(join(work, 'odd'), `https://github.com/acme/pay${ESC}[2Jments.git`);
      const io = recorder();
      expect(await runEnroll([repo], deps(io))).toBe(1);
      expect(io.errors()).toContain('has no remote on a code host');
      expect(`${io.errors()}${io.output()}`).not.toContain(ESC);
      expect(storedScope()).toEqual(fresh());
    });

    it('strips a stored key it removes', async () => {
      // A key a newer build, or a hand edit, wrote: not one this build would store.
      attach({
        scope: fresh([{ kind: 'repo', identity: TYPED, enrolledAt: NOW }, enrolled()]),
      });
      const io = recorder();
      expect(await runUnenroll(['--repo', TYPED], deps(io))).toBe(0);
      expect(io.output()).toContain('Unenrolled github.com/acme/evil[2J.');
      expect(io.output()).not.toContain(ESC);
      expect(identities()).toEqual([WORK_REPO]);
    });
  });
});

// A claude.ai organization, as the browser extension keys it, and a second one.
const ORG = '0a1b2c3d-0000-4000-8000-00000000000a';
const ACCOUNT = `claude:${ORG}`;
const OTHER_ACCOUNT = 'claude:0a1b2c3d-0000-4000-8000-00000000000b';

function enrolledAccount(identity = ACCOUNT) {
  return { kind: 'account', identity, label: 'claude.ai account', enrolledAt: NOW };
}

const CODING_LABEL = 'Claude account (Claude Code and claude.ai)';

// An account entry that covers the coding-agent sessions signed in to the
// account as well as its chats.
function codingAccount(identity = ACCOUNT) {
  return { kind: 'account', identity, label: CODING_LABEL, enrolledAt: NOW, codingAgents: true };
}

// The web-chat block: the capture consent, and the account grant when asked.
function webChat(options: { consent?: boolean; grant?: boolean } = {}) {
  return {
    webChatCapture: {
      responses: 'always' as const,
      account: options.grant === true,
      ...(options.grant === true
        ? {
            accountConsent: {
              acknowledgedAt: '2026-10-01T09:00:00.000Z',
              version: WEB_CHAT_ACCOUNT_CONSENT_VERSION,
            },
          }
        : {}),
      ...(options.consent === false
        ? {}
        : {
            consent: {
              acknowledgedAt: '2026-10-01T09:00:00.000Z',
              version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
            },
          }),
    },
  };
}

describe('aka enroll --account', () => {
  it('enrolls the account as an account entry, echoing it before the write', async () => {
    attach({ scope: fresh(), extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(storedScope()).toEqual(fresh([codingAccount()]));
    const shown = io.output();
    expect(shown).toContain(`Enrolling ${ACCOUNT} (${CODING_LABEL}) with Acme.\n`);
    expect(shown).toContain(
      "Enrolled. Replies in this account's chats, with their tool calls and token usage, are\nrecorded and sent to Acme from now on. Prompts typed in it are still checked, and not recorded.\n",
    );
    expect(shown.indexOf('Enrolling')).toBeLessThan(shown.indexOf('Enrolled.'));
    // Not the repository wording, which would promise sessions and scans.
    expect(shown).not.toContain('Activity in this repository');
    expect(shown).not.toContain('Web-chat capture is off');
  });

  it('stores the key the extension stamps, however it was typed', async () => {
    attach({ scope: fresh(), extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', `  CLAUDE:${ORG.toUpperCase()} `], deps(io))).toBe(0);
    expect(identities()).toEqual([ACCOUNT]);
  });

  it('says nothing is recorded yet while web-chat capture is off, and where to turn it on', async () => {
    attach({ scope: fresh(), extra: webChat({ consent: false }) });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(identities()).toEqual([ACCOUNT]);
    expect(io.output()).toContain(
      'Web-chat capture is off on this machine, so nothing is recorded yet. Turn it on under\nSettings in `aka dashboard`.\n',
    );
  });

  it.each([
    ['a repository key', WORK_REPO],
    ['a chatgpt id that is not a workspace id', 'chatgpt:payments'],
    ['an id that is not an organization id', 'claude:payments'],
    ['a bare organization id', ORG],
    ['text with whitespace around it, which the refusal names without it', '  chatgpt:payments  '],
  ])('refuses %s, and writes nothing', async (_name, input) => {
    attach({ scope: fresh(), extra: webChat() });
    const before = stored();
    const io = recorder();
    expect(await runEnroll(['--account', input], deps(io))).toBe(1);
    expect(exits).toEqual([1]);
    expect(io.errors()).toContain(`aka enroll: ${input.trim()} is not a web chat account key.\n`);
    expect(io.errors()).toContain('`aka enroll --list-detected`');
    expect(io.errors()).toContain('chatgpt:<workspace-id>');
    expect(stored()).toEqual(before);
    expect(settingsWrite.calls).toBe(0);
  });

  it('changes nothing for an account already enrolled', async () => {
    attach({ scope: fresh([codingAccount()]), extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
    expect(identities()).toEqual([ACCOUNT]);
  });

  it('is refused on a machine-wide attachment, like a repository', async () => {
    attach({ mode: 'machine', extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
    expect(io.errors()).toContain('machine-wide');
    expect(storedScope()).toBeUndefined();
  });

  it('sends nothing earlier without a history-sync grant but what a live send left owed, and says how to', async () => {
    attach({ scope: fresh(), extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(flat(io.output())).toContain(
      'Nothing recorded in it before it was enrolled is sent, apart from captured prompts, replies and tool results a live send could not deliver since this machine attached. To send its earlier replies as well, run `aka sync-history --on`.',
    );
    expect(io.output()).not.toContain('before now');
    expect(seed.calls).toEqual([]);
  });

  it('queues its earlier captures under the grant, and promises nothing about its sessions', async () => {
    attach({ scope: fresh(), extra: { ...webChat(), ...consent() } });
    seed.answer = 3;
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(seed.calls).toEqual([{ dataDir: dataDirOf(base), keys: [ACCOUNT] }]);
    expect(io.output()).toContain('Queued 3 earlier captured prompts, replies and tool results');
    expect(io.output()).not.toContain('sessions, tool calls, token usage');
  });

  it('is listed with its label by aka enroll --list', async () => {
    attach({ scope: fresh([enrolledAccount()]), extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--list'], deps(io))).toBe(0);
    expect(io.output()).toContain(`${ACCOUNT} (claude.ai account), enrolled 2026-10-07`);
  });
});

describe('aka unenroll --account', () => {
  it('takes the account out, and says its chats are no longer recorded', async () => {
    attach({ scope: fresh([enrolledAccount(), enrolled()]), extra: webChat() });
    const io = recorder();
    expect(await runUnenroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
    expect(io.output()).toContain(
      `Unenrolled ${ACCOUNT}. From now on, its chats are checked and nothing from them is recorded or sent to Acme.\n`,
    );
    expect(io.output()).not.toContain('sessions and scans you start');
  });

  it('matches the key however it was typed', async () => {
    attach({ scope: fresh([enrolledAccount()]), extra: webChat() });
    const io = recorder();
    expect(await runUnenroll(['--account', `claude:${ORG.toUpperCase()}`], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
  });

  it('removes an entry stored under a key enroll would not accept, and words it as a claude key', async () => {
    attach({
      scope: fresh([{ kind: 'account', identity: 'claude:legacy-id', enrolledAt: NOW }]),
      extra: webChat(),
    });
    const io = recorder();
    expect(await runUnenroll(['--account', 'claude:legacy-id'], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
    expect(
      io
        .output()
        .startsWith(
          'Unenrolled claude:legacy-id. From now on, its chats are checked and nothing from them is recorded or sent to Acme.\n',
        ),
    ).toBe(true);
  });

  it('removes an entry stored in another case when the key is typed as it is stored', async () => {
    const stored = `claude:${ORG.toUpperCase()}`;
    attach({
      scope: fresh([{ kind: 'account', identity: stored, enrolledAt: NOW }, enrolled()]),
      extra: webChat(),
    });
    const io = recorder();
    expect(await runUnenroll(['--account', stored], deps(io))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
    expect(
      io
        .output()
        .startsWith(
          `Unenrolled ${stored}. From now on, its chats are checked and nothing from them is recorded or sent to Acme.\n`,
        ),
    ).toBe(true);
  });

  it.each([
    ['a key stored in another case', `claude:${ORG.toUpperCase()}`],
    ['text that is not an account key', 'claude:legacy-id'],
  ])('matches %s as typed, without the whitespace around it', async (_name, listed) => {
    attach({
      scope: fresh([{ kind: 'account', identity: listed, enrolledAt: NOW }, enrolled()]),
      extra: webChat(),
    });
    const io = recorder();
    expect(await runUnenroll(['--account', `  ${listed}\t `], deps(io))).toBe(0);
    expect(identities()).toEqual([WORK_REPO]);
    expect(io.output().startsWith(`Unenrolled ${listed}. `)).toBe(true);
  });

  it('says so when the account is not enrolled', async () => {
    attach({ scope: fresh([enrolled()]), extra: webChat() });
    const io = recorder();
    expect(await runUnenroll(['--account', OTHER_ACCOUNT], deps(io))).toBe(0);
    expect(io.output()).toContain(`${OTHER_ACCOUNT} is not enrolled with Acme; nothing changed.\n`);
    expect(identities()).toEqual([WORK_REPO]);
  });
});

describe('aka enroll --list-detected', () => {
  it('says the record is off without the account grant, and how to turn it on', async () => {
    attach({ scope: fresh(), extra: webChat() });
    // A record left behind is not listed while the grant is off.
    recordDetectedWebAccount(dataDirOf(base), ACCOUNT, SOURCE_TOOL.ClaudeAi);
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain('does not record which web chat accounts it sees');
    expect(io.output()).toContain('`aka extension account --on`');
    expect(io.output()).not.toContain(ACCOUNT);
  });

  it('says none has been seen under the grant when the record is empty', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain('No web chat account has been seen here yet.');
  });

  it('lists each account seen, newest first, marking what is enrolled and how to enroll the rest', async () => {
    attach({ scope: fresh([enrolledAccount()]), extra: webChat({ grant: true }) });
    recordDetectedWebAccount(
      dataDirOf(base),
      ACCOUNT,
      SOURCE_TOOL.ClaudeAi,
      new Date('2026-10-05T09:00:00.000Z'),
    );
    recordDetectedWebAccount(
      dataDirOf(base),
      OTHER_ACCOUNT,
      SOURCE_TOOL.ClaudeAi,
      new Date('2026-10-06T09:00:00.000Z'),
    );
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toBe(
      'Web chat accounts seen on this machine, for Acme:\n' +
        `  ${OTHER_ACCOUNT}, last seen 2026-10-06 — not enrolled: \`aka enroll --account ${OTHER_ACCOUNT}\`\n` +
        `  ${ACCOUNT}, last seen 2026-10-05 — enrolled\n` +
        'Claude Code — signed in now:\n  none (no login file)\n' +
        'Codex — signed in now:\n  none (no login file)\n',
    );
    // Listing writes nothing.
    expect(settingsWrite.calls).toBe(0);
  });
});

// The Claude Code login fixtures: the attaching member's address and another,
// generated per run, and Claude Code's login file in the suite's own Claude home.
const CLAUDE_MEMBER = fixtureEmail(`member-${randomUUID().slice(0, 8)}`);
const SOMEONE_ELSE = fixtureEmail(`other-${randomUUID().slice(0, 8)}`);
// `as const`: the credential readers take the version as the literal `2`.
const SCOPED_CREDENTIAL = {
  specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: TEST_KEY,
} as const;

const flat = (text: string): string => text.replace(/\s+/g, ' ');

const UNTIL_USER_KNOWN =
  'This device does not know yet which AKA user attached it, so a Claude Code session outside an enrolled repository is not sent until it does; one inside an enrolled repository is sent under the repository rule.';

function claudeSignIn(
  account: Readonly<Record<string, unknown>> = {},
  email: string = CLAUDE_MEMBER,
  org: string = ORG,
): void {
  writeFileSync(join(claudeHome, '.claude.json'), JSON.stringify(workConfig(org, email, account)));
}

/** The record that tells this device who attached it, bound to the test credential. */
function knownMember(): void {
  writeAttachedIdentity(dataDirOf(base), {
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    tenantName: MEMBER.tenantName,
    userEmail: CLAUDE_MEMBER,
  });
}

/** A work account a hook validated on this device. */
function learn(key: string): void {
  recordValidatedWorkAccount(dataDirOf(base), {
    endpoint: ENDPOINT,
    credential: SCOPED_CREDENTIAL,
    key,
  });
}

/**
 * Every file under `dir` with its bytes, the store's own files left out: what a
 * command that persists nothing must leave as it found it.
 */
function treeOf(dir: string): Record<string, string> {
  const tree: Record<string, string> = {};
  for (const name of readdirSync(dir, { recursive: true, encoding: 'utf8' })) {
    const path = join(dir, name);
    if (!statSync(path).isFile() || basename(name).startsWith(DB_FILENAME)) continue;
    tree[name] = readFileSync(path, 'base64');
  }
  return tree;
}

// The Codex login fixtures: a ChatGPT workspace id generated per run, and the
// login file Codex writes, built by the reader's own helper in the suite's own
// Codex home. The login is the attaching member's, so knownMember() matches it.
const CODEX_WORKSPACE = randomUUID();
const CHATGPT_KEY = `chatgpt:${CODEX_WORKSPACE}`;
const CHATGPT_LABEL = 'ChatGPT workspace (Codex)';

function codexSignIn(plan: string | undefined, email: string = CLAUDE_MEMBER) {
  return writeCodexAuth(codexHome, {
    accountId: CODEX_WORKSPACE,
    email,
    ...(plan === undefined ? {} : { plan }),
  });
}

// An entry written by `aka enroll --account` for a ChatGPT workspace.
function codexAccount(identity = CHATGPT_KEY) {
  return { kind: 'account', identity, label: CHATGPT_LABEL, enrolledAt: NOW, codingAgents: true };
}

describe('aka enroll --account — Claude Code sessions', () => {
  it('marks the entry for Claude Code sessions, and says what it forwards and from when', async () => {
    attach({ scope: fresh(), extra: webChat() });
    knownMember();
    claudeSignIn();
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([codingAccount()]));
    const shown = flat(io.output());
    expect(shown).toContain(
      "Claude Code sessions signed in to this organization are sent to Acme too, from any folder, with their folder, project and branch names, and this account's claude.ai chats when web chat capture is on.",
    );
    expect(shown).toContain(
      'A session already running starts forwarding at its next event, and a new one from its first reply on. The first prompt of a new session, a session that uses an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule.',
    );
    expect(shown).not.toMatch(/login file shows? the (?:plan|account)/);
    expect(shown).toContain(
      'Nothing a Claude Code session recorded before this enrollment is sent this way, apart from captured prompts, replies and tool results a live send could not deliver since this machine attached.',
    );
    for (const notPrinted of [
      'every session signed in to this organization',
      'That starts with the next session',
      'no Claude Code session recorded before now',
      'nothing recorded before now',
      'it is sent only from an enrolled repository',
    ]) {
      expect(shown).not.toContain(notPrinted);
    }
    expect(shown).toContain(
      'a login under another email, a plan Claude Code does not show, or a device a colleague approved.',
    );
    expect(shown).not.toContain('Claude Code is not signed in to that organization');
    expect(shown).not.toContain('could not be read, so no session');
    expect(shown).not.toContain('does not know yet which AKA user');
  });

  it('adds the marker in place to an entry enrolled for its chats only, and queues nothing again', async () => {
    const earlier = { ...enrolledAccount(), enrolledAt: '2026-10-02T09:00:00.000Z' };
    attach({ scope: fresh([earlier]), extra: { ...webChat(), ...consent() } });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([{ ...earlier, codingAgents: true }]));
    expect(io.output()).toContain('it now also covers Claude Code sessions.\n');
    expect(seed.calls).toEqual([]);
  });

  it('adds the marker in place to every stored entry of the account', async () => {
    const first = enrolledAccount();
    const second = { ...enrolledAccount(), enrolledAt: '2026-10-02T09:00:00.000Z' };
    attach({ scope: fresh([first, enrolled(), second]), extra: webChat() });
    expect(await runEnroll(['--account', ACCOUNT], deps(recorder()))).toBe(0);
    expect(storedScope()).toEqual(
      fresh([{ ...first, codingAgents: true }, enrolled(), { ...second, codingAgents: true }]),
    );
  });

  it('still enrolls while work subscriptions are off, and says the opt-out does not cover it', async () => {
    attach({ scope: { ...fresh(), workSubscriptions: 'off' }, extra: webChat() });
    const io = recorder();
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(identities()).toEqual([ACCOUNT]);
    expect(flat(io.output())).toContain(
      'an account you enroll by hand still forwards, because the opt-out covers only automatic recognition.',
    );
  });

  it.each<[string, () => void]>([
    ['there is no login file', () => undefined],
    [
      'the login is for another organization',
      () => {
        claudeSignIn({}, CLAUDE_MEMBER, randomUUID());
      },
    ],
  ])(
    'says Claude Code is not signed in to that organization now when %s',
    async (_case, signIn) => {
      attach({ scope: fresh(), extra: webChat() });
      knownMember();
      signIn();
      const io = recorder();
      expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
      const shown = flat(io.output());
      expect(shown).toContain(
        'Claude Code is not signed in to that organization on this machine now; its sessions are sent when it is.',
      );
      expect(shown).not.toContain('has not seen Claude Code');
      expect(shown).not.toContain('could not be read');
    },
  );

  it.each<[string, () => void]>([
    [
      'the login file does not parse',
      () => {
        writeFileSync(join(claudeHome, '.claude.json'), '{ not json');
      },
    ],
    [
      'the login file does not parse and the environment names the account',
      () => {
        writeFileSync(join(claudeHome, '.claude.json'), '{ not json');
        vi.stubEnv('CLAUDE_CODE_ORGANIZATION_UUID', ORG);
      },
    ],
  ])(
    'says the login file could not be read, not that Claude Code is signed out, when %s',
    async (_case, unreadable) => {
      attach({ scope: fresh(), extra: webChat() });
      knownMember();
      unreadable();
      const io = recorder();
      expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
      const shown = flat(io.output());
      expect(shown).toContain(
        "Claude Code's login file could not be read, so no session is sent this way until it can be.",
      );
      expect(shown).not.toContain('is not signed in to that organization');
      expect(shown).not.toContain('does not know yet which AKA user');
    },
  );

  it.each<[string, () => void]>([
    [
      'the login is for that organization',
      () => {
        claudeSignIn();
      },
    ],
    ['there is no login file', () => undefined],
    [
      'the login file does not parse',
      () => {
        writeFileSync(join(claudeHome, '.claude.json'), '{ not json');
      },
    ],
  ])(
    'says a session outside an enrolled repository waits until the device knows who attached it, and one inside follows the repository rule, when %s',
    async (_case, signIn) => {
      attach({ scope: fresh([enrolled()]), extra: webChat() });
      signIn();
      const io = recorder();
      expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
      expect(identities()).toEqual([WORK_REPO, ACCOUNT]);
      const shown = flat(io.output());
      expect(shown).toContain(UNTIL_USER_KNOWN);
      expect(shown).not.toContain('sends no Claude Code session');
      expect(shown).not.toContain('is not signed in to that organization');
      expect(shown).not.toContain('could not be read, so no session');
    },
  );

  it.each<['enroll' | 'unenroll', string, string]>(
    (['enroll', 'unenroll'] as const).flatMap((verb) => [
      [verb, '--account', `agent:${'0'.repeat(16)}:${ACCOUNT}`] as const,
      [verb, '--repo', `agent:${'0'.repeat(16)}:${ACCOUNT}`] as const,
      [verb, '--account', '  AGENT:anything'] as const,
    ]),
  )('refuses an agent key given to aka %s %s, and writes nothing', async (verb, flag, value) => {
    attach({ scope: fresh([codingAccount()]), extra: webChat() });
    const before = stored();
    const io = recorder();
    const run = verb === 'enroll' ? runEnroll : runUnenroll;
    expect(await run([flag, value], deps(io))).toBe(1);
    expect(io.errors()).toContain(`aka ${verb}: an agent: key is never enrolled`);
    expect(`${io.errors()}${io.output()}`.includes(value.trim())).toBe(false);
    expect(stored()).toEqual(before);
    expect(settingsWrite.calls).toBe(0);
  });
});

// The plan notices a terminal shows, line for line. Off one, where a coding
// agent's own output is recorded, the command says nothing about the login's plan.
const CLAUDE_PLAN_NOTICE =
  'The Claude Code login signed in now is on a personal plan, not a Team or Enterprise plan.\n' +
  'Enrolling its organization sends the Claude Code sessions signed in to it to Acme, from any folder, and, where web chat capture is on, the replies in its claude.ai chats.\n' +
  'The first prompt of a new session, a session that uses an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule.\n';
const CODEX_PLAN_NOTICE =
  'The Codex login signed in now is on a plan that is not a ChatGPT workspace plan.\n' +
  'Enrolling its workspace sends every new Codex thread signed in to it to Acme, from any folder.\n';
const CONFIRMATION = 'Enroll it anyway? [y/N]: ';

function expectNoPlanNotice(io: ReturnType<typeof recorder>): void {
  for (const heard of [io.output(), io.errors()]) {
    for (const notice of [CLAUDE_PLAN_NOTICE, CODEX_PLAN_NOTICE]) {
      // The closing rule sentence is also part of what a completed enrollment prints.
      const planLines = notice
        .split('\n')
        .filter((text) => text !== '' && !text.startsWith('The first prompt of a new session'));
      for (const line of planLines) {
        expect(heard.includes(line)).toBe(false);
      }
    }
  }
}

/** A terminal that answers every question with `answer`, recording what had been printed when each was asked. */
function answering(answer: string) {
  const asked: string[] = [];
  const printedBefore: string[] = [];
  const io = {
    ...recorder(),
    ask: (question: string): Promise<string> => {
      asked.push(question);
      printedBefore.push(io.output());
      return Promise.resolve(answer);
    },
  };
  return { io, asked, printedBefore };
}

describe('aka enroll --account — the login signed in now on a personal plan', () => {
  it('asks on a terminal before enrolling it, and enrolls on yes', async () => {
    attach({ scope: fresh(), extra: webChat() });
    knownMember();
    claudeSignIn({ organizationType: 'claude_max' });
    const { io, asked, printedBefore } = answering('y');
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(asked).toEqual([CONFIRMATION]);
    expect(printedBefore).toEqual([CLAUDE_PLAN_NOTICE]);
    expect(identities()).toEqual([ACCOUNT]);
    const shown = flat(io.output());
    expect(shown).toContain(
      'Enrolling its organization sends the Claude Code sessions signed in to it to Acme, from any folder, and, where web chat capture is on, the replies in its claude.ai chats. The first prompt of a new session, a session that uses an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule.',
    );
    expect(shown).not.toContain('sends every Claude Code session');
    expect(shown).not.toContain('does not know yet which AKA user');
    expect(shown).not.toMatch(/login file shows? the (?:plan|account)/);
  });

  it('says before it asks that a session outside an enrolled repository waits until the device knows who attached it', async () => {
    attach({ scope: fresh([enrolled()]), extra: webChat() });
    claudeSignIn({ organizationType: 'claude_max' });
    const { io, asked } = answering('n');
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
    expect(asked).toEqual(['Enroll it anyway? [y/N]: ']);
    const shown = flat(io.output());
    expect(shown).toContain(UNTIL_USER_KNOWN);
    expect(shown).not.toContain('sends no Claude Code session');
    expect(shown.indexOf('does not know yet')).toBeLessThan(shown.indexOf('Nothing was enrolled.'));
  });

  it.each(['claude_max', 'claude_pro'])(
    'shows the whole notice for a %s login, then asks, and enrolls nothing when the answer is no',
    async (organizationType) => {
      attach({ scope: fresh(), extra: webChat() });
      knownMember();
      claudeSignIn({ organizationType });
      const before = stored();
      const { io, asked, printedBefore } = answering('n');
      expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
      expect(asked).toEqual([CONFIRMATION]);
      expect(printedBefore).toEqual([CLAUDE_PLAN_NOTICE]);
      expect(io.output()).toBe(`${CLAUDE_PLAN_NOTICE}Nothing was enrolled.\n`);
      expect(io.errors()).toBe('');
      expect(stored()).toEqual(before);
    },
  );

  it('refuses without a terminal unless --yes, and writes nothing', async () => {
    attach({ scope: fresh(), extra: webChat() });
    knownMember();
    claudeSignIn({ organizationType: 'claude_pro' });
    const before = stored();
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
    expect(io.errors()).toContain('Run this on a terminal to confirm, or add --yes.');
    expectNoPlanNotice(io);
    expect(stored()).toEqual(before);
    const yes = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--account', ACCOUNT, '--yes'], deps(yes))).toBe(0);
    expectNoPlanNotice(yes);
    expect(identities()).toEqual([ACCOUNT]);
  });

  // The key and the plan are read before the address can be compared, so the
  // guard holds before the first sync has told the device who attached it.
  it('asks even before this device knows who attached it', async () => {
    attach({ scope: fresh(), extra: webChat() });
    claudeSignIn({ organizationType: 'claude_max' });
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
    expectNoPlanNotice(io);
    expect(identities()).toEqual([]);
  });

  it('asks nothing for an account already enrolled for Claude Code sessions, on a terminal', async () => {
    attach({ scope: fresh([codingAccount()]), extra: webChat() });
    knownMember();
    claudeSignIn({ organizationType: 'claude_max' });
    const before = stored();
    const { io, asked } = answering('n');
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(asked).toEqual([]);
    expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
    expect(io.output()).not.toContain('personal plan');
    expect(stored()).toEqual(before);
    expect(exits).toEqual([]);
  });

  it('asks nothing for an account already enrolled for Claude Code sessions, off a terminal and without --yes', async () => {
    attach({ scope: fresh([codingAccount()]), extra: webChat() });
    knownMember();
    claudeSignIn({ organizationType: 'claude_max' });
    const before = stored();
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
    expect(io.errors()).toBe('');
    expect(stored()).toEqual(before);
    expect(exits).toEqual([]);
  });

  it('still asks for an account stored without the marker, whose chats alone were enrolled', async () => {
    attach({ scope: fresh([enrolledAccount()]), extra: webChat() });
    knownMember();
    claudeSignIn({ organizationType: 'claude_max' });
    const { io, asked } = answering('n');
    expect(await runEnroll(['--account', ACCOUNT], deps(io))).toBe(1);
    expect(asked).toEqual(['Enroll it anyway? [y/N]: ']);
  });

  it('asks nothing for a Team login, or for a key the login signed in now does not name', async () => {
    attach({ scope: fresh(), extra: webChat() });
    claudeSignIn();
    expect(await runEnroll(['--account', ACCOUNT], deps(recorder()))).toBe(0);
    claudeSignIn({ organizationType: 'claude_max' }, CLAUDE_MEMBER, randomUUID());
    expect(await runEnroll(['--account', OTHER_ACCOUNT], deps(recorder()))).toBe(0);
    expect(identities()).toEqual([ACCOUNT, OTHER_ACCOUNT]);
  });
});

describe('aka unenroll --work-subscriptions', () => {
  it('turns them off, forgets the learned work accounts, and says what still forwards', async () => {
    attach({ scope: fresh([enrolled(), codingAccount()]), extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(storedScope()).toEqual({
      ...fresh([enrolled(), codingAccount()]),
      workSubscriptions: 'off',
    });
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
    const shown = flat(io.output());
    for (const said of [
      'Work subscriptions are off on this device for Acme.',
      'Sessions signed in to a work subscription stop forwarding at their next event, from any folder outside an enrolled repository',
      `${WORK_REPO} — \`aka unenroll --repo ${WORK_REPO}\` removes it`,
      `${ACCOUNT} — \`aka unenroll --account ${ACCOUNT}\` removes it`,
      "Your organization's model restrictions now apply only in enrolled repositories and to accounts enrolled by hand.",
      'Nothing already sent is recalled. Rows recorded but not yet sent stay on this device, and are sent if you turn recognition back on and the same work account is recognised again.',
      '`aka enroll --work-subscriptions` turns recognition back on.',
    ]) {
      expect(shown).toContain(said);
    }
  });

  it('says so when they are already off, changes nothing, and forgets the learned accounts again', async () => {
    attach({ scope: { ...fresh([enrolled()]), workSubscriptions: 'off' }, extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    const before = stored();
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toHaveLength(1);
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(io.output()).toContain(
      'Recognition of work subscriptions is already off for Acme on this device. The work accounts it had learned were cleared again; nothing else changed.\n',
    );
    expect(io.output()).not.toContain('nothing changed.\n');
    expect(stored()).toEqual(before);
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
  });

  it('says only that nothing changed when they are already off and nothing was learned', async () => {
    attach({ scope: { ...fresh([enrolled()]), workSubscriptions: 'off' }, extra: webChat() });
    knownMember();
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(io.output()).toBe(
      'Recognition of work subscriptions is already off for Acme on this device; nothing changed.\n',
    );
  });

  // The record's lock cannot be taken, so the learned accounts stay. The opt-out
  // is stored all the same, and the command says what is left and what clears it.
  it('says the learned accounts could not be cleared because the record is busy, when already off', async () => {
    attach({ scope: { ...fresh([enrolled()]), workSubscriptions: 'off' }, extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    forgetSeam.fails = true;
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(flat(io.output())).toContain(
      'The work accounts this device had learned could not be cleared now because the record is busy; running this command again clears them.',
    );
    expect(io.output()).not.toContain('were cleared again');
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toHaveLength(1);
    forgetSeam.fails = false;
    const again = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(again))).toBe(0);
    expect(again.output()).toContain('were cleared again');
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
  });

  it('stores the opt-out and says the record is busy when turning them off now', async () => {
    attach({ scope: fresh([enrolled()]), extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    forgetSeam.fails = true;
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(exits).toEqual([]);
    expect(storedScope()).toEqual({ ...fresh([enrolled()]), workSubscriptions: 'off' });
    const shown = flat(io.output());
    expect(shown).toContain('Work subscriptions are off on this device for Acme.');
    expect(shown).toContain(
      'The work accounts this device had learned could not be cleared now because the record is busy; running this command again clears them.',
    );
  });

  it('does not call a record with nothing learned busy', async () => {
    attach({ scope: fresh([enrolled()]), extra: webChat() });
    forgetSeam.fails = true;
    const io = recorder();
    expect(await runUnenroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(io.output()).not.toContain('busy');
  });

  it('keeps every other key and entry of the record as found', async () => {
    const newer = {
      ...fresh([enrolled()]),
      builtBy: 'a newer build',
      entries: [enrolled(), { kind: 'org', identity: 'example-org', enrolledAt: NOW }],
    };
    attach({ scope: newer });
    expect(await runUnenroll(['--work-subscriptions'], deps(recorder()))).toBe(0);
    expect(storedScope()).toEqual({ ...newer, workSubscriptions: 'off' });
  });
});

describe('aka enroll --work-subscriptions', () => {
  it('turns them back on, and says waiting rows are sent once their account is recognised again', async () => {
    attach({ scope: { ...fresh([enrolled()]), workSubscriptions: 'off' } });
    const io = recorder();
    expect(await runEnroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([enrolled()]));
    const shown = flat(io.output());
    expect(shown).toContain('Work subscriptions are on again on this device for Acme.');
    expect(shown).toContain(
      'A Claude Code session signed in to a work subscription (a Claude Team or Enterprise plan), under the same email as your AKA account, sends everything it records from its first reply on, from any folder, with its folder, project and branch names.',
    );
    expect(shown).toContain(
      "The device checks that locally: it reads Claude Code's login file, the session's own log, and the settings and environment that choose the account, and compares the signed-in email with your AKA account. The check sends none of it (no email, plan or account id), though the token usage and tool calls read from that same log are sent with the rest of the activity of a recognised session or of one signed in to an account you enroll by hand.",
    );
    expect(shown).toContain(
      'The first prompt of a new session, a session that uses an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule.',
    );
    expect(shown).not.toContain('own login file');
    expect(shown).not.toMatch(/login file shows? the (?:plan|account)/);
    expect(shown).toContain(
      "A new Codex thread signed in with ChatGPT to a Business, Team, Enterprise or Edu workspace, under the same email as your AKA account, with its login saved in Codex's login file and OpenAI as the provider, sends everything it records, from any folder, with its folder, project and branch names. A resumed thread follows the repository rule: it is sent only from an enrolled repository.",
    );
    expect(shown).toContain(
      "For Codex the device checks the same way, locally: it reads Codex's login file, the first line of the thread's own log and the environment variables that choose the account or provider, and compares the signed-in email with your AKA account. The check sends none of it (no email, plan or workspace id), though the token usage and tool calls read from that thread's log are sent with the rest of the activity of a recognised thread or of one signed in to a workspace you enroll by hand.",
    );
    // The Codex check waits for no first reply and reads no settings file.
    const codexLines = io
      .output()
      .split('\n')
      .filter((line) => line.includes('Codex'));
    expect(codexLines).toHaveLength(3);
    for (const line of codexLines) {
      expect(line).not.toContain('first reply');
      expect(line).not.toContain('settings');
      expect(line).not.toContain('chatgpt:');
    }
    expect(shown).toContain(
      'A Claude Code session signed in to a work account is recognised again at its next event. A Codex thread signed in to a work account is recognised again at its next event if it started while recognition was on, and not if it started while it was off.',
    );
    expect(shown).not.toContain('the next time a session signed in to it runs');
    expect(shown).toContain(
      'Rows recorded under a work account before you turned recognition off, and not yet sent, are sent once it is recognised again.',
    );
  });

  it('clears a stored value this version does not know, which reads as off', async () => {
    attach({ scope: { ...fresh(), workSubscriptions: 'paused' } });
    expect(await runEnroll(['--work-subscriptions'], deps(recorder()))).toBe(0);
    expect(storedScope()).toEqual(fresh());
  });

  it('keeps every other key and entry of the record as found', async () => {
    const newer = {
      ...fresh([enrolled()]),
      builtBy: 'a newer build',
      entries: [enrolled(), { kind: 'org', identity: 'example-org', enrolledAt: NOW }],
    };
    attach({ scope: { ...newer, workSubscriptions: 'off' } });
    expect(await runEnroll(['--work-subscriptions'], deps(recorder()))).toBe(0);
    expect(storedScope()).toEqual(newer);
  });

  it('says so when they are already on, and changes nothing', async () => {
    attach({ scope: fresh([enrolled()]) });
    const before = stored();
    const io = recorder();
    expect(await runEnroll(['--work-subscriptions'], deps(io))).toBe(0);
    expect(io.output()).toContain(
      'Recognition of work subscriptions is already on for Acme on this device; nothing changed.\n',
    );
    expect(stored()).toEqual(before);
  });

  it('writes nothing to the identity record', async () => {
    attach({ scope: { ...fresh(), workSubscriptions: 'off' } });
    knownMember();
    learn(OTHER_ACCOUNT);
    const record = readFileSync(join(dataDirOf(base), 'attached-identity.json'), 'utf8');
    expect(await runEnroll(['--work-subscriptions'], deps(recorder()))).toBe(0);
    expect(readFileSync(join(dataDirOf(base), 'attached-identity.json'), 'utf8')).toBe(record);
  });
});

describe('aka enroll and aka unenroll --work-subscriptions where there is no personal-device mode', () => {
  it.each<[string, () => void, ManagedSettings | null]>([
    ['an unattached machine', () => undefined, null],
    [
      'a machine-wide attachment',
      () => {
        attach({ mode: 'machine' });
      },
      null,
    ],
    [
      'a managed machine-wide attachment',
      () => {
        attach({ mode: 'machine' });
      },
      governedBy(),
    ],
    [
      'a managed machine that still holds a scoped credential',
      () => {
        attach({ scope: fresh([enrolled()]) });
      },
      governedBy(),
    ],
  ])(
    '--work-subscriptions refuses on an unattached, machine-wide or managed machine and writes nothing (%s)',
    async (_name, arrange, managedSettings) => {
      arrange();
      for (const run of [runEnroll, runUnenroll]) {
        const before = stored();
        const io = recorder();
        expect(await run(['--work-subscriptions'], deps(io, { managedSettings }))).toBe(1);
        expect(stored()).toEqual(before);
        expect(io.output()).toBe('');
      }
      expect(settingsWrite.calls).toBe(0);
    },
  );

  it('leaves the learned work accounts of a managed device alone', async () => {
    attach({ scope: fresh() });
    knownMember();
    learn(OTHER_ACCOUNT);
    const io = recorder();
    expect(
      await runUnenroll(['--work-subscriptions'], deps(io, { managedSettings: governedBy() })),
    ).toBe(1);
    expect(io.errors()).toContain(
      'cannot be changed while an administrator manages its connection; re-attaching makes it machine-wide',
    );
    expect(readAttachedIdentity(dataDirOf(base))?.workAccounts.map((e) => e.identity)).toEqual([
      OTHER_ACCOUNT,
    ]);
  });
});

describe('aka unenroll --account — work accounts this device validated', () => {
  it('refuses a work account validated automatically and not enrolled by hand, naming the opt-out', async () => {
    attach({ scope: fresh([enrolled()]), extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    const before = stored();
    const io = recorder();
    expect(await runUnenroll(['--account', OTHER_ACCOUNT], deps(io))).toBe(1);
    expect(flat(io.errors())).toContain(
      `${OTHER_ACCOUNT} was validated automatically for Acme while this device is attached as its account; \`aka unenroll --work-subscriptions\` stops recognising work subscriptions on this device.`,
    );
    expect(stored()).toEqual(before);
  });

  it('removes the manual entry of a key also validated automatically, and says recognition continues', async () => {
    attach({ scope: fresh([codingAccount(OTHER_ACCOUNT)]), extra: webChat() });
    knownMember();
    learn(OTHER_ACCOUNT);
    const io = recorder();
    expect(await runUnenroll(['--account', OTHER_ACCOUNT], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
    expect(io.output()).toContain(
      'Automatic recognition of that account continues until `aka unenroll --work-subscriptions`.\n',
    );
  });

  it('says sessions signed in to it stop forwarding, and what is already recorded stays', async () => {
    attach({ scope: fresh([codingAccount()]), extra: webChat() });
    const io = recorder();
    expect(await runUnenroll(['--account', ACCOUNT], deps(io))).toBe(0);
    expect(flat(io.output())).toContain(
      'Sessions signed in to it stop forwarding at their next event; anything already recorded under it stays on this device, even inside enrolled repositories.',
    );
    expect(io.output()).not.toContain('Automatic recognition');
  });
});

describe('aka enroll --list-detected — the Claude Code login', () => {
  it('lists the organization signed in now, its plan hint and its state', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    knownMember();
    claudeSignIn();
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(
      `Claude Code — signed in now:\n  ${ACCOUNT}  Team or Enterprise plan  would validate\n`,
    );
  });

  it.each<[string, Record<string, unknown>, boolean, string]>([
    ['enrolled', fresh([codingAccount()]), false, 'enrolled'],
    ['validated automatically', fresh(), true, 'validated automatically'],
    [
      'off',
      { ...fresh(), workSubscriptions: 'off' },
      false,
      'would validate, but work subscriptions are off on this device',
    ],
  ])('says it is %s', async (_name, scope, learned, state) => {
    attach({ scope, extra: webChat({ grant: true }) });
    knownMember();
    if (learned) learn(ACCOUNT);
    claudeSignIn();
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(`  ${ACCOUNT}  Team or Enterprise plan  ${state}\n`);
  });

  it('prints only the key and whether it counts off a terminal', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    knownMember();
    claudeSignIn({ organizationType: 'claude_max' });
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(`Claude Code — signed in now:\n  ${ACCOUNT}  not-recognised\n`);
    expect(io.output()).not.toContain('personal plan');
  });

  it('says there is no login file off a terminal too', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    knownMember();
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain('Claude Code — signed in now:\n  none (no login file)\n');
  });

  it('says why no organization is named on a terminal, and only that none is off one', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    knownMember();
    writeFileSync(join(claudeHome, '.claude.json'), '{}');
    const interactive = recorder();
    expect(await runEnroll(['--list-detected'], deps(interactive))).toBe(0);
    expect(interactive.output()).toContain(
      'Claude Code — signed in now:\n  none (not signed in)\n',
    );
    const piped = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(piped))).toBe(0);
    expect(piped.output()).toContain('Claude Code — signed in now:\n  none\n');
  });

  it('--list-detected never prints the fixture email and writes nothing', async () => {
    attach({ scope: fresh(), extra: webChat({ grant: true }) });
    knownMember();
    claudeSignIn({}, CLAUDE_MEMBER);
    recordDetectedWebAccount(dataDirOf(base), ACCOUNT, SOURCE_TOOL.ClaudeAi);
    const homeBefore = treeOf(base);
    const claudeBefore = treeOf(claudeHome);
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    for (const address of [CLAUDE_MEMBER, SOMEONE_ELSE]) {
      expect(io.output()).not.toContain(address);
      expect(io.errors()).not.toContain(address);
    }
    expect(treeOf(base)).toEqual(homeBefore);
    expect(treeOf(claudeHome)).toEqual(claudeBefore);
    expect(settingsWrite.calls).toBe(0);
  });
});

// The commands `aka status` prints are the ones a person copies and runs. Each
// is run through the real argument parser, so a printed command the parser
// refuses fails here, and a printed key that the command does not act on does too.
describe('aka status — the commands it prints', () => {
  const claudePaths = () => ({
    home: claudeHome,
    managedSettings: join(claudeHome, 'managed-settings.json'),
  });

  async function statusText(): Promise<string> {
    const io = recorder();
    await runStatus([], {
      base,
      prompter: io,
      managedSettings: null,
      claudePaths: claudePaths(),
      codexHome,
    });
    return io.output();
  }

  const printedCommands = (text: string): string[] =>
    [...text.matchAll(/`(aka (?:enroll|unenroll)[^`]*)`/g)].flatMap((match) =>
      match[1] === undefined ? [] : [match[1]],
    );

  async function runPrinted(
    command: string,
  ): Promise<{ code: number; io: ReturnType<typeof recorder> }> {
    const [, verb, ...argv] = command.split(' ');
    const io = recorder();
    const code = await (verb === 'enroll' ? runEnroll : runUnenroll)(argv, deps(io));
    return { code, io };
  }

  it.each<[string, () => void, string[]]>([
    [
      'a device with work subscriptions on',
      () => {
        attach({ scope: fresh() });
      },
      [WORK_SUBSCRIPTION_COMMANDS.off, 'aka enroll'],
    ],
    [
      'a device with work subscriptions off',
      () => {
        attach({ scope: { ...fresh(), workSubscriptions: 'off' } });
      },
      [WORK_SUBSCRIPTION_COMMANDS.on],
    ],
    [
      'a Claude Code login that shows no plan',
      () => {
        attach({ scope: fresh() });
        knownMember();
        claudeSignIn({ organizationType: undefined });
      },
      [`aka enroll --account ${ACCOUNT}`],
    ],
    [
      'a Codex login that shows no plan',
      () => {
        attach({ scope: fresh() });
        knownMember();
        codexSignIn(undefined);
      },
      [`aka enroll --account ${CHATGPT_KEY}`],
    ],
  ])('prints commands the parser accepts for %s', async (_name, arrange, expected) => {
    arrange();
    const commands = printedCommands(await statusText());
    for (const command of expected) expect(commands).toContain(command);
    for (const command of commands) {
      const { code, io } = await runPrinted(command);
      expect(code, command).not.toBe(2);
      expect(io.errors(), command).not.toContain('Usage: aka');
    }
  });

  it('prints the same commands the two verbs are documented with', () => {
    expect(WORK_SUBSCRIPTION_COMMANDS).toEqual({
      off: 'aka unenroll --work-subscriptions',
      on: 'aka enroll --work-subscriptions',
    });
  });

  // The chats-only line tells a person to run the command again; running exactly
  // that command marks the entry, and the answer is not "already enrolled".
  it('marks an account entry stored without the marker when its printed command is run', async () => {
    attach({ scope: fresh([enrolledAccount()]), extra: webChat() });
    const printed = printedCommands(await statusText()).filter((command) =>
      command.startsWith('aka enroll --account '),
    );
    expect(printed).toEqual([`aka enroll --account ${ACCOUNT}`]);
    const { code, io } = await runPrinted(printed[0] ?? '');
    expect(code).toBe(0);
    expect(io.output()).not.toContain('Already enrolled');
    expect(storedScope()).toEqual(fresh([{ ...enrolledAccount(), codingAgents: true }]));
    expect(printedCommands(await statusText())).not.toContain(`aka enroll --account ${ACCOUNT}`);
  });
});

describe('aka status — the Claude Code login, through the command', () => {
  const claudePaths = () => ({
    home: claudeHome,
    managedSettings: join(claudeHome, 'managed-settings.json'),
  });

  async function statusText(
    options: { interactive?: boolean; cwd?: string; paths?: boolean } = {},
  ): Promise<string> {
    const io = { ...recorder(), isInteractive: options.interactive ?? true };
    const project = options.cwd;
    await runStatus([], {
      base,
      prompter: io,
      managedSettings: null,
      ...(options.paths === false ? {} : { claudePaths: claudePaths() }),
      codexHome,
      ...(project === undefined ? {} : { cwd: () => project }),
    });
    return io.output();
  }

  it('names the Claude Code login on a terminal, and collapses the line off one', async () => {
    attach({ scope: fresh() });
    knownMember();
    claudeSignIn();
    expect(await statusText()).toContain(
      '  this login Claude Code — a work subscription for the attached user — its sessions forward from any folder\n',
    );
    const piped = await statusText({ interactive: false });
    expect(piped).toContain('  this login details on an interactive terminal\n');
    expect(piped).not.toContain('Claude Code —');
  });

  it('reads the login from the Claude home it is given, not the machine it runs on', async () => {
    attach({ scope: fresh() });
    knownMember();
    expect(await statusText()).toContain('  this login Claude Code — login file not found\n');
  });

  it('reads the project settings layers of the working directory it is given', async () => {
    attach({ scope: fresh() });
    knownMember();
    claudeSignIn();
    const project = mkdtempSync(join(tmpdir(), 'aka-enroll-project-'));
    try {
      mkdirSync(join(project, '.claude'));
      writeFileSync(
        join(project, '.claude', 'settings.json'),
        JSON.stringify({ env: { CLAUDE_CODE_USE_BEDROCK: '1' } }),
      );
      expect(await statusText({ cwd: project })).toContain(
        '  this login Claude Code — an API key or another provider is in use\n',
      );
    } finally {
      removeTree(project);
    }
  });
});

describe('aka enroll --account chatgpt:', () => {
  it('enrolls a ChatGPT workspace for Codex threads, with the coding-agent marker', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('business');
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([codexAccount()]));
    const shown = io.output();
    expect(shown).toContain(`Enrolling ${CHATGPT_KEY} (${CHATGPT_LABEL}) with Acme.\n`);
    expect(shown).toContain('new Codex threads started while signed in to it');
    expect(shown).toContain('from the next new thread');
    expect(shown).toContain('A resumed thread');
    expect(shown).not.toContain('has not seen Codex');
    expect(shown).not.toContain('Web-chat capture');
    expect(shown).not.toContain('claude.ai');
  });

  it('stores the key however it was typed', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    const typed = `  ChatGPT:${CODEX_WORKSPACE.toUpperCase()} `;
    expect(await runEnroll(['--account', typed], deps(io))).toBe(0);
    expect(identities()).toEqual([CHATGPT_KEY]);
  });

  it('says when no Codex login signed in now names the workspace', async () => {
    attach({ scope: fresh() });
    knownMember();
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(io.output()).toContain('has not seen Codex signed in to that workspace');
  });

  it('reads the login from the Codex home the environment names when it is given none', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('business');
    vi.stubEnv('CODEX_HOME', codexHome);
    const listed = recorder();
    expect(await runEnroll(['--list-detected'], { ...deps(listed), codexHome: undefined })).toBe(0);
    expect(listed.output().includes(`  ${CHATGPT_KEY}  workspace plan  would validate\n`)).toBe(
      true,
    );
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], { ...deps(io), codexHome: undefined })).toBe(
      0,
    );
    expect(io.output().includes('has not seen Codex')).toBe(false);
    expect(identities()).toEqual([CHATGPT_KEY]);
  });

  it('queues no earlier captures for it, as a ChatGPT web chat carries no workspace key', async () => {
    attach({ scope: fresh(), extra: { ...webChat(), ...consent() } });
    seed.answer = 3;
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(seed.calls).toEqual([]);
    expect(io.output()).not.toContain('Queued');
  });

  it('adds the marker in place to a stored entry that lacks it', async () => {
    const stale = { kind: 'account', identity: CHATGPT_KEY, enrolledAt: NOW };
    attach({ scope: fresh([stale]) });
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(storedScope()).toEqual(fresh([{ ...stale, codingAgents: true }]));
    expect(io.output()).toContain('new Codex threads started while signed in to it');
    expect(io.output()).not.toContain('claude.ai');
  });

  it('changes nothing for a workspace already enrolled', async () => {
    attach({ scope: fresh([codexAccount()]) });
    const io = recorder();
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
    expect(identities()).toEqual([CHATGPT_KEY]);
  });

  describe('a key naming the current Codex login on a plan that is not a workspace plan', () => {
    it('shows the whole notice, then asks before enrolling on a terminal, and enrolls on yes', async () => {
      attach({ scope: fresh() });
      knownMember();
      codexSignIn('plus');
      const { io, asked, printedBefore } = answering('y');
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
      expect(asked).toEqual([CONFIRMATION]);
      expect(printedBefore).toEqual([CODEX_PLAN_NOTICE]);
      expect(identities()).toEqual([CHATGPT_KEY]);
      expect(io.output().includes('Claude Code')).toBe(false);
    });

    it('enrolls nothing when the answer is no', async () => {
      attach({ scope: fresh() });
      knownMember();
      codexSignIn('plus');
      const before = stored();
      const { io, asked, printedBefore } = answering('n');
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(1);
      expect(asked).toEqual([CONFIRMATION]);
      expect(printedBefore).toEqual([CODEX_PLAN_NOTICE]);
      expect(io.output()).toBe(`${CODEX_PLAN_NOTICE}Nothing was enrolled.\n`);
      expect(io.errors()).toBe('');
      expect(stored()).toEqual(before);
    });

    it('asks even before this device knows who attached it', async () => {
      attach({ scope: fresh() });
      codexSignIn('plus');
      const io = { ...recorder(), isInteractive: false };
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(1);
      expectNoPlanNotice(io);
      expect(identities()).toEqual([]);
    });

    it('refuses without a terminal unless --yes, and writes nothing', async () => {
      attach({ scope: fresh() });
      knownMember();
      codexSignIn('plus');
      const before = stored();
      const io = { ...recorder(), isInteractive: false };
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(1);
      expect(io.errors()).toContain('Run this on a terminal to confirm, or add --yes.');
      expectNoPlanNotice(io);
      expect(stored()).toEqual(before);
      const yes = { ...recorder(), isInteractive: false };
      expect(await runEnroll(['--account', CHATGPT_KEY, '--yes'], deps(yes))).toBe(0);
      expectNoPlanNotice(yes);
      expect(identities()).toEqual([CHATGPT_KEY]);
    });

    it('asks nothing for a workspace already enrolled for Codex threads', async () => {
      attach({ scope: fresh([codexAccount()]) });
      knownMember();
      codexSignIn('plus');
      const io = { ...recorder(), isInteractive: false };
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
      expect(io.output()).toContain('Already enrolled with Acme; nothing changed.\n');
      expect(exits).toEqual([]);
    });

    it('asks nothing for a workspace plan, or for a key the login signed in now does not name', async () => {
      attach({ scope: fresh() });
      knownMember();
      codexSignIn('business');
      expect(await runEnroll(['--account', CHATGPT_KEY], deps(recorder()))).toBe(0);
      codexSignIn('plus');
      const other = `chatgpt:${randomUUID()}`;
      expect(await runEnroll(['--account', other], deps(recorder()))).toBe(0);
      expect(identities()).toEqual([CHATGPT_KEY, other]);
    });

    describe('while a key, a token or a gateway is set for Codex', () => {
      const vetoes: [string, string, string][] = [
        ['a key', 'CODEX_API_KEY', randomUUID()],
        ['a token', 'CODEX_ACCESS_TOKEN', randomUUID()],
        ['a gateway address', 'OPENAI_BASE_URL', 'https://gateway.example.com/v1'],
      ];

      it.each(vetoes)(
        'asks before enrolling it under %s, and enrolls on yes',
        async (_n, name, value) => {
          attach({ scope: fresh() });
          knownMember();
          codexSignIn('plus');
          vi.stubEnv(name, value);
          const { io, asked, printedBefore } = answering('y');
          expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
          expect(asked).toEqual([CONFIRMATION]);
          expect(printedBefore).toEqual([CODEX_PLAN_NOTICE]);
          expect(identities()).toEqual([CHATGPT_KEY]);
        },
      );

      it.each(vetoes)('needs --yes without a terminal under %s', async (_n, name, value) => {
        attach({ scope: fresh() });
        knownMember();
        codexSignIn('plus');
        vi.stubEnv(name, value);
        const before = stored();
        const io = { ...recorder(), isInteractive: false };
        expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(1);
        expect(io.errors().includes('Run this on a terminal to confirm, or add --yes.')).toBe(true);
        expectNoPlanNotice(io);
        expect(stored()).toEqual(before);
        const yes = { ...recorder(), isInteractive: false };
        expect(await runEnroll(['--account', CHATGPT_KEY, '--yes'], deps(yes))).toBe(0);
        expect(identities()).toEqual([CHATGPT_KEY]);
      });

      it('asks nothing for a workspace plan, and does not say the device has not seen the login', async () => {
        attach({ scope: fresh() });
        knownMember();
        codexSignIn('business');
        vi.stubEnv('CODEX_API_KEY', randomUUID());
        const io = recorder();
        expect(await runEnroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
        expect(io.output().includes('has not seen Codex')).toBe(false);
        expect(identities()).toEqual([CHATGPT_KEY]);
      });

      it('lists the login with its plan hint, and says why it does not count', async () => {
        attach({ scope: fresh() });
        knownMember();
        codexSignIn('plus');
        vi.stubEnv('CODEX_API_KEY', randomUUID());
        const io = recorder();
        expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
        expect(
          io
            .output()
            .includes(
              `Codex — signed in now:\n  ${CHATGPT_KEY}  not a workspace plan  an API key or another provider is in use\n`,
            ),
        ).toBe(true);
        const piped = { ...recorder(), isInteractive: false };
        expect(await runEnroll(['--list-detected'], deps(piped))).toBe(0);
        expect(
          piped.output().includes(`Codex — signed in now:\n  ${CHATGPT_KEY}  not-recognised\n`),
        ).toBe(true);
      });
    });
  });

  it('is undone by aka unenroll --account, like any entry enrolled by hand', async () => {
    attach({ scope: fresh() });
    expect(await runEnroll(['--account', CHATGPT_KEY], deps(recorder()))).toBe(0);
    expect(await runUnenroll(['--account', CHATGPT_KEY], deps(recorder()))).toBe(0);
    expect(identities()).toEqual([]);
  });

  it('is taken out by aka unenroll --account naming Codex threads, and says nothing of chats', async () => {
    attach({ scope: fresh([codexAccount()]) });
    const io = recorder();
    expect(await runUnenroll(['--account', CHATGPT_KEY], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
    const shown = io.output();
    expect(
      shown.includes(
        `Unenrolled ${CHATGPT_KEY}. From now on, Codex threads signed in to it are not sent to Acme by this entry.\n`,
      ),
    ).toBe(true);
    expect(shown.includes('chats')).toBe(false);
    expect(shown.includes('claude.ai')).toBe(false);
  });

  it('is taken out by aka unenroll --account from an entry stored in another case, typed as stored', async () => {
    const stored = `chatgpt:${CODEX_WORKSPACE.toUpperCase()}`;
    attach({ scope: fresh([codexAccount(stored)]) });
    const io = recorder();
    expect(await runUnenroll(['--account', stored], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
    expect(
      io
        .output()
        .startsWith(
          `Unenrolled ${stored}. From now on, Codex threads signed in to it are not sent to Acme by this entry.\n`,
        ),
    ).toBe(true);
  });

  it('is taken out by aka unenroll --account from an entry stored under a key enroll refuses, and worded as Codex threads', async () => {
    attach({ scope: fresh([codexAccount('chatgpt:payments')]) });
    const io = recorder();
    expect(await runUnenroll(['--account', 'chatgpt:payments'], deps(io))).toBe(0);
    expect(identities()).toEqual([]);
    expect(
      io
        .output()
        .startsWith(
          'Unenrolled chatgpt:payments. From now on, Codex threads signed in to it are not sent to Acme by this entry.\n',
        ),
    ).toBe(true);
  });

  it('names both key forms when it refuses a key', async () => {
    attach({ scope: fresh() });
    const io = recorder();
    expect(await runEnroll(['--account', 'payments'], deps(io))).toBe(1);
    expect(io.errors()).toContain('claude:<organization-id>');
    expect(io.errors()).toContain('chatgpt:<workspace-id>');
  });

  it('names a ChatGPT workspace in the usage text of both verbs', async () => {
    const enrollUsage = recorder();
    expect(await runEnroll(['--everything'], deps(enrollUsage))).toBe(2);
    expect(enrollUsage.errors()).toContain('chatgpt:workspace-id');
    const unenrollUsage = recorder();
    expect(await runUnenroll(['--everything'], deps(unenrollUsage))).toBe(2);
    expect(unenrollUsage.errors()).toContain('chatgpt:workspace-id');
  });
});

describe('aka enroll --list-detected — the Codex login', () => {
  it('lists the workspace signed in now, its plan hint and its state', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('business');
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    const shown = io.output();
    expect(shown).toContain('Codex — signed in now:\n');
    expect(shown).toContain(`  ${CHATGPT_KEY}  workspace plan  would validate\n`);
  });

  it.each<[string, Record<string, unknown>, boolean, string]>([
    ['enrolled', fresh([codexAccount()]), false, 'enrolled'],
    ['validated automatically', fresh(), true, 'validated automatically'],
    [
      'off',
      { ...fresh(), workSubscriptions: 'off' },
      false,
      'would validate, but work subscriptions are off on this device',
    ],
  ])('says it is %s', async (_name, scope, learned, state) => {
    attach({ scope });
    knownMember();
    if (learned) learn(CHATGPT_KEY);
    codexSignIn('business');
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(`  ${CHATGPT_KEY}  workspace plan  ${state}\n`);
  });

  it('gives the plan hint of a login that is not on a workspace plan, with its reason', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('plus');
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(`  ${CHATGPT_KEY}  not a workspace plan  not a workspace plan\n`);
  });

  // A coding agent's own terminal output is recorded, so off a terminal no reason is
  // printed: a personal plan reads the same as any other login that does not count.
  it('prints only the key and whether it counts off a terminal', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('plus');
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(`Codex — signed in now:\n  ${CHATGPT_KEY}  not-recognised\n`);
    expect(io.output()).not.toContain('not a workspace plan');
  });

  it('never prints the login address or the plan string, and writes nothing', async () => {
    attach({ scope: fresh() });
    knownMember();
    const login = codexSignIn('business');
    const homeBefore = treeOf(base);
    const codexBefore = treeOf(codexHome);
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    const shown = io.output() + io.errors();
    expect(shown.includes(CLAUDE_MEMBER)).toBe(false);
    expect(shown.includes('business')).toBe(false);
    for (const secret of [login.jwt.token, ...login.secrets]) {
      expect(shown.includes(secret)).toBe(false);
    }
    expect(treeOf(base)).toEqual(homeBefore);
    expect(treeOf(codexHome)).toEqual(codexBefore);
    expect(settingsWrite.calls).toBe(0);
  });

  it('says there is no login file when Codex has none', async () => {
    attach({ scope: fresh() });
    knownMember();
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain('Codex — signed in now:\n  none (no login file)\n');
  });

  it('says why no login is named on a terminal, and only that none is off one', async () => {
    attach({ scope: fresh() });
    knownMember();
    vi.stubEnv('CODEX_API_KEY', randomUUID());
    const interactive = recorder();
    expect(await runEnroll(['--list-detected'], deps(interactive))).toBe(0);
    expect(interactive.output()).toContain(
      'Codex — signed in now:\n  none (an API key or another provider is in use)\n',
    );
    const piped = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(piped))).toBe(0);
    expect(piped.output()).toContain('Codex — signed in now:\n  none\n');
  });

  it('says there is no login file off a terminal too', async () => {
    attach({ scope: fresh() });
    knownMember();
    const io = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain('Codex — signed in now:\n  none (no login file)\n');
  });

  it('says a login file that is not a ChatGPT login cannot be read on a terminal, and only that none is named off one', async () => {
    attach({ scope: fresh() });
    knownMember();
    writeCodexAuth(codexHome, {
      accountId: CODEX_WORKSPACE,
      email: CLAUDE_MEMBER,
      authMode: 'apikey',
    });
    const interactive = recorder();
    expect(await runEnroll(['--list-detected'], deps(interactive))).toBe(0);
    expect(interactive.output()).toContain(
      'Codex — signed in now:\n  none (not a ChatGPT login this device can read)\n',
    );
    const piped = { ...recorder(), isInteractive: false };
    expect(await runEnroll(['--list-detected'], deps(piped))).toBe(0);
    expect(piped.output()).toContain('Codex — signed in now:\n  none\n');
  });

  it('reads a login file that is not a ChatGPT login as a veto while a key is set', async () => {
    attach({ scope: fresh() });
    knownMember();
    writeCodexAuth(codexHome, {
      accountId: CODEX_WORKSPACE,
      email: CLAUDE_MEMBER,
      authMode: 'apikey',
    });
    vi.stubEnv('CODEX_API_KEY', randomUUID());
    const io = recorder();
    expect(await runEnroll(['--list-detected'], deps(io))).toBe(0);
    expect(io.output()).toContain(
      'Codex — signed in now:\n  none (an API key or another provider is in use)\n',
    );
  });

  it('reads a Codex home that cannot be used as a veto, not as no login file, while a key is set', async () => {
    attach({ scope: fresh() });
    knownMember();
    const notADirectory = join(work, 'codex-home-is-a-file');
    writeFileSync(notADirectory, '');
    vi.stubEnv('CODEX_HOME', notADirectory);
    vi.stubEnv('CODEX_API_KEY', randomUUID());
    const io = recorder();
    expect(await runEnroll(['--list-detected'], { ...deps(io), codexHome: undefined })).toBe(0);
    expect(io.output()).toContain(
      'Codex — signed in now:\n  none (an API key or another provider is in use)\n',
    );
  });
});

describe('aka status — the Codex login, through the command', () => {
  async function statusText(
    options: { interactive?: boolean; codexHome?: boolean } = {},
  ): Promise<string> {
    const io = { ...recorder(), isInteractive: options.interactive ?? true };
    await runStatus([], {
      base,
      prompter: io,
      managedSettings: null,
      claudePaths: { home: claudeHome, managedSettings: join(claudeHome, 'managed-settings.json') },
      ...(options.codexHome === false ? {} : { codexHome }),
    });
    return io.output();
  }

  it('names the Codex login on a terminal, and collapses the line off one', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('business');
    expect(await statusText()).toContain(
      'Codex — a work subscription for the attached user — its new threads forward from any folder\n',
    );
    const piped = await statusText({ interactive: false });
    expect(piped).toContain('  this login details on an interactive terminal\n');
    expect(piped).not.toContain('Codex —');
  });

  it('lines the Codex login up under the Claude Code one', async () => {
    attach({ scope: fresh() });
    knownMember();
    claudeSignIn();
    codexSignIn('business');
    expect(await statusText()).toContain(
      '  this login Claude Code — a work subscription for the attached user — its sessions forward from any folder\n' +
        '             Codex — a work subscription for the attached user — its new threads forward from any folder\n',
    );
  });

  it('reads the login from the Codex home it is given, not the machine it runs on', async () => {
    attach({ scope: fresh() });
    knownMember();
    expect(await statusText()).toContain('Codex — login file not found\n');
  });

  it('resolves the Codex home from the Codex environment when it is given none', async () => {
    attach({ scope: fresh() });
    knownMember();
    codexSignIn('business');
    vi.stubEnv('CODEX_HOME', codexHome);
    expect(await statusText({ codexHome: false })).toContain(
      'Codex — a work subscription for the attached user — its new threads forward from any folder\n',
    );
  });

  it('prints the Codex line, and --list-detected the same finding, when CODEX_HOME is not a usable directory', async () => {
    attach({ scope: fresh() });
    knownMember();
    const notADirectory = join(work, 'codex-home-is-a-file');
    writeFileSync(notADirectory, '');
    vi.stubEnv('CODEX_HOME', notADirectory);
    expect(await statusText({ codexHome: false })).toContain('Codex — login file not found\n');
    const io = recorder();
    expect(await runEnroll(['--list-detected'], { ...deps(io), codexHome: undefined })).toBe(0);
    expect(io.output()).toContain('Codex — signed in now:\n  none (no login file)\n');
  });
});

describe('defaultLabel', () => {
  it('uses the slug as it is when it fits', () => {
    expect(defaultLabel('payments-api')).toBe('payments-api');
  });

  it('cuts a long name to the eighty characters a label may hold', () => {
    expect(defaultLabel('r'.repeat(100))).toBe('r'.repeat(80));
  });

  it('never splits a character at the cut', () => {
    expect(defaultLabel(`${'r'.repeat(79)}${GRINNING_FACE}`)).toBe('r'.repeat(79));
  });

  it('omits a label the schema refuses, and one there is nothing to make from', () => {
    expect(defaultLabel(`pay${ZERO_WIDTH_SPACE}ments`)).toBeUndefined();
    expect(defaultLabel('')).toBeUndefined();
    expect(defaultLabel(undefined)).toBeUndefined();
  });
});

describe('registration', () => {
  it('registers the forms in the hint, not as command-owned flags', () => {
    const enroll = COMMAND_SPECS.find((spec) => spec.name === 'enroll');
    const unenroll = COMMAND_SPECS.find((spec) => spec.name === 'unenroll');
    expect(enroll?.argHint).toContain('--repo');
    expect(enroll?.argHint).toContain('--list');
    expect(unenroll?.argHint).toContain('--repo');
    // The help prints a command's own flags on the one line under it, so a
    // second flag declared here would be filed under nothing.
    expect(enroll?.flags).toBeUndefined();
    expect(unenroll?.flags).toBeUndefined();
  });

  describe('main', () => {
    let exitCode: typeof process.exitCode;
    beforeEach(() => {
      exitCode = process.exitCode;
      vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    });
    afterEach(() => {
      vi.restoreAllMocks();
      // The default exit sets process.exitCode; left set, it would fail the run.
      process.exitCode = exitCode;
    });

    it.each(['enroll', 'unenroll'])('dispatches %s to its own handler', async (verb) => {
      const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      // An external `aka-<verb>` that would answer if the built-in were missing.
      const spawn = vi.fn().mockReturnValue({ status: 0 }) as ExternalSpawn &
        ReturnType<typeof vi.fn>;
      await main([verb, '--home', base], { spawn, platform: 'darwin', exists: () => false });
      const written = stderr.mock.calls.map((call) => String(call[0])).join('');
      expect(spawn).not.toHaveBeenCalled();
      expect(written).toContain('not attached to a deployment');
      expect(process.exitCode).toBe(1);
    });
  });
});

describe('enroll.ts', () => {
  // The verbs are local: they change settings and contact nothing. The CLI's
  // privacy footnote counts the paths that reach a network, and these are not
  // among them, so nothing in this file may open one. A module is named with or
  // without the `node:` prefix, so both are matched.
  const TRANSPORT_IMPORT = /(?:from |import\()'(?:node:)?(?:http|https|http2|net|tls|dgram)'/;

  it.each([
    "import http from 'http';",
    "import { request } from 'node:https';",
    "import { connect } from 'net';",
    "import { connect } from 'node:tls';",
    "const dgram = await import('dgram');",
    "import { connect } from 'node:http2';",
  ])('the transport check recognises %s', (line) => {
    expect(line).toMatch(TRANSPORT_IMPORT);
  });

  it.each([
    "import { join } from 'node:path';",
    "import { runEnroll } from './http.ts';",
    "import { network } from 'netmask';",
  ])('the transport check leaves %s alone', (line) => {
    expect(line).not.toMatch(TRANSPORT_IMPORT);
  });

  it('imports no transport and calls no fetch', () => {
    const source = readFileSync(new URL('../../src/commands/enroll.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/from '@akasecurity\/remote'/);
    expect(source).not.toMatch(TRANSPORT_IMPORT);
    expect(source).not.toMatch(/\bfetch\(/);
  });
});

describe('quotedForShell', () => {
  it.each(['src/acme/payments-api', 'a_b-c.d:e=f,g+h@i%j', '/tmp/x/y'])(
    'leaves the plain word %s as it is',
    (word) => {
      expect(quotedForShell(word, 'linux')).toBe(word);
    },
  );

  it.each([
    'my projects/x',
    'a(b)',
    'a&b',
    'a;b',
    'a|b',
    'a<b>c',
    '$HOME/x',
    '$(rm -rf x)',
    'a`b`',
    'a*b',
    'a?b',
    '~/x',
    'a#b',
    'a!b',
    'a\\b',
    'a"b',
  ])('single-quotes %s for a POSIX shell', (word) => {
    expect(quotedForShell(word, 'linux')).toBe(`'${word}'`);
  });

  it('closes, escapes and reopens a single quote inside the word', () => {
    expect(quotedForShell("it's here", 'darwin')).toBe(`'it'\\''s here'`);
  });

  it('double-quotes for a Windows shell', () => {
    expect(quotedForShell('my projects\\x', 'win32')).toBe('"my projects\\x"');
    expect(quotedForShell('plain/word', 'win32')).toBe('plain/word');
  });
});
