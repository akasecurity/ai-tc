import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { HistorySyncState } from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
  writeHistorySyncState,
} from '@akasecurity/persistence';
import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  HISTORY_SYNC_PAYLOAD_VERSION,
  MANAGED_SETTINGS_FILENAME,
  parseAttachmentScope,
  resolveScope,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../persistence/src/managed-settings.ts';
import { renderAttachedStatus } from '../../src/attached/status.ts';
import {
  attachmentScopeLines,
  endpointForTerminal,
  printableForTerminal,
} from '../../src/index.ts';

// What `aka status` says about an attachment's mode and enrolled scope: the
// mode, what is enrolled, every state in which the list forwards no activity,
// what the record does not limit, and the address lines that name the
// deployment. Each renderer case writes a real settings file and a real
// credential file and reads them back through the renderer, so a red here is
// the renderer's.

const ENDPOINT = 'https://aka.acme.test';
const OLD_ENDPOINT = 'https://aka.old.test';
const TEST_KEY = 'not-a-real-key';
const ENROLLED_AT = '2026-10-07T09:30:00.000Z';
const WORK_REPO = 'github.com/acme/payments-api';
const SECOND_REPO = 'github.com/acme/billing-worker';
// A scope entry of the other kind, a web-chat workspace. Nothing in this build
// writes one; a newer build or a hand edit can.
const ACCOUNT = 'example-chat:acme-workspace';
// The binding a scoped attach records. The account is any printable string to
// the schema; nothing here reads it as an address.
const MEMBER = { tenantName: 'Acme', userEmail: 'member-of-acme' } as const;
const ESC = String.fromCharCode(0x1b);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
// A part of a recorded address that must never reach the screen.
const HIDDEN = 'hiddenpart';
const NOT_LIMITED =
  '             the policy pull and the device report are not limited to what is enrolled';
// The three states of the list itself that forward no activity. Each has its own
// headline, because what to do about one is not what to do about another.
const MISSING_HEADLINE = '  scope      no enrolled list is stored — no activity is sent';
const MISSING_LIST = [
  MISSING_HEADLINE,
  '             (run `aka enroll` inside a work repository to add it; an aka older than 0.9.16 also',
  '             drops the list when it saves settings)',
];
const UNREADABLE_HEADLINE =
  '  scope      the enrolled list cannot be read by this aka — it sends no activity under it';
const UNREADABLE_LIST = [
  UNREADABLE_HEADLINE,
  '             (it may have been written by a newer aka)',
];
const EMPTY_HEADLINE = '  scope      nothing enrolled yet — no activity is sent';

let root: string;
let settingsDir: string;
let dataDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-status-scope-'));
  settingsDir = settingsDirOf(root);
  dataDir = dataDirOf(root);
  mkdirSync(settingsDir, { recursive: true });
  mkdirSync(dataDir, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function entry(identity: string, label?: string): Record<string, string> {
  return {
    kind: 'repo',
    identity,
    enrolledAt: ENROLLED_AT,
    ...(label === undefined ? {} : { label }),
  };
}

function bound(entries: unknown[] = []): Record<string, unknown> {
  return { endpoint: ENDPOINT, ...MEMBER, entries };
}

function attach(
  mode: 'machine' | 'scoped',
  scope?: unknown,
  extra: Partial<WorkspaceSettings> = {},
  credentialEndpoint = ENDPOINT,
): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label: 'Acme', attachedAt: '2026-10-01T09:00:00.000Z' },
      ...(scope === undefined ? {} : { attachmentScope: scope }),
      ...extra,
    },
    root,
    // No managed overlay: an administrator's file on the machine running this
    // suite must not decide what it sees.
    null,
  );
  writeControlPlaneCredential(
    settingsDir,
    mode === 'scoped'
      ? {
          specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
          mode: 'scoped',
          endpoint: credentialEndpoint,
          apiKey: TEST_KEY,
        }
      : {
          specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION,
          endpoint: credentialEndpoint,
          apiKey: TEST_KEY,
        },
  );
}

const status = (): string => renderAttachedStatus({ base: root, settingsDir, dataDir });

describe('printableForTerminal', () => {
  it('strips control and format characters and bounds what is left', () => {
    expect(printableForTerminal(`Acme${ESC}[2J`)).toBe('Acme[2J');
    expect(printableForTerminal(`pay${ZERO_WIDTH_SPACE}ments`)).toBe('payments');
    expect(printableForTerminal('x'.repeat(80))).toBe('x'.repeat(80));
    expect(printableForTerminal('x'.repeat(81))).toBe(`${'x'.repeat(80)}…`);
    expect(printableForTerminal('abcdef', 3)).toBe('abc…');
  });
});

describe('endpointForTerminal', () => {
  it.each<[string, string]>([
    ['https://aka.old.test', 'https://aka.old.test'],
    ['https://aka.old.test/', 'https://aka.old.test/'],
    ['https://AKA.old.test', 'https://AKA.old.test'],
    ['https://aka.old.test/v1', 'https://aka.old.test/v1'],
    ['http://localhost:4000', 'http://localhost:4000'],
  ])('prints %s as stored', (stored, shown) => {
    expect(endpointForTerminal(stored)).toBe(shown);
  });

  it.each<[string, string]>([
    ['a username', `https://${HIDDEN}@aka.old.test`],
    ['a query', `https://aka.old.test/?t=${HIDDEN}`],
    ['a fragment', `https://aka.old.test/#${HIDDEN}`],
    ['an empty query', 'https://aka.old.test/?'],
    ['an empty fragment', 'https://aka.old.test/#'],
  ])('prints only the origin of an address with %s', (_name, stored) => {
    expect(endpointForTerminal(stored)).toBe('https://aka.old.test, rest not shown');
  });

  it.each(['', 'aka.old.test', `mailto:${HIDDEN}@aka.old.test`, `ftp://${HIDDEN}@aka.old.test`])(
    'prints a placeholder for %j',
    (stored) => {
      expect(endpointForTerminal(stored)).toBe('address not shown');
    },
  );

  it('strips control characters from an address it prints, and bounds it', () => {
    expect(endpointForTerminal(`https://aka.old.test/${ESC}[2J`)).toBe('https://aka.old.test/[2J');
    const long = `https://aka.old.test/${'p'.repeat(300)}`;
    expect(endpointForTerminal(long)).toBe(`${long.slice(0, 200)}…`);
  });
});

describe('renderAttachedStatus — the attachment mode', () => {
  it('names a machine-wide attachment, and prints no scope for it', () => {
    attach('machine', bound([entry(WORK_REPO)]));
    const out = status();
    expect(out.split('\n')[0]).toBe('AKA: attached');
    expect(out).toMatch(/^ {2}mode {7}machine \(activity from anywhere on this machine\)$/m);
    expect(out).not.toMatch(/^ {2}scope /m);
    expect(out).not.toContain(WORK_REPO);
  });

  it('names a scoped attachment', () => {
    attach('scoped', bound());
    expect(status()).toMatch(/^ {2}mode {7}scoped \(activity only from what is enrolled\)$/m);
  });

  it('names a scoped attachment without naming the kind of entry it enrolls', () => {
    attach('scoped', bound([{ kind: 'account', identity: ACCOUNT, enrolledAt: ENROLLED_AT }]));
    const out = status();
    expect(out).toMatch(/^ {2}mode {7}scoped \(activity only from what is enrolled\)$/m);
    expect(out).toContain(`\n             ${ACCOUNT}, enrolled 2026-10-07\n`);
    expect(out).not.toContain('repositories only');
  });

  it('prints no mode for a credential it cannot use', () => {
    attach('scoped', bound([entry(WORK_REPO)]), {}, OLD_ENDPOINT);
    const out = status();
    expect(out.split('\n')[0]).toBe(
      'AKA: attached — credential is for another deployment, re-attach',
    );
    expect(out).not.toMatch(/^ {2}mode /m);
    expect(out).not.toMatch(/^ {2}scope /m);
    expect(out).not.toContain(TEST_KEY);
  });

  it.each(['machine', 'scoped'] as const)(
    'names the endpoint beside a labelled deployment on a %s attachment',
    (mode) => {
      attach(mode, mode === 'scoped' ? bound() : undefined);
      const out = status();
      expect(out).toMatch(/^ {2}plane {6}Acme$/m);
      expect(out).toMatch(/^ {2}endpoint {3}https:\/\/aka\.acme\.test$/m);
    },
  );

  it('prints no second endpoint line when the plane line already is the endpoint', () => {
    attach('scoped', bound());
    // The same connection with no label: `plane` then names the endpoint itself.
    applyOnboarding(
      { controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-10-01T09:00:00.000Z' } },
      root,
      null,
    );
    const out = status();
    expect(out).toMatch(/^ {2}plane {6}https:\/\/aka\.acme\.test$/m);
    expect(out).not.toMatch(/^ {2}endpoint /m);
  });
});

describe('renderAttachedStatus — the plane line without a label', () => {
  // The settings address is checked when settings are saved through the product,
  // not when the file is edited by hand or an overlay pins it. With no label the
  // plane line names the deployment by that address, so it must not echo what an
  // address must never show.
  function editPlaneEndpoint(endpoint: string): void {
    const file = join(settingsDir, SETTINGS_FILENAME);
    const stored = JSON.parse(readFileSync(file, 'utf8')) as {
      controlPlane: Record<string, unknown>;
    };
    delete stored.controlPlane.label;
    stored.controlPlane.endpoint = endpoint;
    writeFileSync(file, JSON.stringify(stored));
  }

  it.each<[string, string, string]>([
    ['a username', `https://${HIDDEN}@aka.acme.test`, 'https://aka.acme.test, rest not shown'],
    ['a query', `https://aka.acme.test/?t=${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['a fragment', `https://aka.acme.test/#${HIDDEN}`, 'https://aka.acme.test, rest not shown'],
    ['no scheme', `${HIDDEN}@aka.acme.test`, 'address not shown'],
  ])('names a deployment whose address has %s without echoing it', (_name, endpoint, shown) => {
    attach('machine');
    editPlaneEndpoint(endpoint);
    const out = status();
    expect(out).toContain(`\n  plane      ${shown}\n`);
    expect(out).not.toContain(HIDDEN);
  });

  it.each(['https://aka.acme.test', 'https://aka.acme.test/', 'https://AKA.acme.test'])(
    'prints the clean address %s as stored',
    (endpoint) => {
      attach('machine');
      editPlaneEndpoint(endpoint);
      expect(status()).toContain(`\n  plane      ${endpoint}\n`);
    },
  );
});

describe('renderAttachedStatus — a machine that became managed after a scoped attach', () => {
  // The renderer reads the settings in force through the default managed read,
  // so an administrator's file is written and that read pointed at it. Until
  // the next attach the credential is still scoped and the forward paths still
  // filter by the list, so status must keep saying so.
  afterEach(() => {
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
  });

  it('still names the scoped mode and the enrolled list', () => {
    attach('scoped', bound([entry(WORK_REPO)]));
    const file = join(root, MANAGED_SETTINGS_FILENAME);
    writeFileSync(
      file,
      JSON.stringify({
        specVersion: 1,
        organization: 'Acme IT',
        values: { controlPlane: { endpoint: ENDPOINT, label: 'Acme' } },
      }),
    );
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);

    const out = status();
    expect(out).toMatch(/^ {2}mode {7}scoped \(activity only from what is enrolled\)$/m);
    expect(out).toContain(`\n             ${WORK_REPO}, enrolled 2026-10-07\n`);
  });
});

describe('renderAttachedStatus — the enrolled scope', () => {
  it('lists each enrolled repository with its label and the day it was enrolled', () => {
    attach('scoped', bound([entry(WORK_REPO, 'payments-api'), entry(SECOND_REPO)]));
    const out = status();
    expect(out).toMatch(
      /^ {2}scope {6}2 enrolled — activity anywhere else stays on this machine$/m,
    );
    expect(out).toContain(`\n             ${WORK_REPO} (payments-api), enrolled 2026-10-07\n`);
    expect(out).toContain(`\n             ${SECOND_REPO}, enrolled 2026-10-07\n`);
    expect(out).not.toContain('not tied to an account');
    expect(out).not.toContain('this version cannot read');
  });

  it('says no list is stored when no scope is recorded', () => {
    attach('scoped');
    const out = status();
    expect(out).toContain(`\n${MISSING_LIST.join('\n')}\n`);
    expect(out).not.toMatch(/^ {2}scope {6}nothing enrolled/m);
  });

  it('says the list cannot be read when the stored scope is not a record at all', () => {
    attach('scoped', 'not-a-scope-record');
    const out = status();
    expect(out).toContain(`\n${UNREADABLE_LIST.join('\n')}\n`);
    expect(out).not.toMatch(/^ {2}scope {6}nothing enrolled/m);
  });

  it('says a freshly recorded scope enrolls nothing yet', () => {
    attach('scoped', bound());
    const out = status();
    expect(out).toMatch(/^ {2}scope {6}nothing enrolled yet — no activity is sent$/m);
    expect(out).toContain('(run `aka enroll` inside a work repository to add it)');
  });

  it('reads a scope recorded for another deployment as sending no activity', () => {
    attach('scoped', { endpoint: OLD_ENDPOINT, ...MEMBER, entries: [entry(WORK_REPO)] });
    const out = status();
    expect(out).toMatch(
      /^ {2}scope {6}recorded for another deployment \(https:\/\/aka\.old\.test\)$/m,
    );
    expect(out).toContain('— no activity is sent here (run `aka enroll` to enroll for this one)');
    expect(out).not.toContain('nothing is sent here');
    expect(out).not.toContain(WORK_REPO);
  });

  // The recorded endpoint is any non-empty string to the schema, so it can carry
  // a terminal escape. It is echoed on the line naming the other deployment.
  it('strips control characters from the endpoint a foreign scope names', () => {
    attach('scoped', {
      endpoint: `${OLD_ENDPOINT}/${ESC}[2J`,
      ...MEMBER,
      entries: [entry(WORK_REPO)],
    });
    const out = status();
    expect(out).not.toContain(ESC);
    expect(out).toMatch(
      /^ {2}scope {6}recorded for another deployment \(https:\/\/aka\.old\.test\/\[2J\)$/m,
    );
  });

  it.each<[string, string, string]>([
    ['a username', `https://${HIDDEN}@aka.old.test`, 'https://aka.old.test, rest not shown'],
    ['a query', `https://aka.old.test/?t=${HIDDEN}`, 'https://aka.old.test, rest not shown'],
    ['a fragment', `https://aka.old.test/#${HIDDEN}`, 'https://aka.old.test, rest not shown'],
    ['no scheme', `${HIDDEN}@aka.old.test`, 'address not shown'],
    ['another scheme', `mailto:${HIDDEN}@aka.old.test`, 'address not shown'],
    ['a control character in its host', `${OLD_ENDPOINT}${ESC}[2J`, 'address not shown'],
  ])('names a foreign scope recorded with %s without echoing it', (_name, recorded, shown) => {
    attach('scoped', { endpoint: recorded, ...MEMBER, entries: [entry(WORK_REPO)] });
    const out = status();
    expect(out).toContain(`\n  scope      recorded for another deployment (${shown})\n`);
    expect(out).not.toContain(HIDDEN);
    expect(out).not.toContain(ESC);
    expect(out).not.toContain(WORK_REPO);
  });

  it.each<[string, unknown[], string]>([
    [
      'one',
      [
        entry(WORK_REPO),
        { kind: 'workspace', identity: 'acme-workspace', enrolledAt: ENROLLED_AT },
      ],
      '1 entry',
    ],
    [
      'two',
      [
        entry(WORK_REPO),
        { kind: 'workspace', identity: 'acme-workspace', enrolledAt: ENROLLED_AT },
        { kind: 'repo', identity: '', enrolledAt: ENROLLED_AT },
      ],
      '2 entries',
    ],
  ])('counts %s unreadable entries without printing them', (_name, entries, counted) => {
    attach('scoped', bound(entries));
    const out = status();
    expect(out).toMatch(
      /^ {2}scope {6}1 enrolled — activity anywhere else stays on this machine$/m,
    );
    expect(out).toContain(`\n             ${counted} this version cannot read — not sent`);
    expect(out).not.toContain('acme-workspace');
  });

  it.each<[string, Record<string, unknown>]>([
    ['no account at all', { endpoint: ENDPOINT, entries: [entry(WORK_REPO)] }],
    [
      'an organization and no account',
      { endpoint: ENDPOINT, tenantName: 'Acme', entries: [entry(WORK_REPO)] },
    ],
    [
      'an account and no organization',
      { endpoint: ENDPOINT, userEmail: 'member-of-acme', entries: [entry(WORK_REPO)] },
    ],
    [
      'an empty account',
      { endpoint: ENDPOINT, tenantName: 'Acme', userEmail: '', entries: [entry(WORK_REPO)] },
    ],
  ])('says a scope with %s is not tied to an account', (_name, scope) => {
    attach('scoped', scope);
    const out = status();
    expect(out).toContain(`\n             ${WORK_REPO}, enrolled 2026-10-07\n`);
    expect(out).toContain(
      '             not tied to an account — the next `aka attach` starts it empty',
    );
  });

  // A binding that is present but not a printable string fails the whole
  // record, so the machine forwards nothing from it. The block must say that
  // and must not list the entries the record still holds.
  it.each<[string, Record<string, unknown>]>([
    [
      'an account that is not a string',
      { endpoint: ENDPOINT, tenantName: 'Acme', userEmail: 42, entries: [entry(WORK_REPO)] },
    ],
    [
      'an organization with a control character',
      {
        endpoint: ENDPOINT,
        tenantName: `Acme${ESC}[2J`,
        userEmail: 'member-of-acme',
        entries: [entry(WORK_REPO)],
      },
    ],
  ])(
    'lists nothing as enrolled for a record with %s, as the forward verdict does',
    (_name, scope) => {
      attach('scoped', scope);
      const out = status();
      expect(resolveScope({ mode: 'scoped', scope, endpoint: ENDPOINT }).keys.size).toBe(0);
      expect(out).toContain(`\n${UNREADABLE_LIST.join('\n')}\n`);
      expect(out).not.toMatch(/^ {2}scope {6}\d+ enrolled/m);
      expect(out).not.toContain(WORK_REPO);
      expect(out).not.toContain('not tied to an account');
      expect(out).not.toContain(ESC);
    },
  );

  it('lists an identity once however often it is stored, as the forward verdict counts it', () => {
    attach('scoped', bound([entry(WORK_REPO, 'payments-api'), entry(WORK_REPO, 'duplicate')]));
    const out = status();
    expect(out).toMatch(/^ {2}scope {6}1 enrolled — /m);
    expect(out).toContain(`${WORK_REPO} (payments-api)`);
    expect(out).not.toContain('(duplicate)');
  });

  it('prints a long identity whole, up to the bound an identity has', () => {
    const long = `github.com/acme/${'r'.repeat(290)}`;
    attach('scoped', bound([entry(long)]));
    expect(status()).toContain(`\n             ${long}, enrolled 2026-10-07`);
  });

  it('prints exactly the block attachmentScopeLines returns', () => {
    const scope = bound([entry(WORK_REPO, 'payments-api')]);
    attach('scoped', scope);
    expect(status()).toContain(`\n${attachmentScopeLines(scope, ENDPOINT).join('\n')}\n`);
  });
});

describe('renderAttachedStatus — history counts on a scoped machine', () => {
  const consent: Partial<WorkspaceSettings> = {
    historySyncConsent: {
      acknowledgedAt: '2026-10-01T09:00:00.000Z',
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: ENDPOINT,
    },
  };
  const progress: Omit<HistorySyncState, 'specVersion'> = {
    phase: 'filling',
    lastOutcome: 'ok',
    lastPassAtMs: Date.now(),
    sentTotal: 10,
    pendingTotal: 5,
    skippedTotal: 0,
    startedAtMs: Date.now(),
    completedAtMs: null,
  };
  // The three history lines that print numbers: what the file holds for each,
  // and the line its numbers are printed on.
  const numbered: [string, Partial<Omit<HistorySyncState, 'specVersion'>>, string][] = [
    ['sending', {}, '  history    sending — 10 of 15 records sent'],
    ['complete', { phase: 'complete', pendingTotal: 0 }, '  history    complete — 10 records sent'],
    ['paused', { lastOutcome: 'unreachable' }, '             10 of 15 records sent'],
  ];
  const OLDER_VERSION_NOTE =
    '             (counted by an older version of aka, for everything recorded on this machine)';
  const MACHINE_WIDE_NOTE =
    '             (counted while attached machine-wide, for everything recorded on this machine)';
  // What a scoped pass writes when its scope sends nothing: zeros, and complete.
  const emptyScopePass: Omit<HistorySyncState, 'specVersion'> = {
    ...progress,
    phase: 'complete',
    sentTotal: 0,
    pendingTotal: 0,
    completedAtMs: Date.now(),
    countsScope: 'scoped',
  };

  it.each(numbered)(
    'notes that an older version counted everything recorded under the %s line',
    (_name, shape, line) => {
      attach('scoped', bound([entry(WORK_REPO)]), consent);
      // No marker: the file every drain before this one writes, in either mode.
      writeHistorySyncState(dataDir, { ...progress, ...shape });
      const out = status();
      expect(out).toContain(`\n${line}\n${OLDER_VERSION_NOTE}`);
      expect(out).not.toContain('enrolled or not');
    },
  );

  it('notes counts taken while attached machine-wide', () => {
    attach('scoped', bound([entry(WORK_REPO)]), consent);
    // A machine-wide pass of this very version, kept by a re-attach that made the
    // machine scoped: only a detach removes this file.
    writeHistorySyncState(dataDir, { ...progress, countsScope: 'machine' });
    const out = status();
    expect(out).toContain(`\n  history    sending — 10 of 15 records sent\n${MACHINE_WIDE_NOTE}`);
    expect(out).not.toContain('older version');
  });

  it.each(numbered)(
    'prints the %s line bare when the pass counted through the scope',
    (_name, shape, line) => {
      attach('scoped', bound([entry(WORK_REPO)]), consent);
      writeHistorySyncState(dataDir, { ...progress, ...shape, countsScope: 'scoped' });
      const out = status();
      expect(out).toContain(`\n${line}`);
      // No note, in any wording, directly under the numbers.
      expect(out).not.toMatch(/records sent\n {13}\(/);
    },
  );

  it.each(['unmarked', 'machine', 'scoped'] as const)(
    'never notes the counts on a machine-wide attachment (marker %s)',
    (marker) => {
      attach('machine', undefined, consent);
      writeHistorySyncState(dataDir, {
        ...progress,
        ...(marker === 'unmarked' ? {} : { countsScope: marker }),
      });
      const out = status();
      expect(out).toMatch(/^ {2}history {4}sending — 10 of 15 records sent$/m);
      expect(out).not.toMatch(/records sent\n {13}\(/);
      expect(out).not.toContain('nothing to send');
    },
  );

  it.each<[string, unknown]>([
    ['no scope recorded', undefined],
    ['a scope with nothing in it', bound()],
    [
      'a scope recorded for another deployment',
      { endpoint: OLD_ENDPOINT, ...MEMBER, entries: [entry(WORK_REPO)] },
    ],
    ['a scope record this version cannot read', 'not-a-scope-record'],
    [
      'a scope whose binding fails',
      { endpoint: ENDPOINT, tenantName: 'Acme', userEmail: 42, entries: [entry(WORK_REPO)] },
    ],
  ])('says nothing is sent, never complete, with %s', (_name, scope) => {
    attach('scoped', scope, consent);
    writeHistorySyncState(dataDir, emptyScopePass);
    const out = status();
    expect(out).toMatch(/^ {2}history {4}nothing to send — the scope above forwards no activity$/m);
    expect(out).not.toContain('complete —');
    expect(out).not.toMatch(/records sent/);
  });

  it('says nothing is sent before the first pass too, when nothing is enrolled', () => {
    attach('scoped', bound(), consent);
    const out = status();
    expect(out).toMatch(/^ {2}history {4}nothing to send — the scope above forwards no activity$/m);
    expect(out).not.toContain('waiting for the first pass');
  });

  // A refused key is the one thing enrolling cannot fix, so the nothing-to-send
  // line must not hide it. The last pass was refused while a repository was
  // still enrolled; everything has been unenrolled since.
  it('still says the key is refused when nothing is enrolled', () => {
    attach('scoped', bound(), consent);
    writeHistorySyncState(dataDir, { ...progress, lastOutcome: 'refused', countsScope: 'scoped' });
    const out = status();
    expect(out).toContain(
      "\n  history    stopped — that deployment refused this machine's key\n             re-attach to resume",
    );
    expect(out).not.toContain('nothing to send');
  });
});

describe('attachmentScopeLines — what the record does not limit', () => {
  it.each<[string, unknown]>([
    ['no record', undefined],
    ['a value that is not a record', 'not-a-scope-record'],
    ['an empty record', bound()],
    [
      'a record for another deployment',
      { endpoint: OLD_ENDPOINT, ...MEMBER, entries: [entry(WORK_REPO)] },
    ],
    ['an enrolled list', bound([entry(WORK_REPO, 'payments-api')])],
    [
      'an unbound list with an entry this version cannot read',
      {
        endpoint: ENDPOINT,
        entries: [
          entry(WORK_REPO),
          { kind: 'workspace', identity: 'acme-workspace', enrolledAt: ENROLLED_AT },
        ],
      },
    ],
  ])('ends the block for %s with the policy pull and the device report', (_name, scope) => {
    const lines = attachmentScopeLines(scope, ENDPOINT);
    expect(lines[lines.length - 1]).toBe(NOT_LIMITED);
    expect(lines.filter((line) => line === NOT_LIMITED)).toHaveLength(1);
  });

  it('prints it in status straight after the scope block', () => {
    attach('scoped');
    expect(status()).toContain(`\n${NOT_LIMITED}\n  sync `);
  });

  it('prints it nowhere on a machine-wide attachment', () => {
    attach('machine', bound([entry(WORK_REPO)]));
    expect(status()).not.toContain('the policy pull and the device report');
  });
});

describe('attachmentScopeLines — a missing list and one this build cannot read', () => {
  // Two ways a record that is present can fail to read: its entries are not a
  // list, and a name past its bound. Each is checked to be unreadable first, so
  // a fixture that quietly became readable cannot pass for the state.
  const UNREADABLE: [string, unknown][] = [
    ['entries that are not a list', { endpoint: ENDPOINT, ...MEMBER, entries: 'x' }],
    [
      'an organization name past its bound',
      { endpoint: ENDPOINT, tenantName: 'x'.repeat(201), userEmail: 'member', entries: [] },
    ],
  ];

  it.each<[string, unknown]>([
    ['undefined', undefined],
    ['null', null],
  ])('says no list is stored when the value is %s', (_name, raw) => {
    expect(attachmentScopeLines(raw, ENDPOINT)).toEqual([...MISSING_LIST, NOT_LIMITED]);
  });

  it.each(UNREADABLE)('says the list cannot be read for %s, and offers no enroll', (_name, raw) => {
    expect(parseAttachmentScope(raw)).toBeUndefined();
    const lines = attachmentScopeLines(raw, ENDPOINT);
    expect(lines).toEqual([...UNREADABLE_LIST, NOT_LIMITED]);
    expect(lines.join('\n')).not.toContain('aka enroll');
  });

  it('gives the missing list, the unreadable list and the empty list three different blocks', () => {
    const blocks = [undefined, 'not-a-scope-record', bound()].map((raw) =>
      attachmentScopeLines(raw, ENDPOINT).join('\n'),
    );
    expect(new Set(blocks).size).toBe(3);
  });

  it.each<[string, unknown, string]>([
    ['no list stored', undefined, MISSING_HEADLINE],
    ['a list this build cannot read', UNREADABLE[0]?.[1], UNREADABLE_HEADLINE],
    ['a list with nothing in it yet', bound(), EMPTY_HEADLINE],
  ])('shows %s once, under its own headline only', (_name, scope, headline) => {
    attach('scoped', scope);
    const out = status();
    for (const other of [MISSING_HEADLINE, UNREADABLE_HEADLINE, EMPTY_HEADLINE]) {
      expect(out.split(other).length - 1).toBe(other === headline ? 1 : 0);
    }
    // The three read alike: none names a kind of entry the others leave out.
    expect(out).not.toContain("repository's activity");
  });
});
