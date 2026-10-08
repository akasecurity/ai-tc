import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
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

// What `aka status` says about a scoped attachment: the mode, what is enrolled,
// and every state in which nothing is sent. Each renderer case writes a real
// settings file and a real credential file and reads them back through the
// renderer, so a red here is the renderer's.

const ENDPOINT = 'https://aka.acme.test';
const OLD_ENDPOINT = 'https://aka.old.test';
const TEST_KEY = 'not-a-real-key';
const ENROLLED_AT = '2026-10-07T09:30:00.000Z';
const WORK_REPO = 'github.com/acme/payments-api';
const SECOND_REPO = 'github.com/acme/billing-worker';
// The binding a scoped attach records. The account is any printable string to
// the schema; nothing here reads it as an address.
const MEMBER = { tenantName: 'Acme', userEmail: 'member-of-acme' } as const;
const ESC = String.fromCharCode(0x1b);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
// A part of a recorded address that must never reach the screen.
const HIDDEN = 'hiddenpart';
const NOT_LIMITED =
  '             the policy pull and the device report are not limited to what is enrolled';

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
    expect(out).toMatch(/^ {2}mode {7}machine \(every repository\)$/m);
    expect(out).not.toMatch(/^ {2}scope /m);
    expect(out).not.toContain(WORK_REPO);
  });

  it('names a scoped attachment', () => {
    attach('scoped', bound());
    expect(status()).toMatch(/^ {2}mode {7}scoped \(enrolled repositories only\)$/m);
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
    expect(out).toMatch(/^ {2}mode {7}scoped \(enrolled repositories only\)$/m);
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

  it('says nothing is sent when no scope is recorded', () => {
    attach('scoped');
    const out = status();
    expect(out).toMatch(/^ {2}scope {6}nothing enrolled — no repository's activity is sent$/m);
    expect(out).toContain('(run `aka enroll` inside a work repository to add it)');
  });

  it('says nothing is sent when the stored scope is not a record at all', () => {
    attach('scoped', 'not-a-scope-record');
    expect(status()).toMatch(/^ {2}scope {6}nothing enrolled — no repository's activity is sent$/m);
  });

  it('says a freshly recorded scope enrolls nothing yet', () => {
    attach('scoped', bound());
    const out = status();
    expect(out).toMatch(/^ {2}scope {6}nothing enrolled yet — no repository's activity is sent$/m);
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
      expect(out).toMatch(/^ {2}scope {6}nothing enrolled — no repository's activity is sent$/m);
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
  const progress = {
    phase: 'filling',
    lastOutcome: 'ok',
    lastPassAtMs: Date.now(),
    sentTotal: 10,
    pendingTotal: 5,
    skippedTotal: 0,
    startedAtMs: Date.now(),
    completedAtMs: null,
  } as const;

  it('says the counts cover every repository, enrolled or not', () => {
    attach('scoped', bound([entry(WORK_REPO)]), consent);
    writeHistorySyncState(dataDir, progress);
    const out = status();
    expect(out).toContain('  history    sending — 10 of 15 records sent\n');
    expect(out).toContain(
      '\n             (counts cover every repository on this machine, enrolled or not)',
    );
  });

  it('adds no caveat on a machine-wide attachment', () => {
    attach('machine', undefined, consent);
    writeHistorySyncState(dataDir, progress);
    const out = status();
    expect(out).toContain('  history    sending — 10 of 15 records sent');
    expect(out).not.toContain('counts cover every repository');
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
