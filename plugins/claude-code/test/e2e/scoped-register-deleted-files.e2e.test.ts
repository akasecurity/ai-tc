/**
 * A scoped attachment never sends the deleted files of a personal clone kept
 * inside an enrolled checkout, driven end to end with the real parts: git
 * checkouts on disk, a credential file written by `writeControlPlaneCredential`
 * and read back by the real reader, the real attached gateway, and the real
 * worktree scan. Only the network is replaced, by a client that records what the
 * gateway hands it instead of sending it, so no socket is opened.
 *
 * The factory has no seam for a client: `resolveGatewayForConfig` builds its own
 * from the connection's endpoint. So the gateway here is built the way the
 * factory builds it (the same local gateway, forward policy and gateway class),
 * and its attachment comes from the real file: the credential is read by
 * `readControlPlaneCredential` and its mode taken by `attachmentModeOf`, then
 * resolved against the settings' scope by `resolveScope`. A version 2 file is
 * therefore a scoped attachment and a version 1 file a machine-wide one, as in
 * production. The build is registered as the process's default gateway factory,
 * the seam the scanner resolves its gateway through, and put back after each
 * case.
 *
 * The scan's deletion sweep lists every ledgered path under its root that is
 * gone from disk, and the ledger holds the files of a nested clone as well. A
 * clone that was removed since the last scan, or one an ignore file now hides,
 * is in no walk, so the check on repositories nested in the register's project
 * never sees it, yet its paths come back as deleted and used to be sent under
 * the enrolled project's register. These cases pin that they are not, and pin
 * the two controls: an enrolled file deleted from a directory that still exists
 * is sent, and a machine-wide attachment sends what it always sent.
 */
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  readControlPlaneCredential,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedClient, DataGatewayFactory } from '@akasecurity/plugin-runtime';
import {
  AttachedDataGateway,
  createForwardPolicy,
  setDefaultGatewayFactory,
  StandaloneDataGateway,
} from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections, toPosix } from '@akasecurity/plugin-sdk';
import { scanWorktree } from '@akasecurity/scanner';
import type { EgressIngestRequest, WorkspaceSettings } from '@akasecurity/schema';
import { attachmentModeOf, defaultWorkspaceSettings, resolveScope } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { migratedStore } from '../helpers/store-templates.ts';

const WORK_ORIGIN = 'https://github.com/acme/payments-api.git';
const WORK_KEY = 'github.com/acme/payments-api';
const PERSONAL_ORIGIN = 'https://github.com/me/personal.git';
const ENROLLED_AT = '2026-10-01T12:00:00.000Z';
// Never contacted: the client below does not open a connection.
const ENDPOINT = 'https://plane.example.test';
const TEST_KEY = 'not-a-real-key';
const CLONE = 'personal-clone';

let tmp: string;
let repo: string;
let home: string;
// Every project register the gateway handed the client, in order.
let registers: EgressIngestRequest[];
let restoreFactory: () => void;

// A client that records the registers it is given and sends nothing. The other
// members are never reached by a scan of files that hold no finding, and
// settle harmlessly if one is.
function recordingClient(): AttachedClient {
  return {
    ingestEvents: (batch) => Promise.resolve({ accepted: batch.events.length, duplicates: 0 }),
    ingestInventory: () => Promise.reject(new Error('a scan sends no inventory')),
    recordAuditEvent: () => Promise.resolve(),
    recordAuditEvents: (events) => Promise.resolve({ accepted: events.length }),
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: (request) => {
      registers.push(request);
      return Promise.resolve({});
    },
  };
}

// The gateway the factory would build for an attached machine, with the
// recording client in place of the remote one (see the header).
const attachedGateway: DataGatewayFactory = (config, meta) => {
  const connection = config.settings.controlPlane;
  if (connection === undefined) throw new Error('the settings name no control plane');
  const credential = readControlPlaneCredential(config.settingsDir, connection);
  if (credential === null) throw new Error('the credential file is not usable');
  return new AttachedDataGateway({
    local: new StandaloneDataGateway(config.dataDir, bundledDetections(), meta),
    client: recordingClient(),
    dataDir: config.dataDir,
    readCachedBundle: () => Promise.resolve(null),
    forward: createForwardPolicy({ dir: config.dataDir }),
    attachment: resolveScope({
      mode: attachmentModeOf(credential),
      scope: config.settings.attachmentScope,
      endpoint: connection.endpoint,
    }),
  });
};

beforeEach(() => {
  tmp = realpathSync(mkdtempSync(join(tmpdir(), 'aka-scoped-register-')));
  repo = join(tmp, 'repo');
  home = join(tmp, 'home');
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
  registers = [];
  restoreFactory = setDefaultGatewayFactory(attachedGateway);
});

afterEach(() => {
  restoreFactory();
  removeTree(tmp);
});

function gitRepo(dir: string, url: string): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n`,
  );
}

function write(rel: string, content: string): void {
  const full = join(repo, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

// A call site the egress extractor reads, distinct per file so the scan's
// content-hash dedup never merges two of them.
const callFor = (name: string): string =>
  `await fetch('https://api.stripe.com/v1/charges'); // ${name}\n`;

// The enrolled checkout with a personal clone inside it, each holding files.
function seedProjectWithClone(): void {
  gitRepo(repo, WORK_ORIGIN);
  gitRepo(join(repo, CLONE), PERSONAL_ORIGIN);
  write('src/pay.ts', callFor('pay'));
  write('src/old.ts', callFor('old'));
  write(`${CLONE}/top.ts`, callFor('clone-top'));
  write(`${CLONE}/src/notify.ts`, callFor('clone-notify'));
  write(`${CLONE}/src/keep.ts`, callFor('clone-keep'));
}

// The clone's working tree emptied the way `git submodule deinit` empties one:
// the `.git` and every file are gone and the directory itself stays.
function emptyClone(): void {
  rmSync(join(repo, CLONE, '.git'), { recursive: true, force: true });
  rmSync(join(repo, CLONE, 'top.ts'));
  rmSync(join(repo, CLONE, 'src'), { recursive: true, force: true });
  expect(existsSync(join(repo, CLONE))).toBe(true);
}

// An attachment: the credential file on disk, and the settings that name the
// connection and enrol the work repository. The SAME settings in both modes, so
// what differs is the credential alone.
function attach(mode: 'scoped' | 'machine'): PluginConfig {
  writeControlPlaneCredential(
    settingsDirOf(home),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: TEST_KEY }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: ENROLLED_AT },
  );
  const settings: WorkspaceSettings = {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    dataSharesInPlace: true,
    controlPlane: { endpoint: ENDPOINT, attachedAt: ENROLLED_AT },
    attachmentScope: {
      endpoint: ENDPOINT,
      entries: [{ kind: 'repo', identity: WORK_KEY, enrolledAt: ENROLLED_AT }],
    },
  };
  return {
    settings,
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

async function scan(config: PluginConfig): Promise<void> {
  await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
}

function deletedOf(register: EgressIngestRequest | undefined): readonly string[] {
  if (register?.reconcile.mode !== 'ledger') throw new Error('expected a ledger-mode register');
  return register.reconcile.deletedFiles;
}

function scannedOf(register: EgressIngestRequest | undefined): readonly string[] {
  if (register?.reconcile.mode !== 'ledger') throw new Error('expected a ledger-mode register');
  return register.reconcile.scannedFiles;
}

// The paths the scan ledger holds, as project-relative posix keys: what the
// deletion sweep of the NEXT scan lists once a file is gone.
async function ledgeredFiles(): Promise<string[]> {
  const local = new StandaloneDataGateway(dataDirOf(home), bundledDetections());
  try {
    return (await local.scanLedgerPaths()).map((path) => toPosix(relative(repo, path)));
  } finally {
    await local.close();
  }
}

describe('a scoped attachment (version 2 credential) and the deleted files of a personal clone', () => {
  it('sends nothing of a clone that was removed since the last scan', async () => {
    seedProjectWithClone();
    const config = attach('scoped');

    // The first scan walks the clone, so its files are ledgered; the register
    // holds a repository that is not enrolled, so none is sent.
    await scan(config);
    expect(registers).toEqual([]);
    expect(await ledgeredFiles()).toEqual(
      expect.arrayContaining([`${CLONE}/top.ts`, `${CLONE}/src/notify.ts`, `${CLONE}/src/keep.ts`]),
    );

    rmSync(join(repo, CLONE), { recursive: true, force: true });
    write('src/new.ts', callFor('new'));
    await scan(config);

    // The register itself goes: the project is enrolled and nothing is nested
    // in it any more. It names no path of the clone.
    expect(registers).toHaveLength(1);
    expect(scannedOf(registers[0])).toContain('src/new.ts');
    expect(deletedOf(registers[0])).toEqual([]);
    expect(JSON.stringify(registers)).not.toContain(CLONE);
  });

  it('sends nothing of a clone that an ignore file now hides, though it is still on disk', async () => {
    seedProjectWithClone();
    const config = attach('scoped');
    await scan(config);
    expect(registers).toEqual([]);

    write('.akaignore', `${CLONE}/\n`);
    rmSync(join(repo, CLONE, 'src', 'notify.ts'));
    write('src/new.ts', callFor('new'));
    expect(existsSync(join(repo, CLONE, 'src', 'keep.ts'))).toBe(true);
    await scan(config);

    expect(registers).toHaveLength(1);
    expect(scannedOf(registers[0])).toContain('src/new.ts');
    expect(deletedOf(registers[0])).toEqual([]);
    expect(JSON.stringify(registers)).not.toContain(CLONE);
  });

  it('still sends a file of the enrolled repository deleted from a directory that exists', async () => {
    gitRepo(repo, WORK_ORIGIN);
    write('src/pay.ts', callFor('pay'));
    write('src/old.ts', callFor('old'));
    const config = attach('scoped');
    await scan(config);
    const before = registers.length;

    rmSync(join(repo, 'src', 'old.ts'));
    await scan(config);

    expect(registers).toHaveLength(before + 1);
    expect(deletedOf(registers.at(-1))).toEqual(['src/old.ts']);
  });

  it('sends nothing of a nested repository whose working tree was emptied but whose directory stays', async () => {
    // What `git submodule deinit` leaves: the `.git` and every file go, the empty
    // directory stays. Its top-level file's directory exists, and with no `.git`
    // left the path would read as the enrolled project's own.
    seedProjectWithClone();
    const config = attach('scoped');
    await scan(config);
    expect(registers).toEqual([]);

    emptyClone();
    write('src/new.ts', callFor('new'));
    await scan(config);

    expect(registers).toHaveLength(1);
    expect(scannedOf(registers[0])).toContain('src/new.ts');
    expect(deletedOf(registers[0])).toEqual([]);
    expect(JSON.stringify(registers)).not.toContain(CLONE);
  });

  it('sends the enrolled file and not the clone when both are deleted in one scan', async () => {
    seedProjectWithClone();
    const config = attach('scoped');
    await scan(config);

    rmSync(join(repo, CLONE), { recursive: true, force: true });
    rmSync(join(repo, 'src', 'old.ts'));
    await scan(config);

    expect(registers).toHaveLength(1);
    expect(deletedOf(registers[0])).toEqual(['src/old.ts']);
    expect(JSON.stringify(registers)).not.toContain(CLONE);
  });
});

describe('a machine-wide attachment (version 1 credential) sends what it always sent', () => {
  it('names the files of a removed clone in the register, nested repository or not', async () => {
    seedProjectWithClone();
    const config = attach('machine');

    // No nested-repository check here: the first register already carries the
    // clone's files.
    await scan(config);
    expect(registers).toHaveLength(1);
    expect(scannedOf(registers[0])).toContain(`${CLONE}/top.ts`);

    rmSync(join(repo, CLONE), { recursive: true, force: true });
    write('src/new.ts', callFor('new'));
    await scan(config);

    expect(registers).toHaveLength(2);
    expect([...deletedOf(registers[1])].sort()).toEqual([
      `${CLONE}/src/keep.ts`,
      `${CLONE}/src/notify.ts`,
      `${CLONE}/top.ts`,
    ]);
  });

  it('names the files of an emptied nested repository too, as it always did', async () => {
    seedProjectWithClone();
    const config = attach('machine');
    await scan(config);
    expect(registers).toHaveLength(1);

    emptyClone();
    write('src/new.ts', callFor('new'));
    await scan(config);

    expect(registers).toHaveLength(2);
    expect([...deletedOf(registers[1])].sort()).toEqual([
      `${CLONE}/src/keep.ts`,
      `${CLONE}/src/notify.ts`,
      `${CLONE}/top.ts`,
    ]);
  });
});
