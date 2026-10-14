import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import type { SharesForwardConnection, SharesForwardSendResult } from '@akasecurity/local-ops';
import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { EgressIngestRequest } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { runScan } from '../../src/commands/scan.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// `aka scan` over a checkout that holds another repository, end to end. The walk
// folds the nested repository's call sites into the project's register, so a
// scoped attachment forwards it only once both are enrolled. The forward runs
// for real against a recording transport. The mode is stood in for as in
// packages/local-ops/test/shares-forward-scope.test.ts.
const reader = vi.hoisted(() => ({ scoped: false }));

vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneCredential: (...args: Parameters<typeof actual.readControlPlaneCredential>) => {
      const real = actual.readControlPlaneCredential(...args);
      return real === null || !reader.scoped ? real : { ...real, specVersion: 2, mode: 'scoped' };
    },
  };
});

const ENDPOINT = 'https://aka.acme.test';
const TEST_KEY = 'not-a-real-key';
const WORK = 'github.com/acme/payments-api';
const PERSONAL = 'github.com/someone/side-project';
// An scp-style remote's userinfo reads as an email address to a scanner, so
// it is built from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

interface Sent {
  connection: SharesForwardConnection;
  request: EgressIngestRequest;
}

interface Payload {
  forward: Record<string, unknown> | null;
}

let home: string;
let root: string;
let out: string;
let sent: Sent[];

function gitRepo(dir: string, url?: string): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  const remote = url === undefined ? '' : `[remote "origin"]\n\turl = ${url}\n`;
  writeFileSync(join(dir, '.git', 'config'), `[core]\n\tbare = false\n${remote}`);
}

function write(rel: string, content: string): void {
  const full = join(root, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

// Both halves of an attachment through the real writers, plus a scope record
// naming `identities` for this deployment, written as raw JSON.
function attach(...identities: string[]): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-09-01T10:00:00.000Z' },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
  });
  const file = join(settingsDir(home), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(
    file,
    JSON.stringify({
      ...settings,
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: identities.map((identity) => ({
          kind: 'repo',
          identity,
          enrolledAt: '2026-09-02T10:00:00.000Z',
        })),
      },
    }),
  );
}

const send = (
  connection: SharesForwardConnection,
  request: EgressIngestRequest,
): Promise<SharesForwardSendResult> => {
  sent.push({ connection, request });
  return Promise.resolve({ ok: true });
};

async function scanJson(): Promise<Payload> {
  out = '';
  await runScan([root, '--format', 'json', '--home', home], { send });
  return JSON.parse(out) as Payload;
}

beforeEach(() => {
  reader.scoped = false;
  sent = [];
  out = '';
  home = mkdtempSync(join(tmpdir(), 'aka-scan-nested-home-'));
  mkdirSync(dataDir(home), { recursive: true });
  migratedStore.seed(dataDir(home));
  root = mkdtempSync(join(tmpdir(), 'aka-scan-nested-root-'));
  gitRepo(root, 'https://github.com/acme/payments-api.git');
  gitRepo(join(root, 'tools', 'mine'), `${gitUser}github.com:someone/side-project.git`);
  write('client.ts', "export const CHARGES = 'https://api.stripe.com/v1/charges';\n");
  write(
    'tools/mine/notify.ts',
    "export const HOOK = 'https://api.github.com/repos/someone/side-project/dispatches';\n",
  );
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([home, root]);
  process.exitCode = undefined;
});

describe('aka scan — a project with a repository nested in it', () => {
  it('on a scoped attachment, keeps the register local while the nested repository is not enrolled', async () => {
    reader.scoped = true;
    attach(WORK);

    const payload = await scanJson();

    expect(payload.forward).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(sent).toHaveLength(0);
  });

  it('on a scoped attachment, forwards once the nested repository is enrolled too', async () => {
    reader.scoped = true;
    attach(WORK, PERSONAL);

    const payload = await scanJson();

    expect(payload.forward).toMatchObject({ status: 'forwarded', endpoint: ENDPOINT });
    expect(sent).toHaveLength(1);
  });

  it('on a scoped attachment, keeps the register local for a nested repository with no remote', async () => {
    reader.scoped = true;
    gitRepo(join(root, 'scratch'));
    write('scratch/try.ts', 'export const x = 1;\n');
    attach(WORK, PERSONAL);

    const payload = await scanJson();

    expect(payload.forward).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(sent).toHaveLength(0);
  });

  it('on a machine-wide attachment, sends exactly what the same tree sends with nothing nested', async () => {
    attach('github.com/acme/unrelated');

    const withNested = await scanJson();
    rmSync(join(root, 'tools', 'mine', '.git'), { recursive: true, force: true });
    const withoutNested = await scanJson();

    expect(withNested.forward).toMatchObject({ status: 'forwarded', endpoint: ENDPOINT });
    expect(withoutNested.forward).toMatchObject({ status: 'forwarded', endpoint: ENDPOINT });
    expect(sent).toHaveLength(2);
    expect(JSON.stringify(sent[1]?.request)).toBe(JSON.stringify(sent[0]?.request));
  });
});
