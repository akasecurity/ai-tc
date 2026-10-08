import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedCredentialV2 } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runSyncHistory } from '../../src/commands/sync-history.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// The credential reader, wrapped for the scoped cases at the end of this file.
// They arm `credentialRead` with a usable scoped read rather than writing a
// scoped credential file, so they exercise the backfill's scope independently
// of what the reader accepts; armed with an Error, the reader throws it.
// Unarmed, every call reaches the real reader.
const credentialRead = vi.hoisted<{ value: unknown }>(() => ({ value: undefined }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneCredentialFile: (
      ...args: Parameters<typeof actual.readControlPlaneCredentialFile>
    ): ReturnType<typeof actual.readControlPlaneCredentialFile> => {
      if (credentialRead.value instanceof Error) throw credentialRead.value;
      return (
        (credentialRead.value as
          ReturnType<typeof actual.readControlPlaneCredentialFile> | undefined) ??
        actual.readControlPlaneCredentialFile(...args)
      );
    },
  };
});

const ENDPOINT = 'https://aka.example-org.internal';

let base: string;
let exits: number[];

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

const deps = (io: ReturnType<typeof recorder>) => ({
  base,
  prompter: io,
  exit: (code: number) => exits.push(code),
});

const attach = (endpoint = ENDPOINT): void => {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, attachedAt: new Date().toISOString(), label: 'Example Org' },
    },
    base,
  );
};

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-history-'));
  exits = [];
});

afterEach(() => {
  removeTree(base);
});

describe('aka sync-history', () => {
  it('reports that an unattached machine sends nothing', async () => {
    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(exits).toEqual([]);
    expect(io.output()).toContain('not attached');
  });

  // A grant names the deployment it covers, so there has to be one to name.
  it('refuses to grant on an unattached machine', async () => {
    const io = recorder();
    await runSyncHistory(['--on'], deps(io));
    expect(exits).toEqual([1]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  it('grants against the endpoint this machine is attached to', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toMatchObject({
      endpoint: ENDPOINT,
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    });
  });

  // The grant message is where someone typing `aka sync-history --on` reads
  // what they are agreeing to, so the masking claim in it has to carry its
  // condition. A drained capture is the stored content, and a span is masked in
  // the store only where the policy assigned its detection is redact or block —
  // under monitor or warn, which is every detection until one is promoted, the
  // value is drained as it was seen.
  it('states the masking as the per-detection condition it is', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on'], deps(io));
    const shown = io.output();
    expect(shown).toContain('masked only where the policy');
    expect(shown).toContain('is redact or block');
    expect(shown).toContain('under monitor or warn');
    expect(shown).toContain('ships on redact or block');
    // The unconditional promise this replaced. Pinned absent so a reword cannot
    // reinstate it beside the new sentence and still read green.
    expect(shown).not.toContain('detected secrets masked');
  });

  it('revokes what it granted', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory(['--off'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
    // Revoking stops what has not gone; it cannot unsend what has.
    expect(io.output()).toContain('already sent');
  });

  it('revokes even when nothing was granted', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--off'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  // Granting and then not waiting for the next session is the natural thing to
  // ask for, and the grant message itself sets it up ("starting with your next
  // session"). Recording the grant and silently ignoring half the command is the
  // one outcome that must not happen.
  it('grants and then sends when --on and --run are given together', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on', '--run'], deps(io));

    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeDefined();
    // The grant message AND the state the pass left behind — --on alone prints
    // only the first.
    expect(io.output()).toContain("Sending this machine's unsent activity");
    expect(io.output().trimEnd().split('\n').length).toBeGreaterThan(3);
  });

  // The whole point of the report line: `--run` used to print only the consent
  // sentence, which reads identically whether a pass sent everything, sent
  // nothing, or was never attempted. A user reaching for this command is trying
  // to find out WHICH, and seven different refusals were one silent `null`.
  it('says WHY it did nothing on an unattached machine', async () => {
    const io = recorder();
    await runSyncHistory(['--run'], deps(io));

    expect(exits).toEqual([]);
    // Asserted on wording only the REPORT can produce: `describe()` already
    // says "not attached to a deployment", so an assertion on that phrase passes
    // with the report line deleted — which is exactly how this test was wrong the
    // first time. "This pass" is the discriminator.
    expect(io.output()).toContain('This pass did nothing: there is no deployment to send to.');
    // Positive control: the consent sentence is still printed beneath it.
    expect(io.output()).toContain('so it sends nothing');
  });

  it('names the remedy when the grant is missing, not merely that nothing happened', async () => {
    // `no-consent` and `not-attached` both left the store untouched and printed
    // the same thing before. They are different instructions to a human, and the
    // command is only useful if it gives the right one.
    attach();
    const io = recorder();
    await runSyncHistory(['--run'], deps(io));

    expect(exits).toEqual([]);
    expect(io.output()).toContain(
      'This pass did nothing: sending existing activity is switched off.',
    );
    expect(io.output()).not.toContain('there is no deployment to send to');
  });

  it('revokes and still runs cleanly when --off and --run are given together', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory(['--off', '--run'], deps(io));

    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  it('refuses --on and --off together rather than picking one', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on', '--off'], deps(io));
    expect(exits).toEqual([2]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
    expect(io.errors()).toContain('not both');
  });

  it('refuses an unknown flag rather than ignoring it', async () => {
    const io = recorder();
    await runSyncHistory(['--send-everything'], deps(io));
    expect(exits).toEqual([2]);
    expect(io.errors()).toContain('Usage: aka sync-history');
  });

  it('says what is in force once granted', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(io.output()).toContain('Sending');
    expect(io.output()).toContain('Example Org');
  });

  // A grant given for one deployment must not read as in force after the machine
  // is pointed at another — and the difference is worth saying, because "off"
  // alone would be a state the user cannot account for.
  it('treats a grant for another deployment as not in force, and says why', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    attach('https://elsewhere.example-org.internal');

    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(io.output()).toContain('no longer');
  });

  // The stale-grant notice is the second place this consent is stated, and the
  // one a user meets when their grant is paused and being re-asked — so it
  // carries the same masking claim and needs the same guard. Nothing reached
  // this branch before, which is how the copy it replaced went unnoticed.
  it('states the masking condition when re-asking for a grant that predates the change', async () => {
    attach();
    applyOnboarding(
      {
        historySyncConsent: {
          acknowledgedAt: new Date().toISOString(),
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
          endpoint: ENDPOINT,
        },
      },
      base,
    );

    const io = recorder();
    await runSyncHistory([], deps(io));
    const shown = io.output();
    // The branch under test, not merely some refusal: a version-stale grant is
    // re-asked rather than reported as never given.
    expect(shown).toContain('predates a change');
    expect(shown).toContain('is set to redact or block');
    expect(shown).toContain('ships on redact or block');
    // The unconditional promise this replaced. Without this the case passes on
    // any wording that happens to mention a policy.
    expect(shown).not.toContain('with detected secrets masked');
  });
});

// The consent-time backfill on a SCOPED attachment marks only the enrolled
// repositories' captures: the same scope the drain reads with.
describe('aka sync-history --on — the capture backfill and the attachment scope', () => {
  const WORK = 'github.com/acme/work';
  const PERSONAL = 'github.com/someone/dotfiles';
  const RECORDED = '2026-08-01T00:01:00.000Z';

  afterEach(() => {
    credentialRead.value = undefined;
  });

  const enroll = (keys: readonly string[]): void => {
    applyOnboarding(
      {
        attachmentScope: {
          endpoint: ENDPOINT,
          entries: keys.map((identity) => ({ kind: 'repo', identity, enrolledAt: RECORDED })),
        },
      },
      base,
    );
  };

  /** One prompt per id, stamped with its key, recorded before the grant, never marked. */
  const seedCaptures = (byId: Record<string, string>): void => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      db.auditEvents.ensureSessionRoot('s-1', '2026-08-01T00:00:00.000Z');
      for (const [id, scopeKey] of Object.entries(byId)) {
        db.auditEvents.insertAuditEvent({
          id,
          eventType: 'prompt',
          rootSessionId: 's-1',
          parentId: 's-1',
          startedAt: RECORDED,
          content: `text of ${id}`,
          attributes: { scope_key: scopeKey },
        });
      }
    } finally {
      db.close();
    }
  };

  const owedIds = (): string[] => {
    const db = openLocalDatabase(dataDirOf(base));
    try {
      return db.historySync
        .pendingCaptureRows(10, Date.now() + 1)
        .map((r) => r.id)
        .sort();
    } finally {
      db.close();
    }
  };

  it("marks only the enrolled repository's captures on a scoped attachment", async () => {
    attach();
    enroll([WORK]);
    seedCaptures({ 'work-prompt': WORK, 'personal-prompt': PERSONAL });
    credentialRead.value = {
      usable: true,
      credential: {
        specVersion: 2,
        mode: 'scoped',
        endpoint: ENDPOINT,
        apiKey: 'placeholder',
        mintedAt: RECORDED,
      } satisfies AttachedCredentialV2,
    };

    await runSyncHistory(['--on'], deps(recorder()));

    expect(exits).toEqual([]);
    expect(owedIds()).toEqual(['work-prompt']);
  });

  // A machine attachment's grant covers every capture; a stored scope does not
  // narrow it.
  it('marks every capture on a machine attachment, whatever scope is stored', async () => {
    attach();
    enroll([WORK]);
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: 'placeholder',
      mintedAt: RECORDED,
    });
    seedCaptures({ 'work-prompt': WORK, 'personal-prompt': PERSONAL });

    await runSyncHistory(['--on'], deps(recorder()));

    expect(owedIds()).toEqual(['personal-prompt', 'work-prompt']);
  });

  // The grant is already recorded when the seed runs, so a credential read that
  // throws while the seed works out its scope must not turn it into a failure:
  // the seed marks no capture then, because marking every capture would make a
  // scoped attachment's retention hold bodies of repositories it does not cover.
  it('still records the grant, and marks no capture, when the credential read throws', async () => {
    attach();
    enroll([WORK]);
    seedCaptures({ 'work-prompt': WORK, 'personal-prompt': PERSONAL });
    credentialRead.value = new Error('the credential file could not be inspected');

    await runSyncHistory(['--on'], deps(recorder()));

    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toMatchObject({ endpoint: ENDPOINT });
    expect(owedIds()).toEqual([]);
  });
});
