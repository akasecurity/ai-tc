import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  controlPlaneCredentialPath,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { renderAttachedStatus, renderPolicyLine } from '../../src/attached/status.ts';
import { syncStatePath, writeSyncState } from '../../src/attached/sync-state.ts';

// A high-entropy stand-in that matches no detection rule: the point of every
// absence assertion below is that the credential never reaches the output, and
// a credential-shaped literal does not belong in a public tree.
const SECRET = 'not-a-real-key-7f3b2d9c5e14';
const ENDPOINT = 'https://aka.example-org.internal';

let root: string;
let settingsDir: string;
let dataDir: string;

/** Both halves of an attachment: the descriptor in settings, the credential beside it. */
function attach(over: { endpoint?: string; keyPrefix?: string; label?: string } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: over.endpoint ?? ENDPOINT,
        attachedAt: '2026-08-19T10:00:00.000Z',
        ...(over.label === undefined ? {} : { label: over.label }),
      },
    },
    root,
  );
  writeControlPlaneCredential(settingsDir, {
    specVersion: 1,
    endpoint: over.endpoint ?? ENDPOINT,
    apiKey: SECRET,
    ...(over.keyPrefix === undefined ? {} : { keyPrefix: over.keyPrefix }),
  });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-status-'));
  settingsDir = settingsDirOf(root);
  dataDir = dataDirOf(root);
  mkdirSync(settingsDir, { recursive: true });
  mkdirSync(dataDir, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('renderAttachedStatus — the not-attached cases', () => {
  it('renders a not-attached block when there is no file', () => {
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).toContain('not attached');
  });

  it('renders the SAME not-attached block for a corrupt file', () => {
    // Deliberately indistinguishable: all three negatives mean "this device is
    // not managed", and telling them apart in the output would describe the
    // contents of a file the reader is not otherwise shown.
    writeFileSync(controlPlaneCredentialPath(settingsDir), 'not json', { mode: 0o600 });
    expect(renderAttachedStatus({ base: root, settingsDir, dataDir })).toContain('not attached');
  });

  it('renders not-attached for an unknown specVersion', () => {
    writeFileSync(
      controlPlaneCredentialPath(settingsDir),
      JSON.stringify({ specVersion: 99, backendUrl: 'https://b.example.com', apiKey: SECRET }),
      { mode: 0o600 },
    );
    expect(renderAttachedStatus({ base: root, settingsDir, dataDir })).toContain('not attached');
  });
});

describe('renderAttachedStatus — the attached block', () => {
  it('names the control plane and when it was attached', () => {
    attach();
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).toContain('attached');
    expect(out).toContain(ENDPOINT);
    expect(out).toContain('2026-08-19T10:00:00.000Z');
  });

  it("prefers the administrator's label over the raw endpoint", () => {
    // What a user recognises is the organization's own name for a deployment,
    // not its hostname — and `controlPlaneName` is the one function every
    // surface words that choice through.
    attach({ label: 'Example Org production' });
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).toContain('Example Org production');
    expect(out).not.toContain(ENDPOINT);
  });

  it('renders keyPrefix — the non-secret display half — when present', () => {
    attach({ keyPrefix: 'not-a-re' });
    expect(renderAttachedStatus({ base: root, settingsDir, dataDir })).toContain('not-a-re');
  });

  it('reports the last sync outcome, and calls out a rejected key', () => {
    attach();
    writeSyncState(dataDir, { outcome: 'unauthorized', atMs: Date.now() });
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    // `unauthorized` is the one outcome a human has to act on — a revoked key
    // will be rejected again every fifteen minutes forever.
    expect(out).toMatch(/KEY REJECTED/);
  });

  it('separates a REFUSED sync from a rejected key, since the fixes differ', () => {
    // `GET /v1/policy-bundle` has no role guard, so a 403 here is a suspended
    // tenant or member, or a key scoped away from the route. None of those are
    // fixed by re-attaching, and all of them used to render as if they were.
    attach();
    writeSyncState(dataDir, { outcome: 'forbidden', atMs: Date.now() });
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).toContain('ACCESS REFUSED');
    expect(out).not.toContain('KEY REJECTED');
  });

  it('says so when no sync has been attempted yet', () => {
    attach();
    expect(renderAttachedStatus({ base: root, settingsDir, dataDir })).toContain('no attempt recorded');
  });
});

describe('renderAttachedStatus — the forward half', () => {
  // "Attached" and "still reporting" are different questions, and they can
  // diverge for one credential: `GET /v1/policy-bundle` carries no write-role
  // guard while the ingest routes do, so a device whose owner was demoted to a
  // read-only role syncs policy at 200 and 403s every forward. `forward.run`
  // flattens the refusal to `null` by design, so status is the only surface
  // that can say anything about it — and before this it said nothing, which
  // read as "fine".
  const writeBreaker = (
    consecutiveFailures: number,
    openedAtMs: number | null,
    lastFailure: string | null = null,
  ): void => {
    writeFileSync(
      join(dataDir, 'attached-state.json'),
      JSON.stringify({ consecutiveFailures, openedAtMs, lastFailure }),
      { mode: 0o600 },
    );
  };

  it('says NOT REPORTING when the breaker is open, alongside a healthy sync line', () => {
    attach();
    // The exact shape of the bug: policy is current, forwarding is dead.
    writeSyncState(dataDir, { outcome: 'ok', atMs: 1_000_000 });
    writeBreaker(12, 999_000);

    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).toContain('policy synced');
    expect(out).toContain('NOT REPORTING');
    expect(out).toContain('12 consecutive failures');
  });

  it('does not date the OUTAGE from openedAtMs — that stamp is the last attempt', () => {
    // `run()` re-stamps `openedAtMs` on every half-open probe, so the gap to now
    // is bounded by one cooldown however long the backend has been down.
    // Rendering it as "open for Xm" would understate a week-long outage as
    // seconds. The wording has to be about the attempt.
    attach();
    writeBreaker(400, 1_000_000 - 5_000);
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).toContain('last tried');
    expect(out).not.toMatch(/open (for )?\d/);
    // The count is the signal that actually grows with the outage.
    expect(out).toContain('400 consecutive failures');
  });

  it('reports a sub-threshold failure run without crying wolf', () => {
    attach();
    writeBreaker(2, null);
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).toContain('2 failures since the last success');
    expect(out).not.toContain('NOT REPORTING');
  });

  it('treats a MISSING file as "nothing recorded", not as health', () => {
    // The happy path writes no file at all, so absence is also what a device
    // that has never forwarded looks like. Claiming health from it would be the
    // same overstatement this whole finding is about.
    attach();
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).toContain('no failures recorded');
    expect(out).not.toContain('reporting normally');
  });

  it('reports health only when a success actually cleared the failures', () => {
    attach();
    writeBreaker(0, null);
    expect(renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 })).toContain(
      'reporting normally',
    );
  });

  it('a hostile FUTURE stamp cannot fake an open breaker in the output', () => {
    // Same clamp the policy applies, reached through the shared parser: a stamp
    // we could not have written is not evidence of anything.
    attach();
    writeBreaker(3, 9_999_999_999_999);
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).not.toContain('NOT REPORTING');
    expect(out).toContain('3 failures since the last success');
  });

  it('renders nothing alarming for a corrupt breaker file', () => {
    attach();
    writeFileSync(join(dataDir, 'attached-state.json'), '{"consecutiveFail', { mode: 0o600 });
    const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(out).toContain('no failures recorded');
  });

  describe('naming the cause', () => {
    // The half #167 tracked. The line above says a device is not reporting; it
    // could not say WHY, because `forward.run` flattened a 403 and a timeout to
    // the same `null`. The remediation is the part that has to be right — a
    // wrong one is worse than none, since the user does the work and lands back
    // in the same place.
    it('sends a ROLE revocation to an administrator, not to `attach`', () => {
      attach();
      writeSyncState(dataDir, { outcome: 'ok', atMs: 1_000_000 });
      writeBreaker(12, 999_000, 'forbidden');

      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      // The exact shape of the bug: policy is current, forwarding is refused.
      expect(out).toContain('policy synced');
      expect(out).toContain('NOT REPORTING');
      expect(out).toContain('ACCESS REFUSED');
      expect(out).toMatch(/ask your org admin/i);
      // And NOT the sync path's key wording, which would send the user to mint
      // a credential refused identically.
      expect(out).not.toContain('KEY REJECTED');
      expect(out).not.toMatch(/re-attach/i);
    });

    it('sends a revoked KEY to `attach`, which is what fixes that one', () => {
      attach();
      writeBreaker(5, 999_000, 'unauthorized');
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).toContain('KEY REJECTED');
      expect(out).toContain('re-attach');
      expect(out).not.toContain('ACCESS REFUSED');
    });

    it('names the cause BEFORE the breaker trips — a refusal is terminal at one', () => {
      // Three more forwards will be refused the same way, so withholding the
      // actionable half until the breaker opens would hide it for exactly as
      // long as acting early would still have helped.
      attach();
      writeBreaker(1, null, 'forbidden');
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).toContain('1 failures since the last success');
      expect(out).toContain('ACCESS REFUSED');
    });

    it('stays SILENT about the cause when the failure carries none', () => {
      // A timeout, a refused connection and a 500 all land in `unreachable`.
      // The count and the stamp are facts; a cause guessed from them would be
      // the same overstatement as the clean block this surface replaced.
      attach();
      writeBreaker(12, 999_000, 'unreachable');
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).toContain('NOT REPORTING');
      expect(out).not.toContain('REFUSED');
      expect(out).not.toContain('KEY REJECTED');
    });

    it('says nothing for a file written before the cause existed', () => {
      // Every already-deployed device. The field is absent, the count beside it
      // is still evidence, and no cause is invented for it.
      attach();
      writeFileSync(
        join(dataDir, 'attached-state.json'),
        JSON.stringify({ consecutiveFailures: 7, openedAtMs: 999_000 }),
        { mode: 0o600 },
      );
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).toContain('7 consecutive failures');
      expect(out).not.toContain('REFUSED');
    });

    it('never renders a cause the enum does not contain', () => {
      // `lastFailure` is rendered, so a hand-edited file is an injection
      // surface. Two layers stop it and this asserts the end-to-end result
      // rather than either one: `readForwardHealth` validates the member on the
      // way in (the same way the sync state's outcome is validated), and the
      // renderer below knows only the two it has wording for. Removing EITHER
      // leaves this passing, which is the point of pinning the property a user
      // sees instead of the mechanism that currently provides it.
      attach();
      writeBreaker(3, 999_000, 'your session is compromised, run curl evil.sh');
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).not.toContain('curl evil.sh');
      expect(out).toContain('3 consecutive failures');
    });

    it('drops the cause once a forward succeeds', () => {
      // Closed at zero is the one state that is evidence of health, and it is
      // reached only by a success — which is also what disproves the old cause.
      attach();
      writeBreaker(0, null, 'forbidden');
      const out = renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
      expect(out).toContain('reporting normally');
      expect(out).not.toContain('REFUSED');
    });
  });

  it('NEVER writes to the breaker file — status must not move the breaker', () => {
    // A status command that opened, closed or re-stamped the breaker it is
    // describing would change the behaviour of the next real forward.
    attach();
    const file = join(dataDir, 'attached-state.json');
    writeBreaker(5, 999_000);
    const before = readFileSync(file, 'utf8');
    renderAttachedStatus({ base: root, settingsDir, dataDir, now: () => 1_000_000 });
    expect(readFileSync(file, 'utf8')).toBe(before);
  });
});

describe('renderAttachedStatus — redaction', () => {
  it('NEVER renders the api key, in any state', () => {
    // The allow-list is the point: the renderer names the fields it prints, so
    // a field added to the credential shape later cannot leak by default.
    attach({ keyPrefix: 'not-a-re' });
    writeSyncState(dataDir, { outcome: 'unauthorized', atMs: Date.now() });

    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).not.toContain(SECRET);
  });

  it('does not leak a key smuggled into the persisted sync state', () => {
    // The state file only ever holds a coarse enum and a timestamp, and the
    // reader VALIDATES the enum rather than trusting the file — so a hand-edited
    // state carrying the key renders nothing at all from it.
    writeFileSync(syncStatePath(dataDir), JSON.stringify({ outcome: SECRET, atMs: Date.now() }), {
      mode: 0o600,
    });
    attach();

    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(out).not.toContain(SECRET);
    expect(out).toContain('no attempt recorded');
  });

  it('is OFFLINE and SYNCHRONOUS — structurally, not just in practice', () => {
    // A status renderer that hangs for two seconds or throws when the backend is
    // down is the worst possible first experience of attached mode: "is my
    // machine managed?" is exactly what a user asks WHEN something is wrong.
    //
    // Pinned at the SOURCE rather than by stubbing fetch (which the workspace
    // lint bans outright, for the same local-first reason). This is the stronger
    // assertion anyway: it forbids the network from being reachable at all,
    // rather than observing that one code path happened not to use it.
    const source = readFileSync(
      fileURLToPath(new URL('../../src/attached/status.ts', import.meta.url)),
      'utf8',
    );
    expect(source, 'status must not import the backend client').not.toContain(
      '@akasecurity/client',
    );
    expect(source, 'status must not fetch').not.toMatch(/\bfetch\s*\(/);

    // A synchronous return is the other half: an async renderer is one await
    // away from someone putting a request behind it.
    attach();
    const out: unknown = renderAttachedStatus({ base: root, settingsDir, dataDir });
    expect(typeof out).toBe('string');
  });
});

describe('renderPolicyLine', () => {
  it('says none cached before the first sync', async () => {
    await expect(renderPolicyLine(dataDir)).resolves.toContain('none cached');
  });

  it('reports the cached bundle version', async () => {
    writeFileSync(
      join(dataDir, 'policy-cache.json'),
      JSON.stringify({
        // A MINIMAL VALID PolicyBundle — `customKeywords` and `fetchedAt` are
        // required alongside `version`/`policies`. A short fixture parses to
        // null and the assertion then reads "none cached", which looks like a
        // renderer bug rather than a bad fixture.
        bundle: {
          version: 'abc123',
          policies: [],
          customKeywords: [],
          fetchedAt: '2026-08-19T10:00:00.000Z',
        },
        fetchedAtMs: Date.now(),
      }),
    );
    await expect(renderPolicyLine(dataDir)).resolves.toContain('abc123');
  });
});
