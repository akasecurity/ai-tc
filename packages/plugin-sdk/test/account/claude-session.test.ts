import { randomUUID } from 'node:crypto';
import { appendFileSync, statSync, writeFileSync } from 'node:fs';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { CredentialOrgSighting, TranscriptDelta } from '../../src/account/claude-session.ts';
import {
  anchorOf,
  credentialOrgAt,
  credentialOrgOf,
  readScanCache,
  resolveSessionAnchor,
  scanCredentialOrgs,
  writeScanCache,
} from '../../src/account/claude-session.ts';
import type { SessionBoundary } from '../../src/account/observation-log.ts';
import { sessionScanCachePath } from '../../src/account/observation-log.ts';
import type { ClaudeMachine } from '../helpers/transcript-builder.ts';
import {
  appendLines,
  assistantLine,
  claudeMachine,
  credentialOrgLine,
  SECOND,
  T0,
  toolOutputLine,
  userPromptLine,
  writeLines,
} from '../helpers/transcript-builder.ts';

let machine: ClaudeMachine;
let sid: string;

beforeEach(() => {
  machine = claudeMachine();
  sid = machine.sessionId;
});

afterEach(() => {
  machine.dispose();
});

const startup = (t = T0): SessionBoundary => ({ t, kind: 'startup', inherited: false });
const sighting = (org: string, t: number): CredentialOrgSighting => ({ pos: t, t, org });
const orgs = (delta: TranscriptDelta): string[] => delta.sightings.map((s) => s.org);

function scan(from: number): TranscriptDelta {
  const delta = scanCredentialOrgs(machine.transcript, sid, from);
  if (delta === undefined) throw new Error('the scan gave up');
  return delta;
}

describe('credentialOrgOf', () => {
  it("reads the org of this session's credential_org attachment, lower-cased", () => {
    const org = randomUUID();
    expect(credentialOrgOf(credentialOrgLine(sid, org.toUpperCase(), T0), sid)).toEqual({
      t: T0,
      org,
    });
  });

  it('ignores a record of another session, such as a fork or a subagent', () => {
    expect(credentialOrgOf(credentialOrgLine(randomUUID(), randomUUID(), T0), sid)).toBeUndefined();
  });

  it('ignores a value that is not a UUID, a tokenized one included', () => {
    for (const value of ['[REDACTED]', `tok_${randomUUID()}`, '', 'not-a-uuid']) {
      expect(credentialOrgOf(credentialOrgLine(sid, value, T0), sid)).toBeUndefined();
    }
  });

  it('ignores a torn line and a line with no timestamp', () => {
    const line = credentialOrgLine(sid, randomUUID(), T0);
    expect(credentialOrgOf(line.slice(0, -10), sid)).toBeUndefined();
    expect(credentialOrgOf(line.replace(/"timestamp":"[^"]+",/, ''), sid)).toBeUndefined();
  });
});

describe('scanCredentialOrgs', () => {
  it('reads every sighting in file order, up to the last complete line', () => {
    const [a, b] = [randomUUID(), randomUUID()];
    writeLines(machine.transcript, [
      userPromptLine(sid, 'hi', T0),
      credentialOrgLine(sid, a, T0 + SECOND),
      assistantLine(sid, T0 + 2 * SECOND),
      credentialOrgLine(sid, b, T0 + 3 * SECOND),
    ]);
    const whole = statSync(machine.transcript).size;
    appendFileSync(machine.transcript, credentialOrgLine(sid, randomUUID(), T0).slice(0, 40));
    const delta = scan(0);
    expect(orgs(delta)).toEqual([a, b]);
    expect(delta.nextOffset).toBe(whole);
    expect(delta.rescanned).toBe(false);
  });

  it('ignores credential_org written inside tool output', () => {
    writeLines(machine.transcript, [toolOutputLine(sid, randomUUID(), T0)]);
    expect(scan(0).sightings).toEqual([]);
  });

  it('reads only what was appended past the offset', () => {
    const [a, b] = [randomUUID(), randomUUID()];
    writeLines(machine.transcript, [credentialOrgLine(sid, a, T0)]);
    const first = scan(0);
    appendLines(machine.transcript, [credentialOrgLine(sid, b, T0 + SECOND)]);
    const second = scan(first.nextOffset);
    expect(orgs(second)).toEqual([b]);
    expect(second.rescanned).toBe(false);
  });

  it('rescans from the top when the file shrank under the offset', () => {
    const [a, b, c] = [randomUUID(), randomUUID(), randomUUID()];
    writeLines(machine.transcript, [
      credentialOrgLine(sid, a, T0),
      credentialOrgLine(sid, b, T0 + SECOND),
    ]);
    const first = scan(0);
    writeLines(machine.transcript, [credentialOrgLine(sid, c, T0)]);
    const shrunk = scan(first.nextOffset);
    expect(shrunk.rescanned).toBe(true);
    expect(orgs(shrunk)).toEqual([c]);
  });

  it('rescans from the top when a rewrite left no newline just before the offset', () => {
    const b = randomUUID();
    writeLines(machine.transcript, [
      userPromptLine(sid, 'a', T0),
      credentialOrgLine(sid, b, T0 + SECOND),
    ]);
    const first = scan(0);
    writeLines(machine.transcript, [
      userPromptLine(sid, 'a, rewritten longer by the scrub', T0),
      credentialOrgLine(sid, b, T0 + SECOND),
    ]);
    const rewritten = scan(first.nextOffset);
    expect(rewritten.rescanned).toBe(true);
    expect(orgs(rewritten)).toEqual([b]);
  });

  it('gives up past the cap, and on a missing transcript', () => {
    writeLines(machine.transcript, [
      credentialOrgLine(sid, randomUUID(), T0),
      userPromptLine(sid, 'x'.repeat(4096), T0 + SECOND),
    ]);
    expect(scanCredentialOrgs(machine.transcript, sid, 0, 1024)).toBeUndefined();
    expect(scanCredentialOrgs(`${machine.transcript}.missing`, sid, 0)).toBeUndefined();
  });

  it('reads a record that straddles a read chunk, at the offset its line starts', () => {
    const CHUNK = 4 * 1024 * 1024; // how many bytes the scan reads at a time
    const padding = `${userPromptLine(sid, 'x'.repeat(40), T0)}\n`;
    const paddingBytes = Buffer.byteLength(padding);
    const [straddling, after] = [randomUUID(), randomUUID()];
    const straddlingLine = `${credentialOrgLine(sid, straddling, T0 + SECOND)}\n`;
    const afterLine = `${credentialOrgLine(sid, after, T0 + 2 * SECOND)}\n`;
    const leading = Math.floor((CHUNK - 16) / paddingBytes);
    const straddlingAt = leading * paddingBytes;
    const afterAt = straddlingAt + Buffer.byteLength(straddlingLine) + 10 * paddingBytes;
    expect(straddlingAt).toBeLessThan(CHUNK);
    expect(straddlingAt + Buffer.byteLength(straddlingLine)).toBeGreaterThan(CHUNK);
    writeFileSync(
      machine.transcript,
      padding.repeat(leading) + straddlingLine + padding.repeat(10) + afterLine,
    );
    const delta = scan(0);
    expect(delta.sightings).toEqual([
      { pos: straddlingAt, t: T0 + SECOND, org: straddling },
      { pos: afterAt, t: T0 + 2 * SECOND, org: after },
    ]);
    expect(delta.nextOffset).toBe(statSync(machine.transcript).size);
    expect(delta.nextOffset).toBeGreaterThan(CHUNK);
    expect(delta.rescanned).toBe(false);
  });
});

describe('credentialOrgAt', () => {
  it('re-reads the org on the line a sighting starts at, and nothing mid-line', () => {
    const [a, b] = [randomUUID(), randomUUID()];
    writeLines(machine.transcript, [
      credentialOrgLine(sid, a, T0),
      credentialOrgLine(sid, b, T0 + SECOND),
    ]);
    const second = scan(0).sightings[1];
    expect(second).toBeDefined();
    expect(credentialOrgAt(machine.transcript, sid, second?.pos ?? -1)).toBe(b);
    expect(credentialOrgAt(machine.transcript, sid, 3)).toBeUndefined();
  });
});

describe('anchorOf', () => {
  it('has no anchor before the first reply, so turn 1 of a new session stays local', () => {
    expect(anchorOf([], startup()).anchor).toEqual({ kind: 'none', reason: 'no-session-account' });
  });

  it('anchors on the first credential_org at or after the boundary', () => {
    const org = randomUUID();
    expect(anchorOf([sighting(org, T0 + SECOND)], startup()).anchor).toEqual({
      kind: 'anchor',
      org,
      at: T0 + SECOND,
    });
  });

  it('ignores a credential_org from before a clear', () => {
    const [old, current] = [randomUUID(), randomUUID()];
    const clear: SessionBoundary = { t: T0, kind: 'clear', inherited: false };
    expect(
      anchorOf([sighting(old, T0 - SECOND), sighting(current, T0 + SECOND)], clear).anchor,
    ).toMatchObject({
      kind: 'anchor',
      org: current,
    });
  });

  it('a second org under one boundary attributes none', () => {
    const [first, second] = [randomUUID(), randomUUID()];
    const outcome = anchorOf(
      [sighting(first, T0 + SECOND), sighting(second, T0 + 2 * SECOND)],
      startup(),
    );
    expect(outcome.anchor).toEqual({ kind: 'none', reason: 'org-changed' });
    expect(outcome.anchorAt).toBe(T0 + SECOND);
    expect(outcome.changedAt).toBe(T0 + 2 * SECOND);
  });

  it('trusts the same org re-emitted after a compaction', () => {
    const org = randomUUID();
    expect(
      anchorOf([sighting(org, T0 + SECOND), sighting(org, T0 + 9 * SECOND)], startup()).anchor,
    ).toMatchObject({
      kind: 'anchor',
      org,
    });
  });

  it('anchors an inherited resume on the last credential_org before it', () => {
    const [older, last] = [randomUUID(), randomUUID()];
    const resume: SessionBoundary = { t: T0 + 10 * SECOND, kind: 'resume', inherited: true };
    expect(
      anchorOf([sighting(older, T0 + SECOND), sighting(last, T0 + 2 * SECOND)], resume).anchor,
    ).toEqual({
      kind: 'anchor',
      org: last,
      at: T0 + 2 * SECOND,
    });
    const reemitted = [sighting(last, T0 + 2 * SECOND), sighting(older, T0 + 11 * SECOND)];
    expect(anchorOf(reemitted, resume).anchor).toEqual({ kind: 'none', reason: 'org-changed' });
  });

  it('anchors a resume with no inheritance only on a credential_org after it', () => {
    const [before, after] = [randomUUID(), randomUUID()];
    const resume: SessionBoundary = { t: T0 + 10 * SECOND, kind: 'resume', inherited: false };
    expect(anchorOf([sighting(before, T0 + SECOND)], resume).anchor.kind).toBe('none');
    expect(
      anchorOf([sighting(before, T0 + SECOND), sighting(after, T0 + 11 * SECOND)], resume).anchor,
    ).toMatchObject({
      kind: 'anchor',
      org: after,
    });
  });

  it('has no anchor without a boundary, as for a session whose log holds no start line', () => {
    expect(anchorOf([sighting(randomUUID(), T0 + SECOND)], undefined).anchor.kind).toBe('none');
  });
});

describe('resolveSessionAnchor', () => {
  it('keeps the anchor across hooks, and a later different org is sticky until the next boundary', () => {
    const [work, other] = [randomUUID(), randomUUID()];
    writeLines(machine.transcript, [credentialOrgLine(sid, work, T0 + SECOND)]);
    const first = resolveSessionAnchor(machine.transcript, sid, startup(), undefined);
    expect(first?.anchor).toMatchObject({ kind: 'anchor', org: work });
    appendLines(machine.transcript, [credentialOrgLine(sid, other, T0 + 2 * SECOND)]);
    const second = resolveSessionAnchor(machine.transcript, sid, startup(), first?.state);
    expect(second?.anchor).toEqual({ kind: 'none', reason: 'org-changed' });
    appendLines(machine.transcript, [credentialOrgLine(sid, work, T0 + 3 * SECOND)]);
    const third = resolveSessionAnchor(machine.transcript, sid, startup(), second?.state);
    expect(third?.anchor).toEqual({ kind: 'none', reason: 'org-changed' });
    const clear: SessionBoundary = { t: T0 + 2500, kind: 'clear', inherited: false };
    expect(
      resolveSessionAnchor(machine.transcript, sid, clear, third?.state)?.anchor,
    ).toMatchObject({
      kind: 'anchor',
      org: work,
    });
  });

  it('holds byte offsets and the boundary time in its state, never an org value', () => {
    const org = randomUUID();
    writeLines(machine.transcript, [credentialOrgLine(sid, org, T0 + SECOND)]);
    const resolved = resolveSessionAnchor(machine.transcript, sid, startup(), undefined);
    expect(resolved?.state.lastBoundaryAt).toBe(T0);
    expect(JSON.stringify(resolved?.state)).not.toContain(org);
  });
});

describe('a clear inside a work session', () => {
  const clear: SessionBoundary = { t: T0 + 10 * SECOND, kind: 'clear', inherited: false };
  let work: string;

  beforeEach(() => {
    work = randomUUID();
  });

  function workedThenCleared(): ReturnType<typeof resolveSessionAnchor> {
    writeLines(machine.transcript, [
      userPromptLine(sid, 'hello', T0 + SECOND),
      credentialOrgLine(sid, work, T0 + 2 * SECOND),
      assistantLine(sid, T0 + 3 * SECOND),
    ]);
    const before = resolveSessionAnchor(machine.transcript, sid, startup(), undefined);
    expect(before?.anchor).toMatchObject({ kind: 'anchor', org: work });
    appendLines(machine.transcript, [userPromptLine(sid, 'after the clear', T0 + 11 * SECOND)]);
    const firstPrompt = resolveSessionAnchor(machine.transcript, sid, clear, before?.state);
    expect(firstPrompt?.anchor).toEqual({ kind: 'none', reason: 'no-session-account' });
    return firstPrompt;
  }

  it('keeps the first prompt after the clear local, and anchors again on a re-emitted record', () => {
    const firstPrompt = workedThenCleared();
    appendLines(machine.transcript, [
      credentialOrgLine(sid, work, T0 + 12 * SECOND),
      assistantLine(sid, T0 + 13 * SECOND),
    ]);
    expect(
      resolveSessionAnchor(machine.transcript, sid, clear, firstPrompt?.state)?.anchor,
    ).toMatchObject({
      kind: 'anchor',
      org: work,
    });
  });

  it('has no anchor for the rest of the session when no record is re-emitted, never the old one', () => {
    const firstPrompt = workedThenCleared();
    appendLines(machine.transcript, [
      assistantLine(sid, T0 + 13 * SECOND),
      userPromptLine(sid, 'more', T0 + 20 * SECOND),
    ]);
    const later = resolveSessionAnchor(machine.transcript, sid, clear, firstPrompt?.state);
    expect(later?.anchor).toEqual({ kind: 'none', reason: 'no-session-account' });
    expect(resolveSessionAnchor(machine.transcript, sid, clear, undefined)?.anchor).toEqual({
      kind: 'none',
      reason: 'no-session-account',
    });
  });
});

describe('the transcript scan cache', () => {
  it('round-trips, and reads a corrupt or out-of-shape file as absent', () => {
    const cache = {
      offset: 120,
      anchorAt: 40,
      lastBoundaryAt: T0,
      boundaryKind: 'startup',
      inherited: false,
    } as const;
    writeScanCache(machine.stateDir, sid, cache);
    expect(readScanCache(machine.stateDir, sid)).toEqual(cache);
    writeFileSync(sessionScanCachePath(machine.stateDir, sid), '{"offset": -1}');
    expect(readScanCache(machine.stateDir, sid)).toBeUndefined();
    writeFileSync(sessionScanCachePath(machine.stateDir, sid), 'not json');
    expect(readScanCache(machine.stateDir, sid)).toBeUndefined();
    expect(readScanCache(machine.stateDir, randomUUID())).toBeUndefined();
  });
});
