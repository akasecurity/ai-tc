// Tests the host-floor notice directly — NEVER via a hook entry file
// (src/hooks/*.ts run main() on import and hang vitest collection).
//
// What this pins: an old Claude Code silently loses whichever hook events it
// does not recognise, so AKA must say so — once per session, from the two hooks
// where the transcript's newest record is guaranteed to be the running host's —
// and must stay SILENT whenever it cannot establish the version, because a false
// "update Claude Code" on a correct install is worse than no warning at all.
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { HOST_FLOORS, readHostVersionCache, requiredHostVersion } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { warnIfHostBelowFloor } from '../../src/hooks/host-floor-notice.ts';

let dir: string;
let dataDir: string;
let written: string[];

/** A host that clears every floor, derived so a new row cannot strand this. */
const CURRENT = requiredHostVersion(
  Object.entries(HOST_FLOORS).map(([feature, row]) => ({
    feature,
    label: row.label,
    since: row.since,
  })),
);

const ANCIENT = '2.0.0';

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-host-floor-notice-'));
  dataDir = join(dir, 'data');
  mkdirSync(dataDir, { recursive: true });
  written = [];
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const write = (message: string): void => {
  written.push(message);
};

function transcript(version: string | undefined): string {
  // Throw rather than assert: an unparseable `since` would make CURRENT
  // undefined, and a silent `undefined` here would write a version-less record
  // and turn the "says NOTHING for a current host" control into a vacuous pass.
  if (version === undefined) throw new Error('no derivable current version');
  const path = join(dir, `${version}.jsonl`);
  writeFileSync(path, `${JSON.stringify({ type: 'user', version })}\n`, 'utf8');
  return path;
}

function warn(sessionId: string | undefined, transcriptPath: string | undefined): void {
  warnIfHostBelowFloor({ dataDir }, sessionId, transcriptPath, write);
}

describe('warnIfHostBelowFloor', () => {
  it('has a derivable current version to test against', () => {
    // Guard rather than `as string`: an unparseable `since` would make CURRENT
    // undefined and quietly turn the control below into a vacuous pass.
    expect(CURRENT).toBeDefined();
  });

  it('warns once per session, not once per hook fire', () => {
    // The check runs on every Stop and PostToolUse, so without the claim this
    // would print on every turn for the rest of the session.
    warn('s1', transcript(ANCIENT));
    warn('s1', transcript(ANCIENT));
    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(1);
    expect(written[0]).toContain('[aka]');
    expect(written[0]).toContain('Update Claude Code');
  });

  it('warns again for a different session', () => {
    warn('s1', transcript(ANCIENT));
    warn('s2', transcript(ANCIENT));
    expect(written.length).toBe(2);
  });

  it('warns every fire when there is no session id to dedupe on', () => {
    // Fail-open toward warning: repeating a notice is noise, hiding that a
    // protection is off is not.
    warn(undefined, transcript(ANCIENT));
    warn(undefined, transcript(ANCIENT));
    expect(written.length).toBe(2);
  });

  it('says NOTHING for a host that clears every floor', () => {
    // The non-vacuity control for this file: without it, every assertion above
    // is satisfied by a function that warns unconditionally.
    warn('s1', transcript(CURRENT));
    expect(written).toEqual([]);
  });

  it('says nothing when the version cannot be established', () => {
    const empty = join(dir, 'empty.jsonl');
    writeFileSync(empty, '', 'utf8');
    const bookkeepingOnly = join(dir, 'bk.jsonl');
    writeFileSync(bookkeepingOnly, `${JSON.stringify({ type: 'queue-operation' })}\n`, 'utf8');

    warn('s1', undefined);
    warn('s2', join(dir, 'absent.jsonl'));
    warn('s3', empty);
    warn('s4', bookkeepingOnly);
    expect(written).toEqual([]);
  });

  it('caches the version even when the host is current, so `aka status` can report it', () => {
    warn('s1', transcript(CURRENT));
    expect(readHostVersionCache(dataDir)?.version).toBe(CURRENT);
  });

  it('caches the version it warned about', () => {
    warn('s1', transcript(ANCIENT));
    expect(readHostVersionCache(dataDir)?.version).toBe(ANCIENT);
  });

  it('never throws, whatever the writer does', () => {
    expect(() => {
      warnIfHostBelowFloor({ dataDir }, 's1', transcript(ANCIENT), () => {
        throw new Error('writer exploded');
      });
    }).not.toThrow();
  });

  it('releases the claim when the write throws, so the next fire retries', () => {
    // Swallowing the throw is not enough. The claim is taken BEFORE the write
    // (an exclusive create is the only thing that excludes concurrent hooks), so
    // a writer that threw would otherwise consume the session's one notice and
    // stay silent for good.
    warnIfHostBelowFloor({ dataDir }, 's1', transcript(ANCIENT), () => {
      throw new Error('writer exploded');
    });
    expect(written).toEqual([]);
    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(1);
  });

  it('releases the claim when nothing could be observed', () => {
    // A fresh transcript has no version-bearing record yet. Consuming the claim
    // there would mean the session never observes the host at all.
    const empty = join(dir, 'empty.jsonl');
    writeFileSync(empty, '', 'utf8');
    warn('s1', empty);
    expect(written).toEqual([]);
    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(1);
  });

  it('stays silent for the rest of the session once the host is known to be current', () => {
    // The counterpart: a current host HAS been observed, so the claim is kept
    // and the transcript read does not repeat on every tool call.
    warn('s1', transcript(CURRENT));
    warn('s1', transcript(ANCIENT));
    expect(written).toEqual([]);
  });
});

describe('a session that outlives its claim', () => {
  it('warns again once the claim has aged out', () => {
    // `--continue` keeps the session id, so a claim that never expired would
    // silence the notice for a session someone resumes for days — told once, in
    // a line they may never have read, while a protection stays off.
    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(1);

    const claim = join(dataDir, 'host-floor-claims', encodeURIComponent('s1'));
    const longAgo = new Date(Date.now() - 48 * 60 * 60 * 1000);
    utimesSync(claim, longAgo, longAgo);

    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(2);
  });

  it('stays silent while the claim is still fresh', () => {
    // The control: without it the case above passes against a claim that never
    // suppresses anything at all.
    warn('s1', transcript(ANCIENT));
    warn('s1', transcript(ANCIENT));
    expect(written.length).toBe(1);
  });
});
