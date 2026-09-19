// What the registry read accepts, and what it refuses.
//
// Driven through the injected capture seam, never a real spawn: the PATH shims
// in this repo fail OPEN, so an unstubbed probe here would resolve the
// developer's own `npm` and reach the real registry from a suite that looks
// hermetic.
//
// Refusing the whole map rather than dropping a bad entry is the load-bearing
// part. A non-string version would be handed to the semver comparator, which
// treats what it cannot parse as EQUAL — so a junk value does not fail, it
// silently stops an update being offered.
import { describe, expect, it } from 'vitest';

import type { RunResult } from '../src/exec.ts';
import { npmViewDistTags } from '../src/updates.ts';

const PKG = '@akasecurity/cli';

/** A capture seam answering with one fixed result, recording what it was asked. */
function capturing(result: RunResult): {
  capture: (command: string, args: string[], timeoutMs?: number) => RunResult;
  calls: { command: string; args: string[] }[];
} {
  const calls: { command: string; args: string[] }[] = [];
  return {
    calls,
    capture: (command, args) => {
      calls.push({ command, args });
      return result;
    },
  };
}

const ok = (stdout: string): RunResult => ({ ok: true, stdout, stderr: '' });
const failed = (stdout: string): RunResult => ({ ok: false, stdout, stderr: 'npm ERR!' });

describe('npmViewDistTags — the request', () => {
  it('asks npm for the dist-tags of the named package, as JSON', () => {
    const { capture, calls } = capturing(ok('{"latest":"0.9.12"}'));
    npmViewDistTags(PKG, capture);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toBe('npm');
    // The whole argv, in order: `--json` is what stops npm sorting and
    // truncating the human-readable list, which can omit the very tag being
    // asked for, and the package name must be the argument rather than part of
    // a joined string.
    expect(calls[0]?.args).toStrictEqual(['view', PKG, 'dist-tags', '--json']);
  });
});

describe('npmViewDistTags — what it accepts', () => {
  it('reads a tag map', () => {
    const { capture } = capturing(ok('{"latest":"0.9.12","beta":"0.11.0-beta.3"}'));
    expect(npmViewDistTags(PKG, capture)).toStrictEqual({
      latest: '0.9.12',
      beta: '0.11.0-beta.3',
    });
  });

  it('tolerates a warning line printed on stdout ahead of the payload', () => {
    // The defence the single-version read it replaces had, kept: that one took
    // the LAST stdout line, and a bare parse of the whole buffer would drop it.
    const { capture } = capturing(ok('npm warn Unknown project config\n{"latest":"0.9.12"}'));
    expect(npmViewDistTags(PKG, capture)).toStrictEqual({ latest: '0.9.12' });
  });

  it('tolerates a warning line that itself carries a brace before the payload', () => {
    // A byte-scan for the first `{` anywhere in stdout lands inside this
    // warning's own brace and never reaches the payload at all — the case a
    // line-leading search is what closes.
    const { capture } = capturing(
      ok('npm warn using --force Recommended protections disabled. {config}\n{"latest":"1.0.0"}\n'),
    );
    expect(npmViewDistTags(PKG, capture)).toStrictEqual({ latest: '1.0.0' });
  });
});

describe('npmViewDistTags — what it refuses', () => {
  // Each case is a shape the registry, a proxy or a misconfigured npm can
  // really produce, and every one of them must read as NO ANSWER.
  //
  // Grouped by which check refuses it, because the two are mutated separately
  // and a case filed under the wrong one reads as covering a guard it cannot
  // reach. The first group never yields an object to inspect at all; the
  // second parses and is refused on its VALUES.
  // Refused on the EXIT CODE, before the payload is looked at. `npm view
  // --json` prints its own error OBJECT on stdout and exits non-zero, so these
  // parse and are a string map — the shape checks below cannot reach them, and
  // without the exit check a 404 would be read as a registry answer carrying
  // an `error` tag and no `latest`, which reads as "no update published".
  const refusedByExitCode: [string, RunResult][] = [
    ['a JSON error object from a failed lookup', failed('{"error":"code E404 - Not found"}')],
    ['a JSON error object with a summary tag', failed('{"error":"E403","summary":"Forbidden"}')],
    ['a non-zero exit whose stdout is not JSON at all', failed('npm ERR! 404 Not Found')],
  ];

  const notAnObject: [string, RunResult][] = [
    ['empty stdout', ok('')],
    ['stdout with no JSON in it at all', ok('E404 not found')],
    ['a truncated object', ok('{"latest":"0.9.1')],
    ['a JSON null', ok('null')],
    ['a JSON array', ok('[]')],
    ['a JSON string', ok('"0.9.12"')],
    ['an object with trailing junk after it', ok('{"latest":"0.9.12"} and then some')],
  ];

  const notAStringMap: [string, RunResult][] = [
    // The cases the per-value check exists for: replace it with a bare cast
    // and exactly these flip, which is what makes the red attributable.
    ['a number-valued tag', ok('{"latest":"0.9.12","beta":5}')],
    ['a null-valued tag', ok('{"latest":null}')],
    ['a nested-object tag', ok('{"latest":{"version":"0.9.12"}}')],
    ['an array-valued tag', ok('{"latest":["0.9.12"]}')],
  ];

  it.each([...refusedByExitCode, ...notAnObject, ...notAStringMap])(
    'refuses %s',
    (_label, result) => {
      const { capture } = capturing(result);
      expect(npmViewDistTags(PKG, capture)).toBeNull();
    },
  );

  it('has a case for each of the three reasons it refuses', () => {
    // The groups are what makes each red attributable, and an empty one would
    // leave its own reason unexercised while the run above still went green.
    for (const group of [refusedByExitCode, notAnObject, notAStringMap]) {
      expect(group.length).toBeGreaterThan(0);
    }
  });

  it('refuses the whole map rather than keeping the good entries', () => {
    // The positive control for the case above: a partial map would still carry
    // a usable `latest`, so "returns null" has to mean the map is gone rather
    // than that one key was dropped.
    const { capture } = capturing(ok('{"latest":"0.9.12","beta":5}'));
    expect(npmViewDistTags(PKG, capture)).not.toStrictEqual({ latest: '0.9.12' });
  });
});
