import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';

import { drizzleWallRules } from '../src/index.js';

// `drizzleWallRules` exists BECAUSE flat config replaces a rule rather than
// merging it: a package that wants the Drizzle ban and the network bans has to
// receive both in one value, or the later entry silently drops the other. The
// function then did the same thing to its own caller — `paths` and `patterns`
// handed in were overwritten by the Drizzle-derived arrays before they reached
// `noNetworkImports`, so a caller adding one restriction to the wall got that
// restriction and nothing else.
//
// It is the module's own failure mode reached from the inside, and it fails the
// way every one of them does: lint still exits 0.
//
// Driven through a real `Linter` rather than asserted against the rule's
// structure. A shape assertion passes on a value nothing enforces — and what a
// caller needs to know is which imports are refused, which is a question only
// the linter answers.
const linter = new Linter();

/** How many messages `code` produces under a wall built with `opts`. */
const firedUnder = (opts, code) =>
  linter.verify(code, {
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    rules: { 'no-restricted-imports': drizzleWallRules(opts)['no-restricted-imports'] },
  }).length;

const CALLER_PATH = { name: 'left-pad', message: "the caller's own ban" };
const CALLER_PATTERN = { group: ['lodash/*'], message: "the caller's own pattern" };

describe('drizzleWallRules merges a caller’s restrictions rather than replacing its own', () => {
  const wall = { paths: [CALLER_PATH], patterns: [CALLER_PATTERN] };

  it("refuses the caller's own path", () => {
    expect(firedUnder(wall, "import lp from 'left-pad';")).toBe(1);
  });

  it("refuses the caller's own pattern", () => {
    expect(firedUnder(wall, "import get from 'lodash/get';")).toBe(1);
  });

  it('still refuses drizzle, which is the half a replace would have kept', () => {
    // The overwrite kept the Drizzle entries and dropped the caller's, so this
    // case passed throughout and is here as the control: it is what tells a
    // reader the merge did not trade one ban for the other.
    expect(firedUnder(wall, "import { eq } from 'drizzle-orm';")).toBe(1);
    expect(firedUnder(wall, "import { p } from 'drizzle-orm/pg-core';")).toBe(1);
  });

  it('still refuses the network modules it carries forward from base', () => {
    // The other half this function exists to carry. A merge written as a
    // wholesale replace one level down would drop these instead, which is the
    // same defect moved rather than fixed.
    expect(firedUnder(wall, "import https from 'node:https';")).toBe(1);
    expect(firedUnder(wall, "import a from 'axios/lib/adapters/http.js';")).toBe(1);
  });

  it('leaves an unrestricted import alone', () => {
    // Without this every count above is satisfied by a wall that refuses
    // everything.
    expect(firedUnder(wall, "import { join } from 'node:path';")).toBe(0);
  });

  it('still honours allow alongside the merged entries', () => {
    // `allow` rides in `...rest` now that `paths`/`patterns` are destructured
    // out. A destructure that swallowed it would leave the network ban intact
    // and the opt-out silently inert — green lint on a file that needs the
    // exception, which is the shape of every other failure in this module.
    expect(firedUnder({ ...wall, allow: ['node:https'] }, "import https from 'node:https';")).toBe(
      0,
    );
    expect(firedUnder({ ...wall, allow: ['node:https'] }, "import net from 'node:net';")).toBe(1);
  });

  it('takes no paths or patterns at all, exactly as every call site does today', () => {
    // The backward-compatibility case. Every existing caller passes neither, so
    // the defaults must leave the wall byte-for-byte what it was.
    expect(firedUnder({}, "import { eq } from 'drizzle-orm';")).toBe(1);
    expect(firedUnder(undefined, "import { eq } from 'drizzle-orm';")).toBe(1);
    expect(firedUnder({}, "import lp from 'left-pad';")).toBe(0);
  });
});
