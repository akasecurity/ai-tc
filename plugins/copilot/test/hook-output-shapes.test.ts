/**
 * The shapes `emit()` may write to stdout, held to the sentence that enumerates
 * them.
 *
 * The Claude Code sibling's version of this file exists because that
 * enumeration drifted once — it said four while six were reaching the wire, and
 * the two it omitted belonged to the two hooks the prose never named, so
 * nothing about the sentence looked wrong. The drift was possible because
 * `emit` took `unknown`: a new shape reached stdout without passing anything
 * that could be counted.
 *
 * Here `emit` takes the `HookOutput` union, which makes the chain checkable end
 * to end:
 *
 *   call site → union     the compiler, via `emit`'s parameter type
 *   union → this list     the compile-time pins below
 *   this list → the prose the assertions below
 *
 * Each link is enforced by something, so a seventh shape cannot land quietly at
 * any of them. What none of it covers is a hook that writes to stdout WITHOUT
 * going through `emit` — that is `test/e2e/fail-open.e2e.test.ts`'s ground,
 * which reads what the built scripts really print.
 *
 * The sentence lives in `src/hooks/shared.ts` rather than in `CLAUDE.md`: this
 * union spans two dialects and is a property of this package, and the Claude
 * Code sibling's §1 sentence is about that host's shapes. What `CLAUDE.md` DOES
 * carry for this host is the failure convention, and the block of assertions at
 * the bottom of this file holds that bullet to what the code does — because a
 * hook-contract bullet that drifted is the same defect one level up, and the
 * drift the sibling file exists to catch was exactly that.
 */
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { emit, HookOutput } from '../src/hooks/shared.ts';

const SOURCE_FILE = 'src/hooks/shared.ts';

/**
 * One entry per variant of the union, named by the key that is REQUIRED on it
 * and on no sibling — which is how a reader tells them apart, and how the
 * compile-time pins below identify them.
 */
const SHAPE_KEYS = [
  'permissionDecision',
  'modifiedArgs',
  'modifiedResult',
  'hookSpecificOutput',
  'decision',
  'systemMessage',
] as const;

// ---------------------------------------------------------------------------
// The compile-time half — `pnpm typecheck` covers test/, so these are gates
// ---------------------------------------------------------------------------

/** The keys of `T` that are not optional. */
type RequiredKeys<T> = {
  [K in keyof T]-?: object extends Pick<T, K> ? never : K;
}[keyof T];

/**
 * Every required key of every member of the union.
 *
 * The distribution has to happen through a type PARAMETER — `HookOutput extends
 * unknown ? RequiredKeys<HookOutput> : never` written out against the concrete
 * alias does not distribute, and `keyof` over a union is the INTERSECTION of
 * its members' keys, which for this union is empty. That version resolves to
 * `never`, which makes the "every variant is named" pin vacuously true while
 * the "every name has a variant" pin is the only thing that fails. Both
 * directions exist precisely so one of them notices.
 */
type DistributedRequiredKeys<T> = T extends unknown ? RequiredKeys<T> : never;
type VariantKey = DistributedRequiredKeys<HookOutput>;

// Both directions, because they fail differently. A variant added to the union
// and not to the list is a shape nothing counts (the drift that happened); a
// list entry whose variant is gone is an expectation outliving what it
// described, which leaves the prose naming a shape no hook can emit.
type EveryVariantNamed = [VariantKey] extends [(typeof SHAPE_KEYS)[number]] ? true : never;
type EveryNameEmitted = [(typeof SHAPE_KEYS)[number]] extends [VariantKey] ? true : never;

// And that `emit` still narrows at all: were its parameter widened back to
// `unknown`, this stops being assignable and the union above becomes decoration
// the compiler no longer enforces at the one call site that matters.
type EmitNarrowsToHookOutput = [Parameters<typeof emit>[0]] extends [HookOutput] ? true : never;

const everyVariantNamed: EveryVariantNamed = true;
const everyNameEmitted: EveryNameEmitted = true;
const emitNarrows: EmitNarrowsToHookOutput = true;

// ---------------------------------------------------------------------------
// Reading the sentence
// ---------------------------------------------------------------------------

// Written out rather than derived from Intl: the prose spells the count in
// words, and a locale-dependent list would make this expectation depend on the
// runner.
const CARDINALS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];

/**
 * The count word and body of the one "Its <n> shapes are …" sentence.
 *
 * Throws unless it occurs exactly once. A reworded sentence this cannot find is
 * a guard that would otherwise assert nothing and pass — the same failure the
 * enumeration itself had, one level up.
 */
function shapesSentence(text: string): { count: string; body: string } {
  // `\s+` around the wrapping, not a literal space: the source is hard-wrapped
  // with a ` * ` comment prefix, so any of these gaps can be a line break.
  const found = [...text.matchAll(/Its\s+\*?(\w+)\*?\s+shapes\s+are\s+([\s\S]*?)\.\s/gu)];
  const [match, ...extra] = found;
  const count = match?.[1];
  const body = match?.[2];
  if (count === undefined || body === undefined || extra.length > 0) {
    throw new Error(
      `${SOURCE_FILE}: expected exactly one "Its <n> shapes are …" sentence, found ` +
        `${String(found.length)}. It was reworded, removed or duplicated, and this guard cannot ` +
        'read what it is meant to be asserting.',
    );
  }
  return { count: count.toLowerCase(), body };
}

/** The backticked code spans in `text`, in order. */
const codeSpansOf = (text: string): string[] =>
  [...text.matchAll(/`([^`]+)`/gu)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]));

// The sentence lives in a block comment, so every continuation line opens with
// ` * `. Stripped before anything is matched: left in, the prefix lands mid-
// sentence wherever the hard wrap fell, and a phrase assertion would then be
// pinning today's line breaks rather than today's wording.
const SOURCE = readFileSync(new URL(`../${SOURCE_FILE}`, import.meta.url), 'utf8').replace(
  /^\s*\*[ \t]?/gmu,
  '',
);
const SENTENCE = shapesSentence(SOURCE);

describe(`${SOURCE_FILE}'s emit() shape enumeration`, () => {
  it('is pinned to the union at compile time', () => {
    // These are `true` only because the conditional types above resolved to
    // `true`; had either resolved to `never`, `pnpm typecheck` would already
    // have failed and this file would not run. Asserting them here is what
    // stops them being unused declarations someone deletes as dead weight.
    expect([everyVariantNamed, everyNameEmitted, emitNarrows]).toEqual([true, true, true]);
  });

  it('reads a sentence that is really there', () => {
    // Every assertion below is about a set parsed out of prose, and all of them
    // pass on the empty set. This separates "the prose says nothing" from "the
    // prose agrees".
    expect(SENTENCE.body.length, 'the shapes sentence has no body').toBeGreaterThan(0);
    expect(SHAPE_KEYS.length, 'no shapes derived from the union').toBeGreaterThan(0);
  });

  it('states the number of shapes the union carries', () => {
    const word = CARDINALS[SHAPE_KEYS.length];
    expect(
      word,
      `no cardinal word for ${String(SHAPE_KEYS.length)} — extend CARDINALS`,
    ).toBeDefined();
    expect(SENTENCE.count).toBe(word);
  });

  it('names every shape, and no others', () => {
    // A set rather than a sequence: the prose is free to reorder or reword
    // around them. What it is not free to do is drop one, or name one that no
    // variant of the union carries.
    expect([...new Set(codeSpansOf(SENTENCE.body))].sort()).toEqual([...SHAPE_KEYS].sort());
  });

  it('keeps the two dialects distinguishable in the prose', () => {
    // The set check above passes on a sentence that lists all six spans in a
    // heap. This is the substantive claim a reader acts on: which host each
    // shape belongs to, since emitting a CLI shape under VS Code is a payload
    // that host's schema rejects.
    const flat = SENTENCE.body.replace(/\s+/gu, ' ');
    expect(flat).toMatch(/CLI's `permissionDecision`, `modifiedArgs` and `modifiedResult`/u);
    expect(flat).toMatch(/VS Code's `hookSpecificOutput` and `decision`/u);
    // Was "`systemMessage` both dialects share", and that is now false: the CLI
    // documents no message field on `preToolUse`, so a bare systemMessage is VS
    // Code's alone and a CLI notice goes to stderr. Pinned as the narrower
    // claim, because the wider one is exactly the mistake this case exists to
    // catch — a reader acting on it would put a message on CLI stdout.
    expect(flat).toMatch(/bare `systemMessage` that VS Code alone accepts/u);
  });
});

// ---------------------------------------------------------------------------
// The other half of the doc: CLAUDE.md's hook-contract bullet for this host
// ---------------------------------------------------------------------------

const CONVENTIONS = readFileSync(new URL('../../../CLAUDE.md', import.meta.url), 'utf8');

/**
 * The bullet, sliced out by its own bold lead. Throws unless it occurs exactly
 * once — a reworded bullet this cannot find is a guard that would otherwise
 * assert nothing and pass.
 */
function copilotBullet(): string {
  const lead = '- **GitHub Copilot is TWO hosts behind one package';
  const at = CONVENTIONS.indexOf(lead);
  if (at === -1 || CONVENTIONS.slice(at + 1).includes(lead)) {
    throw new Error(
      'CLAUDE.md: expected exactly one GitHub Copilot hook-contract bullet. It was reworded, ' +
        'removed or duplicated, and this guard cannot read what it is meant to be asserting.',
    );
  }
  const rest = CONVENTIONS.slice(at + lead.length);
  const end = rest.indexOf('\n- **');
  return (end === -1 ? rest : rest.slice(0, end)).replace(/\s+/gu, ' ');
}

/**
 * The `permissionDecision` line inside `CliPermissionDecisionOutput`, and only
 * that one.
 *
 * Throws rather than returning '' when the interface cannot be found: an
 * assertion against an empty string would pass every `not.toMatch` and read as
 * a guard holding while it asserted nothing at all.
 */
function cliVerdictField(): string {
  const at = SOURCE.indexOf('export interface CliPermissionDecisionOutput {');
  if (at === -1) throw new Error('shared.ts: CliPermissionDecisionOutput was renamed or removed');
  const body = SOURCE.slice(at, SOURCE.indexOf('}', at));
  const line = body.split('\n').find((l) => l.includes('permissionDecision'));
  if (line === undefined)
    throw new Error('shared.ts: CliPermissionDecisionOutput lost its verdict');
  return line.trim();
}

describe("CLAUDE.md's hook-contract bullet for this host", () => {
  const BULLET = copilotBullet();

  it('reads a bullet that is really there', () => {
    expect(BULLET.length).toBeGreaterThan(0);
  });

  it('names the exit-code channel as the one that fails closed', () => {
    // Each half is a separate claim a reader acts on, so each is matched
    // separately rather than as one sentence a reflow could break.
    expect(BULLET).toMatch(/exits non-zero other than 2 \*\*denies the tool call\*\*/u);
    expect(BULLET).toMatch(/exit 2 denies/u);
    expect(BULLET).toMatch(/timed-out one allows/u);
    expect(BULLET).toMatch(/every other event fails open/u);
  });

  it('says EMPTY STDOUT is the documented no-opinion, not an unmeasured case', () => {
    // The claim the whole design now rests on, and the one that was wrong
    // before: this bullet used to call the empty-stdout case "unmeasured" and
    // justify an explicit allow by it. Both halves are pinned — the vendor's
    // own wording, and the retraction — so a silent revert to the old reading
    // fails here rather than in review.
    expect(BULLET).toContain('Empty output uses default behavior');
    expect(BULLET).toMatch(/NOT unmeasured/u);
    expect(BULLET).toContain('test/fixtures/cli/README.md');
  });

  it('says why an explicit allow is refused, and that the type enforces it', () => {
    // Prose and code held together: the bullet claims a compile error, so the
    // type really has to be the narrow one. A bullet promising a guarantee the
    // module does not carry is the drift this pair exists to catch.
    expect(BULLET).toMatch(/pre-approve/u);
    expect(BULLET).toMatch(/compile error/u);
    // Sliced to the CLI interface rather than searched across the file: VS
    // Code's shape legitimately carries `'allow' | 'deny'`, so a whole-file
    // search for that string would either pass vacuously or forbid the wrong
    // one.
    expect(cliVerdictField()).toBe("permissionDecision: 'deny';");
  });

  it('says the two dialects are payload formats the CLI can both speak', () => {
    // The premise that was false and is now the reason `hooks.json` registers
    // one key. Pinned against the manifest itself, not just against the prose.
    expect(BULLET).toMatch(/payload FORMATS, not hosts/u);
    expect(BULLET).toMatch(/spawns the hook twice per call/u);
    // The weaker fact this bullet actually claims, so the exact key SET stays
    // asserted in one place — `hooks-manifest.test.ts`, whose subject is the
    // manifest. Duplicating it here would mean a deliberate manifest change
    // failed twice with the same message.
    const manifest = JSON.parse(
      readFileSync(new URL('../hooks.json', import.meta.url), 'utf8'),
    ) as {
      hooks: Record<string, unknown>;
    };
    expect(Object.keys(manifest.hooks)).not.toContain('PreToolUse');
  });

  it('states VS Code’s opposite convention and its ignored matchers', () => {
    expect(BULLET).toMatch(/exit 2 blocks/u);
    expect(BULLET).toMatch(/parses matchers and ignores them/u);
  });

  it('describes the answer this package actually implements', () => {
    // Held to the code rather than to itself: the bullet claims nothing is
    // written where no verdict was reached, and claims the exit code is the
    // guarantee. Both are checkable in `shared.ts`.
    expect(BULLET).toMatch(/nothing on every path that reaches no verdict/u);
    expect(BULLET).toMatch(/no path exits non-zero and\s+none exits 2/iu);
    expect(SOURCE).toContain('process.exit(0)');
    expect(SOURCE).not.toMatch(/process\.exit\(\s*[^0)]/u);
    // The emit is GUARDED rather than unconditional — the difference between
    // writing nothing and writing `{}`, which the host would parse.
    expect(SOURCE).toMatch(/if \(output !== undefined\) \{/u);
  });

  it('says the VS Code half is confirmed against no live install', () => {
    expect(BULLET).toMatch(/confirmed against no live install/u);
    expect(BULLET).toContain('test/fixtures/vscode-provisional/');
    // And the directory it names is really there, with the README that carries
    // the disclaimer — a bullet pointing at a path nobody created would read
    // exactly like one pointing at real evidence.
    expect(
      readFileSync(new URL('./fixtures/vscode-provisional/README.md', import.meta.url), 'utf8'),
    ).toMatch(/No live VS Code session produced any file/u);
  });
});
