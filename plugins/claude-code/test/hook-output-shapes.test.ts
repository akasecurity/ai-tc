/**
 * CLAUDE.md §1 enumerates the shapes `emit()` may write to stdout. That
 * enumeration drifted once already — it said four while six were reaching the
 * wire, and the two it omitted (`MessageDisplay`, `SessionStart`) were the two
 * hooks the section never names, so nothing about the sentence looked wrong.
 *
 * The drift was possible because `emit` took `unknown`: a new shape reached
 * stdout without passing anything that could be counted. It now takes the
 * `HookOutput` union, which makes the chain checkable end to end:
 *
 *   call site → union     the compiler, via `emit`'s parameter type
 *   union → this map      the compile-time pins below
 *   this map → the doc    the assertions below
 *
 * Each link is enforced by something, so a seventh shape cannot land quietly at
 * any of them. What none of it covers is a hook that writes to stdout WITHOUT
 * going through `emit` — that is `fail-open.e2e.test.ts`'s ground, which reads
 * what the built scripts really print.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { emit, HookOutput } from '../src/hooks/shared.ts';

// plugins/claude-code/test -> the repo root
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CONVENTIONS_DOC = 'CLAUDE.md';
const SECTION_HEADING = '### 1. Fail-open everywhere in the plugin';

/** The shapes that sit at the top level of the emitted object. */
const TOP_LEVEL_SHAPES = ['decision', 'systemMessage'] as const;

/**
 * One `hookSpecificOutput` variant per hook, mapped to the field that carries
 * its opinion — which is how the doc names each one, and the only part of the
 * variant a reader needs to tell them apart. `hookEventName` is the
 * discriminant, not the shape.
 */
const SHAPE_FIELD_BY_EVENT = {
  PreToolUse: 'permissionDecision',
  PostToolUse: 'updatedToolOutput',
  MessageDisplay: 'displayContent',
  SessionStart: 'additionalContext',
} as const;

// ---------------------------------------------------------------------------
// The compile-time half — `pnpm typecheck` covers test/, so these are gates
// ---------------------------------------------------------------------------

type EmittedEventName = Extract<
  HookOutput,
  { hookSpecificOutput: { hookEventName: string } }
>['hookSpecificOutput']['hookEventName'];

// Both directions, because they fail differently. A variant added to the union
// and not to the map is a shape nothing counts (the drift that happened); a map
// entry whose variant is gone is an expectation outliving what it described,
// which leaves the doc naming a shape no hook can emit.
type EveryVariantNamed = [EmittedEventName] extends [keyof typeof SHAPE_FIELD_BY_EVENT]
  ? true
  : never;
type EveryNameEmitted = [keyof typeof SHAPE_FIELD_BY_EVENT] extends [EmittedEventName]
  ? true
  : never;

// And that `emit` still narrows at all: were its parameter widened back to
// `unknown`, this stops being assignable and the union above becomes decoration
// that the compiler no longer enforces at a single call site.
type EmitNarrowsToHookOutput = [Parameters<typeof emit>[0]] extends [HookOutput] ? true : never;

const everyVariantNamed: EveryVariantNamed = true;
const everyNameEmitted: EveryNameEmitted = true;
const emitNarrows: EmitNarrowsToHookOutput = true;

// ---------------------------------------------------------------------------
// Reading the sentence
// ---------------------------------------------------------------------------

// Written out rather than derived from Intl: the doc spells the count in prose,
// and a locale-dependent list would make this expectation depend on the runner.
const CARDINALS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];

/** The text under `heading`, to the next heading of the same or a higher level. */
function sectionOf(md: string, heading: string): string {
  const lines = md.split('\n');
  const at = lines.flatMap((line, i) => (line === heading ? [i] : []));
  const [start, ...extra] = at;
  if (start === undefined || extra.length > 0) {
    throw new Error(
      `${CONVENTIONS_DOC}: expected exactly one ${JSON.stringify(heading)} heading, found ` +
        `${String(at.length)}. A guard slicing on a non-unique anchor reads the wrong section.`,
    );
  }
  const level = /^#+/.exec(heading)?.[0].length ?? 0;
  const boundary = new RegExp(`^#{1,${String(level)}} `);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => boundary.test(line));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

/**
 * The count word and body of the one "Its <n> shapes are …" sentence.
 *
 * Throws unless it occurs exactly once. A reworded sentence this cannot find is
 * a guard that would otherwise assert nothing and pass — the same failure the
 * enumeration itself had, one level up.
 */
function shapesSentence(section: string): { count: string; body: string } {
  // `\s+` around the wrapping, not a literal space: the doc is hard-wrapped, so
  // any of these gaps can be a newline on the next reflow.
  const found = [...section.matchAll(/Its\s+(\w+)\s+shapes\s+are\s+([\s\S]*?)\.\s/gu)];
  const [match, ...extra] = found;
  const count = match?.[1];
  const body = match?.[2];
  if (count === undefined || body === undefined || extra.length > 0) {
    throw new Error(
      `${CONVENTIONS_DOC} §1: expected exactly one "Its <n> shapes are …" sentence, found ` +
        `${String(found.length)}. It was reworded, removed or duplicated, and this guard cannot ` +
        'read what it is meant to be asserting.',
    );
  }
  return { count: count.toLowerCase(), body };
}

/** The backticked code spans in `text`, in order. */
const codeSpansOf = (text: string): string[] =>
  [...text.matchAll(/`([^`]+)`/gu)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]));

const SECTION = sectionOf(readFileSync(join(REPO_ROOT, CONVENTIONS_DOC), 'utf8'), SECTION_HEADING);
const SENTENCE = shapesSentence(SECTION);

const EVENTS = Object.entries(SHAPE_FIELD_BY_EVENT);
const SHAPE_COUNT = TOP_LEVEL_SHAPES.length + EVENTS.length;

describe(`${CONVENTIONS_DOC} §1's emit() shape enumeration`, () => {
  it('is pinned to the union at compile time', () => {
    // These are `true` only because the conditional types above resolved to
    // `true`; had either resolved to `never`, `pnpm typecheck` would already
    // have failed and this file would not run. Asserting them here is what
    // stops them being unused declarations someone deletes as dead weight.
    expect([everyVariantNamed, everyNameEmitted, emitNarrows]).toEqual([true, true, true]);
  });

  it('reads a sentence that is really there', () => {
    // Every assertion below is about a set parsed out of prose, and all of them
    // pass on the empty set. This separates "the doc says nothing" from "the doc
    // agrees".
    expect(SECTION.length, 'the fail-open section is empty').toBeGreaterThan(0);
    expect(SENTENCE.body.length, 'the shapes sentence has no body').toBeGreaterThan(0);
    expect(SHAPE_COUNT, 'no shapes derived from the union').toBeGreaterThan(0);
  });

  it('states the number of shapes the union carries', () => {
    const word = CARDINALS[SHAPE_COUNT];
    expect(word, `no cardinal word for ${String(SHAPE_COUNT)} — extend CARDINALS`).toBeDefined();
    expect(SENTENCE.count).toBe(word);
  });

  it('names every shape, and no others', () => {
    // A set rather than a sequence: the doc is free to reorder or reword around
    // them. What it is not free to do is drop one, or name one that no variant
    // of the union carries.
    const expected = [
      ...TOP_LEVEL_SHAPES,
      'hookSpecificOutput',
      ...EVENTS.flatMap(([event, field]) => [event, field]),
    ].sort();
    expect([...new Set(codeSpansOf(SENTENCE.body))].sort()).toEqual([...new Set(expected)].sort());
  });

  it('pairs each hook with the field that distinguishes it', () => {
    // The set check above passes on a sentence that lists all ten spans in a
    // heap. This is the substantive claim: `MessageDisplay`'s field is
    // `displayContent` and not `updatedToolOutput`, which a reader acts on.
    // Whitespace-normalised first: the doc is hard-wrapped, so a pair can sit
    // either side of a newline and does today.
    const flat = SENTENCE.body.replace(/\s+/gu, ' ');
    const unpaired = EVENTS.filter(
      ([event, field]) => !flat.includes(`\`${event}\`'s \`${field}\``),
    ).map(([event, field]) => `${event} is not paired with ${field}`);
    expect(unpaired).toEqual([]);
  });
});
