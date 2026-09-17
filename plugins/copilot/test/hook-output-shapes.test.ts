/**
 * `emit` takes the `HookOutput` union rather than `unknown`, so a shape neither
 * host understands cannot reach the wire at all. That matters more here than on
 * the fail-open siblings: an object the Copilot CLI cannot parse is, on
 * `preToolUse`, a DENY.
 *
 * This package spans TWO hosts, which is the thing that makes a narrowed union
 * genuinely load-bearing rather than tidy. The two output vocabularies are
 * near-misses of each other — both spell the word `permissionDecision`, one at
 * the top level and one nested under `hookSpecificOutput` — so a variant built
 * for the wrong host is syntactically plausible, silently ignored by the host
 * that receives it, and invisible in review. The map below pairs each variant
 * with the dialect it belongs to, and the compile pins keep the map and the
 * union in step in both directions:
 *
 *   call site → union     the compiler, via `emit`'s parameter type
 *   union → this map      the compile-time pins below
 *   this map → behaviour  the runtime assertions below, which drive the real
 *                         builders rather than restating their output
 *
 * What none of it covers is a hook that writes to stdout WITHOUT going through
 * `emit`. That is the built-script e2e's ground.
 */
import { describe, expect, it } from 'vitest';

import type { Dialect } from '../src/hooks/dialect.ts';
import { denyOutput, rewriteOutput } from '../src/hooks/pre-tool-use-decision.ts';
import type {
  CliModifiedArgsOutput,
  CliModifiedResultOutput,
  CliPermissionOutput,
  emit,
  HookOutput,
  SystemMessageOutput,
  VsCodeBlockOutput,
  VsCodePermissionOutput,
  VsCodeUpdatedInputOutput,
} from '../src/hooks/shared.ts';
import { allowPayload } from '../src/hooks/shared.ts';

/**
 * Every variant of `HookOutput`, paired with the dialect whose host reads it
 * and the key that distinguishes it from its near-miss twin.
 *
 * `shared` is the one row belonging to neither host exclusively: a bare
 * `systemMessage` is a note with no decision attached and is valid on both.
 */
const VARIANTS = {
  CliPermissionOutput: { dialect: 'cli', key: 'permissionDecision' },
  CliModifiedArgsOutput: { dialect: 'cli', key: 'modifiedArgs' },
  CliModifiedResultOutput: { dialect: 'cli', key: 'modifiedResult' },
  VsCodePermissionOutput: { dialect: 'vscode', key: 'hookSpecificOutput' },
  VsCodeUpdatedInputOutput: { dialect: 'vscode', key: 'hookSpecificOutput' },
  VsCodeBlockOutput: { dialect: 'vscode', key: 'decision' },
  SystemMessageOutput: { dialect: 'shared', key: 'systemMessage' },
} as const satisfies Record<string, { dialect: Dialect | 'shared'; key: string }>;

// ---------------------------------------------------------------------------
// The compile-time half — `pnpm typecheck` covers test/, so these are gates
// ---------------------------------------------------------------------------

// The union, re-assembled from the map's own keys. Written as an explicit
// lookup rather than derived from `HookOutput` itself, because deriving both
// sides from the same expression is how a two-direction pin becomes a tautology.
interface VariantTypes {
  CliPermissionOutput: CliPermissionOutput;
  CliModifiedArgsOutput: CliModifiedArgsOutput;
  CliModifiedResultOutput: CliModifiedResultOutput;
  VsCodePermissionOutput: VsCodePermissionOutput;
  VsCodeUpdatedInputOutput: VsCodeUpdatedInputOutput;
  VsCodeBlockOutput: VsCodeBlockOutput;
  SystemMessageOutput: SystemMessageOutput;
}
type NamedVariants = VariantTypes[keyof typeof VARIANTS];

// Both directions, because they fail differently. A variant added to the union
// and not to the map is a shape nothing counts; a map entry whose variant is
// gone is an expectation outliving what it described.
type EveryVariantNamed = [HookOutput] extends [NamedVariants] ? true : never;
type EveryNameEmitted = [NamedVariants] extends [HookOutput] ? true : never;

// And that `emit` still narrows at all: were its parameter widened back to
// `unknown`, this stops being assignable and the union above becomes decoration
// the compiler no longer enforces at a single call site.
type EmitNarrowsToHookOutput = [Parameters<typeof emit>[0]] extends [HookOutput] ? true : never;

// Every key of the map must name a real type in `VariantTypes`, so a row cannot
// be added to the map alone.
type EveryRowTyped = [keyof typeof VARIANTS] extends [keyof VariantTypes] ? true : never;

const everyVariantNamed: EveryVariantNamed = true;
const everyNameEmitted: EveryNameEmitted = true;
const emitNarrows: EmitNarrowsToHookOutput = true;
const everyRowTyped: EveryRowTyped = true;

// ---------------------------------------------------------------------------
// The runtime half — the builders really do produce the shape the map claims
// ---------------------------------------------------------------------------

describe('the emit union', () => {
  it('holds the compile-time pins', () => {
    // The four `const` declarations above are the assertion; this case exists
    // so they are referenced (and so a reader running one test file sees them).
    expect([everyVariantNamed, everyNameEmitted, emitNarrows, everyRowTyped]).toEqual([
      true,
      true,
      true,
      true,
    ]);
  });

  it('carries a variant for each of the two hosts plus one shared', () => {
    const dialects = Object.values(VARIANTS).map((v) => v.dialect);
    expect(dialects).toContain('cli');
    expect(dialects).toContain('vscode');
    expect(dialects).toContain('shared');
  });
});

describe('the builders emit the dialect they were asked for, and never the other', () => {
  // Driven through the REAL builders rather than object literals. A literal
  // asserts that a shape the test wrote has the keys the test expected, which
  // is true by construction and stays true however the builders change.
  it('denies with the CLI shape on cli and the nested shape on vscode', () => {
    const cli = denyOutput('cli', 'because');
    expect(cli).toEqual({ permissionDecision: 'deny', permissionDecisionReason: 'because' });
    expect(cli).not.toHaveProperty('hookSpecificOutput');

    const vscode = denyOutput('vscode', 'because');
    expect(vscode).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: 'because',
      },
    });
    // The near-miss that makes this worth pinning: both shapes spell the same
    // word, and a VS Code payload carrying it at the TOP level is ignored by
    // that host rather than rejected by it.
    expect(vscode).not.toHaveProperty('permissionDecision');
  });

  it('rewrites with modifiedArgs on cli and updatedInput on vscode', () => {
    const updated = { command: 'echo ***' };
    const cli = rewriteOutput('cli', updated, 'note');
    expect(cli).toEqual({ modifiedArgs: updated });
    // The CLI has no systemMessage channel on this event, so the note is
    // dropped rather than attached to a key the host will not read.
    expect(cli).not.toHaveProperty('systemMessage');

    const vscode = rewriteOutput('vscode', updated, 'note');
    expect(vscode).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: updated,
      },
      systemMessage: 'note',
    });
  });

  it('passes the WHOLE argument object, never a diff', () => {
    // Both hosts replace the call's arguments with what is handed over — VS
    // Code additionally validates it against the tool's own input schema, which
    // a partial object would fail. So an untouched sibling key has to survive.
    const updated = { command: 'echo ***', description: 'left alone', mode: 'sync' };
    expect(rewriteOutput('cli', updated, 'n')).toEqual({ modifiedArgs: updated });
    const vscode = rewriteOutput('vscode', updated, 'n') as VsCodeUpdatedInputOutput;
    expect(vscode.hookSpecificOutput.updatedInput).toEqual(updated);
  });

  it('never emits exit-2’s shape, or any allow-with-reason on vscode', () => {
    // No path in this package exits 2 (VS Code's block channel) and none emits
    // an `ask`, which the CLI resolves to a denial in non-interactive mode.
    const everything: HookOutput[] = [
      allowPayload('cli'),
      allowPayload('vscode'),
      denyOutput('cli', 'r'),
      denyOutput('vscode', 'r'),
      rewriteOutput('cli', {}, 'n'),
      rewriteOutput('vscode', {}, 'n'),
    ];
    for (const output of everything) {
      expect(JSON.stringify(output)).not.toContain('"ask"');
    }
  });
});
