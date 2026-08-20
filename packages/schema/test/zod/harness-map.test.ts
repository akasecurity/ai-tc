import { describe, expect, it } from 'vitest';

import { FindingProvider } from '../../src/zod/finding.ts';
import { toApiProvider, toDbProviderFilter } from '../../src/zod/findings-group-build.ts';
import {
  HARNESS,
  Harness,
  harnessFromTool,
  SOURCE_TOOL,
  SourceTool,
  TOOL_TO_HARNESS,
} from '../../src/zod/harness-map.ts';

describe('SourceTool enum', () => {
  it('accepts claude-ai as a first-class source', () => {
    expect(SourceTool.safeParse('claude-ai').success).toBe(true);
  });
});

// TOOL_TO_HARNESS is typed `Record<string, Harness & FindingProvider>`, so a row
// landing in only one vocabulary is already a compile error. These pin the same
// invariant at runtime, so widening the type or reintroducing a cast still fails
// here: keys are the tool ids the capture side stamps (SourceTool), values are
// what BOTH read surfaces render — Activity via `Harness`, findings via
// `FindingProvider`. `Harness` carries ids `FindingProvider` does not
// ('windsurf'), and `toApiProvider` returns the mapped value unchecked.
describe('TOOL_TO_HARNESS', () => {
  it('keys only valid SourceTool ids', () => {
    for (const tool of Object.keys(TOOL_TO_HARNESS)) {
      expect(SourceTool.safeParse(tool).success).toBe(true);
    }
  });

  it('maps onto valid Harness ids only', () => {
    for (const harness of Object.values(TOOL_TO_HARNESS)) {
      expect(Harness.safeParse(harness).success).toBe(true);
    }
  });

  it('maps onto valid FindingProvider ids only', () => {
    for (const harness of Object.values(TOOL_TO_HARNESS)) {
      expect(FindingProvider.safeParse(harness).success).toBe(true);
    }
  });

  it('routes every mapped tool through toApiProvider onto a FindingProvider', () => {
    for (const tool of Object.keys(TOOL_TO_HARNESS)) {
      expect(FindingProvider.safeParse(toApiProvider(tool)).success).toBe(true);
    }
  });

  it('routes claude-ai onto the claudeai harness', () => {
    expect(harnessFromTool('claude-ai')).toBe('claudeai');
  });

  // The miss path is not shared: harnessFromTool passes an unmapped id through
  // (the read side coalesces it to 'claudecode'), toApiProvider answers 'api'.
  it('answers an unmapped tool differently on each side', () => {
    expect(harnessFromTool('not-a-tool')).toBe('not-a-tool');
    expect(toApiProvider('not-a-tool')).toBe('api');
  });

  // The join rule the registry rests on: the two vocabularies are paired by
  // MEMBER NAME, so the table must be exactly the intersection of the two
  // member-name sets — no more (a row for a tool with no harness to render)
  // and no less (a shared member nobody wired up, which reads as an
  // uninstrumented tool on both surfaces).
  it('pairs exactly the member names both vocabularies carry', () => {
    const shared = Object.keys(SOURCE_TOOL).filter((name) => name in HARNESS);
    const expected = Object.fromEntries(
      shared.map((name) => [
        SOURCE_TOOL[name as keyof typeof SOURCE_TOOL],
        HARNESS[name as keyof typeof HARNESS],
      ]),
    );
    expect(TOOL_TO_HARNESS).toEqual(expected);
  });

  it('leaves a member only one vocabulary carries out of the table', () => {
    // Tool-only: a capture with no harness to render.
    expect(TOOL_TO_HARNESS[SOURCE_TOOL.Cli]).toBeUndefined();
    expect(TOOL_TO_HARNESS[SOURCE_TOOL.Unknown]).toBeUndefined();
    // Harness-only: rendered, but nothing captures under it.
    expect(Object.values(TOOL_TO_HARNESS)).not.toContain(HARNESS.Windsurf);
    expect(Object.values(TOOL_TO_HARNESS)).not.toContain(HARNESS.Api);
  });
});

// toDbProviderFilter is derived as the INVERSE of the table toApiProvider reads
// forward. These pin the round trip in both directions, which is what the
// hand-written second map had nothing checking.
describe('toDbProviderFilter', () => {
  it('round-trips every mapped tool back to the provider it came from', () => {
    for (const tool of Object.keys(TOOL_TO_HARNESS)) {
      expect(toDbProviderFilter(toApiProvider(tool))).toContain(tool);
    }
  });

  it('returns only tools that map forward to the provider asked for', () => {
    for (const provider of FindingProvider.options) {
      for (const tool of toDbProviderFilter(provider)) {
        expect(toApiProvider(tool)).toBe(provider);
      }
    }
  });

  it('keeps claudecode and claudedesktop separate', () => {
    expect(toDbProviderFilter(HARNESS.ClaudeCode)).toEqual([SOURCE_TOOL.ClaudeCode]);
    expect(toDbProviderFilter(HARNESS.ClaudeDesktop)).toEqual([SOURCE_TOOL.ClaudeDesktop]);
  });

  // 'api' is the miss bucket — it names no stored value, so it must come back
  // empty rather than matching some tool by accident.
  it('gives the miss bucket no rows of its own', () => {
    expect(toDbProviderFilter(HARNESS.Api)).toEqual([]);
  });

  // The two loops above cannot see a provider with NO rows: the round-trip
  // iterates the table itself, and the forward check's inner loop never runs
  // on an empty array, so both pass vacuously on exactly the case that breaks
  // a caller. Deriving the filter gave up the exhaustiveness the hand-written
  // `Record<FindingProvider, string[]>` had — a member added to the enum no
  // longer fails to compile here — so the agreement is asserted as SETS
  // instead: every provider but the miss bucket must name at least one stored
  // value. An empty array is indistinguishable from 'api''s, which the
  // contract defines as "matches any unknown value, applied in-memory", so a
  // rowless provider does not read as "no findings" but as the miss bucket —
  // a silently-wrong findings page rather than an empty one.
  it('gives every provider but the miss bucket at least one stored value', () => {
    const covered = new Set(Object.values(TOOL_TO_HARNESS));
    const rowless = FindingProvider.options
      .filter((provider) => provider !== HARNESS.Api)
      .filter((provider) => !covered.has(provider));
    expect(rowless).toEqual([]);
  });
});
