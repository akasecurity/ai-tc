import { describe, expect, it } from 'vitest';

import { SourceTool } from '../../src/zod/event.ts';
import { FindingProvider } from '../../src/zod/finding.ts';
import { toApiProvider } from '../../src/zod/findings-group-build.ts';
import { Harness, harnessFromTool, TOOL_TO_HARNESS } from '../../src/zod/harness-map.ts';

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
});
