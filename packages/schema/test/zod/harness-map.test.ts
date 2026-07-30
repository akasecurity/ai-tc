import { describe, expect, it } from 'vitest';

import { SourceTool } from '../../src/zod/event.ts';
import { Harness, harnessFromTool, TOOL_TO_HARNESS } from '../../src/zod/harness-map.ts';

describe('SourceTool enum', () => {
  it('accepts claude-ai as a first-class source', () => {
    expect(SourceTool.safeParse('claude-ai').success).toBe(true);
  });
});

// TOOL_TO_HARNESS is typed Record<string, string>, so nothing forces its rows
// through the enums at compile time. These pin every member — including any
// future addition — into BOTH vocabularies: keys are the tool ids the capture
// side stamps (SourceTool), values are what the read surfaces render (Harness).
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

  it('routes claude-ai onto the claudeai harness', () => {
    expect(harnessFromTool('claude-ai')).toBe('claudeai');
  });
});
