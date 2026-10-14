import { SourceTool, WebSourceTool } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { sessionToolIsKeyed } from '../src/session-root-key.ts';

describe('sessionToolIsKeyed', () => {
  // Both halves of the partition, over every tool the schema names, so a tool
  // added to either vocabulary lands on one side deliberately.
  it.each(WebSourceTool.options)('refuses the %s web chat tool', (tool) => {
    expect(sessionToolIsKeyed(tool)).toBe(false);
  });

  const coding = SourceTool.options.filter((tool) => !WebSourceTool.safeParse(tool).success);

  it('has coding tools to compare against', () => {
    expect(coding.length).toBeGreaterThan(0);
  });

  it.each(coding)('accepts the %s tool', (tool) => {
    expect(sessionToolIsKeyed(tool)).toBe(true);
  });
});
