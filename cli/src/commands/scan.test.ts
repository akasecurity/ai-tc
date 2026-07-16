import type { ProjectInventoryResult } from '@akasecurity/local-ops';
import { describe, expect, it } from 'vitest';

import { renderInventoryLine } from './scan.ts';

function inv(overrides: Partial<ProjectInventoryResult> = {}): ProjectInventoryResult {
  return {
    projectId: 'p1',
    name: 'ai-tc',
    url: 'https://github.com/acme/ai-tc.git',
    fileCount: 785,
    truncated: false,
    ...overrides,
  };
}

describe('renderInventoryLine', () => {
  it('reports the recorded file count for a full walk', () => {
    expect(renderInventoryLine(inv())).toBe('Inventory: ai-tc · 785 project file(s) recorded');
  });

  it('marks a truncated walk as partial', () => {
    expect(renderInventoryLine(inv({ fileCount: 20_000, truncated: true }))).toBe(
      'Inventory: ai-tc · 20000 project file(s) recorded (partial walk)',
    );
  });

  it('says the tree is unchanged when the walk recorded nothing', () => {
    expect(renderInventoryLine(inv({ fileCount: 0 }))).toBe(
      'Inventory: ai-tc · file tree unchanged',
    );
  });
});
