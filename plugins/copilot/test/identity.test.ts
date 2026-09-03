import { describe, expect, it } from 'vitest';

import { PLUGIN_PACKAGE } from '../src/identity.ts';

describe('skeleton', () => {
  it('names its own package', () => {
    expect(PLUGIN_PACKAGE).toBe('@akasecurity/ai-tc-copilot');
  });
});
