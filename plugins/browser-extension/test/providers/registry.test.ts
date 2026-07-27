import { describe, expect, it } from 'vitest';

import { resolveAdapter } from '../../src/providers/registry.ts';

describe('resolveAdapter', () => {
  it('resolves chatgpt.com and the legacy chat.openai.com host to the ChatGPT adapter', () => {
    expect(resolveAdapter('chatgpt.com')?.id).toBe('chatgpt');
    expect(resolveAdapter('chat.openai.com')?.id).toBe('chatgpt');
  });

  it('resolves claude.ai to the Claude adapter', () => {
    expect(resolveAdapter('claude.ai')?.id).toBe('claude-ai');
  });

  it('returns null for a host no adapter matches', () => {
    expect(resolveAdapter('example.com')).toBeNull();
  });
});
