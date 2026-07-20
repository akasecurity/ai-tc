import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const setupMd = readFileSync(new URL('../commands/setup.md', import.meta.url), 'utf8');

// The prompt-authored scan-offer copy lives in commands/setup.md, so a
// regression is otherwise only visible in the manual walkthrough. These guards
// pin the verbatim strings the wizard shows at the scan offer.
describe('setup.md scan-offer copy', () => {
  it('carries the scope disclosure verbatim', () => {
    expect(setupMd).toContain(
      "A retroactive scan of recent activity — transcripts, temp files, agent memory — tunes the notifications we'll review next.",
    );
  });

  it('carries the Yes-option subtitle verbatim', () => {
    expect(setupMd).toContain('calibrate my notifications to your real activity');
  });

  it('carries the Not-now-option subtitle verbatim', () => {
    expect(setupMd).toContain('start light and learn as we go');
  });
});
