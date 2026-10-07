import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';

// turbo 2.11.6+ appends a managed guidance block to AGENTS.md on agent-run
// commands and tells the agent to keep it committed. `agentGuidance: false`
// stops the rewrite, but turbo's own docs say it leaves an existing block in
// place. So a branch cut before the opt-out can commit the block, and once that
// merges nothing would take it back out, and nothing would flag a later edit
// that drops the key. Both are pinned here.

const TURBO = JSON.parse(
  // Same jsonc handling as coverage-config.test.js: turbo.json uses line
  // comments only.
  readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8').replace(/^\s*\/\/.*$/gm, ''),
);

const AGENTS_MD = readFileSync(join(REPO_ROOT, 'AGENTS.md'), 'utf8');

describe("turbo's agent guidance stays off", () => {
  it('turbo.json opts out of the managed AGENTS.md block', () => {
    expect(TURBO.agentGuidance).toBe(false);
  });

  it('AGENTS.md carries no turbo-managed block', () => {
    expect(AGENTS_MD).not.toContain('turborepo-agent-rules');
  });
});
