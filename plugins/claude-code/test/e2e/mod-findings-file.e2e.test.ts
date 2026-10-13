/**
 * The findings file the Claude Code mod's widgets read, written by the command
 * hooks. Driven as the built hook scripts against a throwaway home: the file holds
 * one record per finding acted on, and never the value itself.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { POINTER_TOKEN_ANCHORED, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION = 'mod-findings-file-e2e';
const RULE_ID = 'secrets/github-pat';

function fixture(): { pack: ReturnType<typeof bundledDetections>[number]; token: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const token = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || token === undefined) throw new Error(`no ${RULE_ID} fixture`);
  return { pack, token };
}
const { pack: PACK, token: TOKEN } = fixture();

function env(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
}

function seed(home: string, policy: BuiltinPolicyId, consent = false): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(PACK.namespace, PACK.packId, policy);
  } finally {
    db.close();
  }
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({
      onboardedAt: '2026-01-01T00:00:00Z',
      ...(consent
        ? {
            vaultConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: VAULT_CONSENT_VERSION,
            },
          }
        : {}),
    }),
  );
}

function records(home: string): { path: string; text: string; lines: Record<string, unknown>[] } {
  const path = join(home, '.aka', 'data', 'mod-findings', `${SESSION}.jsonl`);
  const text = readFileSync(path, 'utf8');
  const lines = text
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
  return { path, text, lines };
}

function run(home: string, script: string, payload: Record<string, unknown>) {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return runHook(script, JSON.stringify({ session_id: SESSION, cwd, ...payload }), {
    env: env(home),
  });
}

describe('the hooks record the findings they act on', () => {
  it('UserPromptSubmit: a blocked prompt leaves one prompt record and not the value', () => {
    withTempHome((home) => {
      seed(home, 'block');
      run(home, 'user-prompt-submit', {
        prompt: `deploy with ${TOKEN} please`,
        hook_event_name: 'UserPromptSubmit',
      });

      const { text, lines } = records(home);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatchObject({
        ruleId: RULE_ID,
        action: 'blocked',
        where: 'prompt',
        shortName: 'GitHub token',
      });
      expect(text).not.toContain(TOKEN);
    }, 'aka-findings-file-prompt-');
  });

  it('PreToolUse: a redacted Write field leaves a tool-input record and not the value', () => {
    withTempHome((home) => {
      seed(home, 'redact');
      run(home, 'pre-tool-use', {
        tool_name: 'Write',
        tool_input: { file_path: join(home, 'project', 'a.txt'), content: `token ${TOKEN}` },
        hook_event_name: 'PreToolUse',
      });

      const { text, lines } = records(home);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatchObject({ ruleId: RULE_ID, action: 'redacted', where: 'tool-input' });
      expect(text).not.toContain(TOKEN);
    }, 'aka-findings-file-pre-');
  });

  it('PostToolUse: a redacted Bash output leaves a tool-output record and not the value', () => {
    withTempHome((home) => {
      seed(home, 'redact');
      run(home, 'post-tool-use', {
        tool_name: 'Bash',
        tool_input: { command: 'cat .env' },
        tool_response: { stdout: `GH=${TOKEN}`, stderr: '' },
        hook_event_name: 'PostToolUse',
      });

      const { text, lines } = records(home);
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatchObject({ ruleId: RULE_ID, action: 'redacted', where: 'tool-output' });
      expect(text).not.toContain(TOKEN);
    }, 'aka-findings-file-post-');
  });

  it('a clean prompt writes no file', () => {
    withTempHome((home) => {
      seed(home, 'block');
      run(home, 'user-prompt-submit', {
        prompt: 'rename this variable',
        hook_event_name: 'UserPromptSubmit',
      });
      expect(() => records(home)).toThrow();
    }, 'aka-findings-file-clean-');
  });

  describe.each([
    [
      'PreToolUse',
      'pre-tool-use',
      'tool-input',
      (home: string) => ({
        tool_name: 'Write',
        tool_input: { file_path: join(home, 'project', 'a.txt'), content: `token ${TOKEN}` },
        hook_event_name: 'PreToolUse',
      }),
    ],
    [
      'PostToolUse',
      'post-tool-use',
      'tool-output',
      () => ({
        tool_name: 'Bash',
        tool_input: { command: 'cat .env' },
        tool_response: { stdout: `GH=${TOKEN}`, stderr: '' },
        hook_event_name: 'PostToolUse',
      }),
    ],
  ])('%s under a vault policy', (_name, script, where, payload) => {
    it('with consent: the finding is vaulted and carries the pointer', () => {
      withTempHome((home) => {
        seed(home, 'vault', true);
        run(home, script, payload(home));

        const { text, lines } = records(home);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({ action: 'vaulted', where });
        expect(POINTER_TOKEN_ANCHORED.test(String(lines[0]?.pointer))).toBe(true);
        expect(text).not.toContain(TOKEN);
      }, 'aka-findings-file-vaulted-');
    });

    it('without consent: the finding is redacted and carries no pointer', () => {
      withTempHome((home) => {
        seed(home, 'vault', false);
        run(home, script, payload(home));

        const { lines } = records(home);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({ action: 'redacted', where });
        expect(lines[0]).not.toHaveProperty('pointer');
      }, 'aka-findings-file-oneway-');
    });
  });

  it('a findings file that cannot be written leaves the decision as it was', () => {
    const decide = (blockFile: boolean): string => {
      let stdout = '';
      withTempHome((home) => {
        seed(home, 'block');
        if (blockFile) writeFileSync(join(home, '.aka', 'data', 'mod-findings'), 'not a directory');
        stdout = run(home, 'user-prompt-submit', {
          prompt: `deploy with ${TOKEN} please`,
          hook_event_name: 'UserPromptSubmit',
        }).stdout;
      }, 'aka-findings-file-unwritable-');
      return stdout;
    };
    const normal = JSON.parse(decide(false)) as { decision?: string };
    const blocked = JSON.parse(decide(true)) as { decision?: string };
    expect(blocked.decision).toBe('block');
    expect(blocked.decision).toBe(normal.decision);
  });
});
