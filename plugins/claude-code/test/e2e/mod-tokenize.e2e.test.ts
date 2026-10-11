/**
 * The prompt.submit mod's helper (scripts/mod-tokenize.js), driven as a process
 * against a throwaway store, the way the mod runs it: JSON on stdin, JSON on
 * stdout, exit 1 and silence when there is no rewrite.
 *
 * What the mod relies on, and these cases pin: a vault pointer in the grammar the
 * schema pins for a value whose detection keeps it; the one-way marker where
 * consent or the archetype says nothing may be kept; the prompt's event and
 * findings recorded exactly once, in the shape the command hook writes; and the
 * UserPromptSubmit hook, shown the rewritten prompt, recording nothing again.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { POINTER_TOKEN_ANCHORED, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { recordModHandoff } from '../../src/mod/handoff.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const RULE_ID = 'secrets/twilio-key';
const SESSION_ID = 'mod-tokenize-e2e';

function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}
const { pack: SECRET_PACK, example: SECRET } = secretFixture();
const PROMPT = `please deploy using this key: ${SECRET} and then tell me when it is done`;

function env(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
}

function seedPolicy(home: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, policy);
  } finally {
    db.close();
  }
}

function settings(home: string, vault: boolean): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({
      onboardedAt: '2026-01-01T00:00:00Z',
      ...(vault
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

function helper(home: string, text: string): ReturnType<typeof runHook> {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return runHook('mod-tokenize', JSON.stringify({ v: 1, text, sessionId: SESSION_ID, cwd }), {
    env: env(home),
  });
}

interface Answer {
  v: number;
  text: string;
  note: string | null;
}

function answerOf(run: ReturnType<typeof runHook>): Answer {
  expect(run.status).toBe(0);
  return JSON.parse(run.stdout) as Answer;
}

function rows(home: string): { events: number; findings: Record<string, unknown>[] } {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    const events = db
      .prepare(`SELECT count(*) AS n FROM audit_events WHERE event_type = 'prompt'`)
      .get() as { n: number };
    const findings = db.prepare(`SELECT * FROM inspection_findings`).all() as Record<
      string,
      unknown
    >[];
    return { events: events.n, findings };
  } finally {
    db.close();
  }
}

describe('mod-tokenize helper', () => {
  it('vault policy and consent: the value becomes a pointer in the pinned grammar, with a note', () => {
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      const run = helper(home, PROMPT);
      const answer = answerOf(run);

      expect(answer.v).toBe(1);
      expect(answer.text).not.toContain(SECRET);
      const pointer = /\[\[aka:[^\]]+\]\]/.exec(answer.text)?.[0];
      expect(pointer).toBeDefined();
      expect(POINTER_TOKEN_ANCHORED.test(pointer ?? '')).toBe(true);
      expect(answer.text).toBe(PROMPT.replace(SECRET, pointer ?? ''));
      expect(answer.note).toContain(pointer);
      expect(answer.note).toContain('Use each pointer verbatim');
      // Nothing the helper prints, on either stream, holds the raw value.
      expectNoEchoOf(run.stdout, SECRET);
      expect(run.stderr).toBe('');
    }, 'aka-mod-tokenize-vault-');
  });

  it('records the prompt once, with the finding the hook itself writes and no raw value', () => {
    // The shape is the hook's, not a copy of it: the same prompt goes through
    // the hook alone on a second home, and the two rows agree field for field
    // (ids and times differ by nature).
    const shape = (row: Record<string, unknown> | undefined): unknown =>
      Object.fromEntries(
        Object.entries(row ?? {}).filter(
          ([key]) => !['id', 'audit_event_id', 'first_detected_at'].includes(key),
        ),
      );
    let fromHook: unknown;
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: PROMPT,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );
      fromHook = shape(rows(home).findings[0]);
    }, 'aka-mod-tokenize-shape-hook-');
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      answerOf(helper(home, PROMPT));

      const { events, findings } = rows(home);
      expect(events).toBe(1);
      expect(findings).toHaveLength(1);
      expect(JSON.stringify(findings[0])).not.toContain(SECRET);
      expect(shape(findings[0])).toEqual(fromHook);
      expect((findings[0] as { action_taken: string }).action_taken).toBe('redact');
    }, 'aka-mod-tokenize-rows-');
  });

  it('the command hook shown the rewritten prompt allows it and records nothing again', () => {
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      const answer = answerOf(helper(home, PROMPT));
      const before = rows(home);

      const hook = runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: answer.text,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );

      expect(hook.status).toBe(0);
      expect(hook.stdout).toBe('');
      expect(rows(home)).toEqual(before);

      // The note is for one prompt: the same text again is an ordinary prompt.
      runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: answer.text,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );
      expect(rows(home).events).toBe(before.events + 1);
    }, 'aka-mod-tokenize-hook-');
  });

  it('a note planted for a raw prompt does not let it through: the hook still decides it', () => {
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      // What a stray or hostile writer of the data directory could leave: a note
      // naming the RAW prompt, as the helper's would name a rewritten one.
      recordModHandoff(join(home, '.aka', 'data'), PROMPT);

      const hook = runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: PROMPT,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );

      expect((JSON.parse(hook.stdout) as { decision?: string }).decision).toBe('block');
      // The note still covers the recording: it vouches for a row, not a verdict.
      expect(rows(home).events).toBe(0);
      expectNoEchoOf(hook.stderr, SECRET);
    }, 'aka-mod-tokenize-planted-');
  });

  it('a redacted prompt that keeps a warn-level value still gets the hook’s warning, unrecorded', () => {
    withTempHome((home) => {
      const email = ['user1', 'example.com'].join('@');
      const emailPack = bundledDetections().find((p) =>
        p.rules.some((r) => r.id === 'core-pii/email'),
      );
      if (emailPack === undefined) throw new Error('no pack carries core-pii/email');
      seedPolicy(home, 'redact');
      settings(home, false);
      const db = openLocalDatabase(join(home, '.aka', 'data'));
      try {
        db.installedPacks.setPolicy(emailPack.namespace, emailPack.packId, 'warn');
      } finally {
        db.close();
      }
      const prompt = `${PROMPT} and mail ${email}`;
      const answer = answerOf(helper(home, prompt));
      expect(answer.text).not.toContain(SECRET);
      expect(answer.text).toContain(email);
      const before = rows(home);

      const hook = runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: answer.text,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );

      expect(hook.status).toBe(0);
      expect((JSON.parse(hook.stdout) as { systemMessage?: string }).systemMessage).toContain(
        'AKA flagged sensitive content',
      );
      expect(rows(home)).toEqual(before);
    }, 'aka-mod-tokenize-mixed-');
  });

  it('control: without the helper the hook still blocks the raw prompt and records it', () => {
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, true);
      const hook = runHook(
        'user-prompt-submit',
        JSON.stringify({
          prompt: PROMPT,
          session_id: SESSION_ID,
          cwd: join(home, 'project'),
          hook_event_name: 'UserPromptSubmit',
        }),
        { env: env(home) },
      );
      expect((JSON.parse(hook.stdout) as { decision?: string }).decision).toBe('block');
      expect(rows(home).events).toBe(1);
    }, 'aka-mod-tokenize-control-');
  });

  it('redact policy (one-way archetype) with consent: the one-way marker and no note', () => {
    withTempHome((home) => {
      seedPolicy(home, 'redact');
      settings(home, true);
      const answer = answerOf(helper(home, PROMPT));

      expect(answer.text).toBe(PROMPT.replace(SECRET, '[REDACTED:SECRET]'));
      expect(answer.note).toBeNull();
      expect(rows(home).findings).toHaveLength(1);
    }, 'aka-mod-tokenize-oneway-');
  });

  it('vault policy without consent: the one-way marker, the vault untouched', () => {
    withTempHome((home) => {
      seedPolicy(home, 'vault');
      settings(home, false);
      const run = helper(home, PROMPT);
      const answer = answerOf(run);

      expect(answer.text).toBe(PROMPT.replace(SECRET, '[REDACTED:SECRET]'));
      expect(run.stdout).not.toContain('[[aka:');
      expect(answer.note).toBeNull();
      expect(rows(home).findings).toHaveLength(1);
    }, 'aka-mod-tokenize-noconsent-');
  });

  it('a block verdict, a clean prompt and bad input give exit 1 and nothing on stdout', () => {
    withTempHome((home) => {
      seedPolicy(home, 'block');
      settings(home, true);
      for (const run of [
        helper(home, PROMPT),
        helper(home, 'rename this variable across the module'),
        runHook('mod-tokenize', 'not json', { env: env(home) }),
        runHook('mod-tokenize', '', { env: env(home) }),
        runHook('mod-tokenize', JSON.stringify({ v: 2, text: PROMPT }), { env: env(home) }),
      ]) {
        expect(run.status).toBe(1);
        expect(run.stdout).toBe('');
        expectNoEchoOf(run.stderr, SECRET);
      }
    }, 'aka-mod-tokenize-none-');
  });

  // The helper decides first and records last. Every way it can decline, and the
  // mod's timeout killing it, must leave the store as it was: the command hook
  // then decides the raw prompt and records it, and recording here too put the
  // prompt in Activity twice.
  it.each(['block', 'monitor'] as const)(
    'a %s verdict is declined and records nothing',
    (policy) => {
      withTempHome((home) => {
        seedPolicy(home, policy);
        settings(home, true);
        const run = helper(home, PROMPT);

        expect(run.status).toBe(1);
        expect(run.stdout).toBe('');
        expect(rows(home)).toEqual({ events: 0, findings: [] });
      }, 'aka-mod-tokenize-declined-');
    },
  );

  it('the never-leak gate declines a rewrite that still holds the value, and records nothing', () => {
    // A rule that matches the value only after a label: the same value pasted bare
    // elsewhere in the text is no match, so redacting the match leaves it in.
    const awsId = 'secrets/aws-secret-key';
    const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === awsId));
    const example = pack?.rules.find((r) => r.id === awsId)?.examples?.[0];
    if (pack === undefined || example === undefined) throw new Error(`no ${awsId} fixture`);
    const value = example.slice(example.indexOf('=') + 1);
    const seedAws = (home: string): void => {
      const db = openLocalDatabase(join(home, '.aka', 'data'));
      try {
        db.installedPacks.recordInventory(bundledDetections());
        db.installedPacks.setPolicy(pack.namespace, pack.packId, 'redact');
      } finally {
        db.close();
      }
      settings(home, false);
    };

    // Control: the labelled value alone is a rewrite, and is recorded.
    withTempHome((home) => {
      seedAws(home);
      const answer = answerOf(helper(home, `use ${example} please`));
      expect(answer.text).not.toContain(value);
      expect(rows(home).events).toBe(1);
      expect(rows(home).findings.length).toBeGreaterThan(0);
    }, 'aka-mod-tokenize-leak-control-');

    withTempHome((home) => {
      seedAws(home);
      const run = helper(home, `use ${example} and also ${value} please`);

      expect(run.status).toBe(1);
      expect(run.stdout).toBe('');
      expect(rows(home)).toEqual({ events: 0, findings: [] });
    }, 'aka-mod-tokenize-leak-');
  });

  it.each(['attachment', 'tool-result'])(
    'a %s row is recorded as a response, never a prompt, with no note and no handoff',
    (door) => {
      withTempHome((home) => {
        seedPolicy(home, 'vault');
        settings(home, true);
        const cwd = join(home, 'project');
        mkdirSync(cwd, { recursive: true });
        const run = runHook(
          'mod-tokenize',
          JSON.stringify({
            v: 1,
            text: PROMPT,
            sessionId: SESSION_ID,
            cwd,
            row: { door },
          }),
          { env: env(home) },
        );
        const answer = answerOf(run);

        expect(answer.text).not.toContain(SECRET);
        expect(POINTER_TOKEN_ANCHORED.test(/\[\[aka:[^\]]+\]\]/.exec(answer.text)?.[0] ?? '')).toBe(
          true,
        );
        expect(answer.note).toBeNull();
        const { events, findings } = rows(home);
        expect(events).toBe(0);
        expect(findings).toHaveLength(1);

        // The rewritten text is not a prompt the command hook should skip.
        const hook = runHook(
          'user-prompt-submit',
          JSON.stringify({
            prompt: answer.text,
            session_id: SESSION_ID,
            cwd,
            hook_event_name: 'UserPromptSubmit',
          }),
          { env: env(home) },
        );
        expect(hook.status).toBe(0);
      }, 'aka-mod-tokenize-row-');
    },
  );
});
