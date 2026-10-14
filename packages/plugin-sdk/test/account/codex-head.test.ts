import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { CODEX_HEAD_MAX_BYTES, readCodexHead } from '../../src/account/codex-head.ts';
import { sessionMetaLine } from '../helpers/fake-jwt.ts';

let dir: string;
let rollout: string;
let sessionId: string;
let account: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-codex-head-'));
  rollout = join(dir, 'rollout.jsonl');
  sessionId = randomUUID();
  account = randomUUID();
});

afterEach(() => {
  removeTree(dir);
});

const NEXT_LINE = `${JSON.stringify({ type: 'event_msg', payload: { type: 'task_started' } })}\n`;

describe('readCodexHead', () => {
  it('reads the originator and the account from a 60 KB head line in one read', () => {
    writeFileSync(
      rollout,
      `${sessionMetaLine({ sessionId, creatorAccountId: account, baseInstructionsBytes: 60 * 1024 })}\n${NEXT_LINE}`,
    );
    expect(readCodexHead(rollout)).toEqual({
      sessionId,
      originator: 'codex_cli_rs',
      modelProvider: 'openai',
      creatorAccountId: account,
    });
  });

  it('reads a head line longer than one 64 KiB read', () => {
    writeFileSync(
      rollout,
      `${sessionMetaLine({ sessionId, creatorAccountId: account, baseInstructionsBytes: 200 * 1024 })}\n`,
    );
    expect(readCodexHead(rollout)).toMatchObject({ creatorAccountId: account });
  });

  it('keeps only the session id, the originator, the provider and the account id', () => {
    const line = sessionMetaLine({ sessionId, creatorAccountId: account });
    writeFileSync(rollout, `${line}\n`);
    const creatorUser = (JSON.parse(line) as { payload: { creator_user_id: string } }).payload
      .creator_user_id;
    const read = readCodexHead(rollout);
    expect(typeof read === 'object' ? Object.keys(read).sort() : []).toEqual([
      'creatorAccountId',
      'modelProvider',
      'originator',
      'sessionId',
    ]);
    expect(JSON.stringify(read)).not.toContain(creatorUser);
  });

  it('reads the session id from id when the head names no session_id', () => {
    writeFileSync(
      rollout,
      `${sessionMetaLine({ sessionId, creatorAccountId: account, idOnly: true })}\n`,
    );
    expect(readCodexHead(rollout)).toMatchObject({ sessionId });
  });

  it.each(['azure', 'ollama', null] as const)(
    'reports provider %j as the head names it',
    (provider) => {
      writeFileSync(
        rollout,
        `${sessionMetaLine({ sessionId, creatorAccountId: account, modelProvider: provider })}\n`,
      );
      expect(readCodexHead(rollout)).toMatchObject({ modelProvider: provider ?? undefined });
    },
  );

  it.each([undefined, 'not-a-uuid', 42])('has no account for creator_account_id %j', (creator) => {
    writeFileSync(rollout, `${sessionMetaLine({ sessionId, creatorAccountId: creator })}\n`);
    expect(readCodexHead(rollout)).toMatchObject({ creatorAccountId: undefined });
  });

  it('lower-cases an upper-case account id', () => {
    writeFileSync(
      rollout,
      `${sessionMetaLine({ sessionId, creatorAccountId: account.toUpperCase() })}\n`,
    );
    expect(readCodexHead(rollout)).toMatchObject({ creatorAccountId: account });
  });

  it('is pending for a missing file and for a head line still being written', () => {
    expect(readCodexHead(rollout)).toBe('pending');
    writeFileSync(rollout, sessionMetaLine({ sessionId, creatorAccountId: account }).slice(0, 200));
    expect(readCodexHead(rollout)).toBe('pending');
  });

  it('reads nothing with no newline within 1 MiB, or a first line that is not session_meta', () => {
    writeFileSync(rollout, 'x'.repeat(CODEX_HEAD_MAX_BYTES + 10));
    expect(readCodexHead(rollout)).toBeUndefined();
    writeFileSync(rollout, NEXT_LINE);
    expect(readCodexHead(rollout)).toBeUndefined();
    writeFileSync(rollout, 'not json\n');
    expect(readCodexHead(rollout)).toBeUndefined();
  });
});
