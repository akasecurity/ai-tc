import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { workSubscriptionsOn } from '../../src/zod/agent-scope.ts';
import {
  AttachmentScope,
  AttachmentScopeEntry,
  parseAttachmentScope,
  resolveScope,
  scopeVerdict,
  WorkspaceSettings,
} from '../../src/zod/local.ts';

// The work-subscription opt-out on the scope record, and the coding-agents
// marker on an account entry. Absent means on, as on every record written before
// the field; any value present reads as off and never costs the record its
// entries.
const ENDPOINT = 'https://plane.example.org';
const ISO = '2026-10-14T09:00:00.000Z';
const WORK = 'github.com/acme/payments-api';
const ACCOUNT = 'claude:2ef4cd3c-c23c-473a-96be-1275cfc79103';
const REPO = { kind: 'repo', identity: WORK, enrolledAt: ISO } as const;
const MARKED = { kind: 'account', identity: ACCOUNT, enrolledAt: ISO, codingAgents: true } as const;
const record = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  endpoint: ENDPOINT,
  entries: [REPO],
  ...over,
});

// The two shapes as a build from before these fields reads them.
const OlderEntry = AttachmentScopeEntry.omit({ codingAgents: true });
const OlderScope = AttachmentScope.omit({ workSubscriptions: true }).extend({
  entries: z.array(OlderEntry),
});

const UNKNOWN_VALUES = [
  ['on', 'on'],
  ['a number', 42],
  ['true', true],
  ['null', null],
  ['an empty string', ''],
  ['an object', {}],
] as const;

describe('workSubscriptionsOn', () => {
  it('an attachment made before this build is on', () => {
    expect(workSubscriptionsOn(record())).toBe(true);
    expect(workSubscriptionsOn(undefined)).toBe(true);
  });

  it('is off once the user turned it off', () => {
    expect(workSubscriptionsOn(record({ workSubscriptions: 'off' }))).toBe(false);
  });

  it.each(UNKNOWN_VALUES)('an unknown value reads as off: %s', (_label, value) => {
    expect(workSubscriptionsOn(record({ workSubscriptions: value }))).toBe(false);
  });

  it('keeps an opt-out on a record this build cannot otherwise read', () => {
    const unreadable = record({ tenantName: 't'.repeat(201), workSubscriptions: 'off' });
    expect(parseAttachmentScope(unreadable)).toBeUndefined();
    expect(workSubscriptionsOn(unreadable)).toBe(false);
  });

  it.each([
    ['a string', 'scoped'],
    ['null', null],
    ['a list', []],
  ] as const)('reads a stored value that is not a record as off: %s', (_label, value) => {
    expect(workSubscriptionsOn(value)).toBe(false);
  });

  it('never throws, even on a record whose field throws when read', () => {
    const hostile = {
      endpoint: ENDPOINT,
      entries: [],
      get workSubscriptions(): string {
        throw new Error('unreadable');
      },
    };
    expect(workSubscriptionsOn(hostile)).toBe(false);
  });
});

describe('AttachmentScope.workSubscriptions', () => {
  it('is absent from a record that carries none, as a build before it wrote', () => {
    expect(parseAttachmentScope(record())).toStrictEqual({ endpoint: ENDPOINT, entries: [REPO] });
  });

  it('reads off as off', () => {
    expect(parseAttachmentScope(record({ workSubscriptions: 'off' }))).toStrictEqual({
      endpoint: ENDPOINT,
      workSubscriptions: 'off',
      entries: [REPO],
    });
  });

  it.each(UNKNOWN_VALUES)(
    'enrolled repositories still forward when it holds %s',
    (_label, value) => {
      const raw = record({ workSubscriptions: value });
      expect(parseAttachmentScope(raw)).toStrictEqual({
        endpoint: ENDPOINT,
        workSubscriptions: 'off',
        entries: [REPO],
      });
      const resolved = resolveScope({ mode: 'scoped', scope: raw, endpoint: ENDPOINT });
      expect(scopeVerdict(resolved, WORK)).toBe('forward');
    },
  );

  it('passes through the settings schema exactly as stored', () => {
    const raw = record({ workSubscriptions: 'paused' });
    expect(WorkspaceSettings.parse({ attachmentScope: raw }).attachmentScope).toBe(raw);
  });
});

describe('AttachmentScopeEntry.codingAgents', () => {
  it('reads a marked account entry with its marker', () => {
    expect(parseAttachmentScope(record({ entries: [REPO, MARKED] }))?.entries).toStrictEqual([
      REPO,
      MARKED,
    ]);
  });

  it('reads an entry with no marker as before, adding none', () => {
    const unmarked = { kind: 'account', identity: ACCOUNT, enrolledAt: ISO };
    const [entry] = parseAttachmentScope(record({ entries: [unmarked] }))?.entries ?? [];
    expect(entry).toStrictEqual(unmarked);
    expect(entry).not.toHaveProperty('codingAgents');
  });

  it.each([
    ['false', false],
    ['a string', 'yes'],
  ] as const)('fails only the entry whose marker is %s', (_label, value) => {
    const raw = record({ entries: [REPO, { ...MARKED, codingAgents: value }] });
    expect(parseAttachmentScope(raw)?.entries).toStrictEqual([REPO]);
  });
});

describe('a build from before these fields', () => {
  it('strips both from what it reads, so a marked entry covers web chats only there', () => {
    const older = OlderScope.parse(record({ workSubscriptions: 'off', entries: [REPO, MARKED] }));
    expect(older).not.toHaveProperty('workSubscriptions');
    expect(older.entries).toStrictEqual([
      REPO,
      { kind: 'account', identity: ACCOUNT, enrolledAt: ISO },
    ]);
  });
});
