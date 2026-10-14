import { expect, mock, test } from 'claude-code/testing';

import { helper } from './harness.js';
import type { Hooks, HelperRequest } from './harness.js';

// The screen half of the mod: ui.render on the message rows, with the aka helper
// (scripts/mod-reveal.js) answered from beneath, on both surfaces that draw mods.

const SURFACES = ['terminal', 'desktop'] as const;
type Surface = (typeof SURFACES)[number];
type Row = 'AssistantMessage' | 'UserMessage';

// Spelled by joining so no pointer-shaped literal sits in the source. A pointer
// in the pinned grammar: [[aka:<category>:<key version>.<26 chars>.<16 chars>]]
function pointer(n: number): string {
  return ['[[aka:secret:', 'AB.', 'A'.repeat(25), 'CDEF'[n] ?? 'G', '.', 'B'.repeat(16), ']]'].join(
    '',
  );
}
const badge = (n: number): string => `[scrubbed:secret/test s…${String(n)}]`;
const value = (n: number): string => `VALUE-${String(n)} [scrubbed:secret]`;
// The pointer's last id character says which of the test's pointers it is.
const index = (token: string): number => 'CDEF'.indexOf(token.split('.')[1]?.slice(-1) ?? '');

// The helper as the process answers: a badge for every pointer, and a value for
// one it was asked to reveal when the mode is full.
function answering(on: Hooks, mode: 'full' | 'masked' | 'off'): HelperRequest[] {
  return helper(on, (request) => {
    const items = (request.stdin as unknown as { items: { token: string; reveal: boolean }[] })
      .items;
    return JSON.stringify({
      v: 1,
      mode,
      items:
        mode === 'off'
          ? []
          : items.map(({ token, reveal }) => ({
              token,
              badge: badge(index(token)),
              revealed: mode === 'full' && reveal ? value(index(token)) : null,
            })),
    });
  });
}

// The engine's own row, beneath the plugin: it draws the text it is handed, so
// what the test reads back is what the plugin made of it.
function engineRow(on: Hooks): void {
  on('ui.render', (_$, e) => ({
    type: 'Box',
    props: { key: 'shown' },
    children: [
      { type: 'Text', props: {}, children: [(e.props as unknown as { text: string }).text] },
    ],
  }));
}

function props(row: Row, text: string, isFirstOfReply = true) {
  return row === 'AssistantMessage'
    ? { text, isFirstOfReply }
    : { text, origin: { kind: 'user' as const }, isExpanded: true };
}

async function mountRow(
  $: Parameters<Parameters<typeof test>[1]>[0],
  surface: Surface,
  row: Row,
  text: string,
  isFirstOfReply = true,
) {
  return $.ui.mount({
    plugin: 'aka',
    surface,
    component: row,
    props: props(row, text, isFirstOfReply) as never,
  } as never) as unknown as Mounted;
}

interface Mounted {
  find(query: { key: string }): Promise<{ text: string } | undefined>;
  redraw(props?: unknown): Promise<void>;
}

async function shown(ui: Mounted): Promise<string | undefined> {
  return (await ui.find({ key: 'shown' }))?.text;
}

for (const surface of SURFACES) {
  for (const row of ['AssistantMessage', 'UserMessage'] as const) {
    test(`${surface} ${row}: a complete pointer is drawn as its value, once the helper answered`, async ($, on) => {
      const clock = mock.clock(on);
      engineRow(on);
      const asked = answering(on, 'full');

      const ui = await mountRow($, surface, row, `key ${pointer(0)} end`);
      await clock.settle();

      expect(await shown(ui)).toBe(`key ${value(0)} end`);
      expect(asked).toHaveLength(1);
      expect(asked[0]?.stdin).toMatchObject({ v: 1, items: [{ token: pointer(0), reveal: true }] });
      expect(asked[0]?.argv[1]).toMatch(/[\\/]scripts[\\/]mod-reveal\.js$/);
    });
  }

  test(`${surface}: a revealed value is never written to $.state, which any plugin can read`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    answering(on, 'full');
    // Every write to the host's state, as a plugin hooking state.set would see it.
    const written: string[] = [];
    on('state.set', (_$, e, next) => {
      written.push(JSON.stringify(e));
      return next(e);
    });

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(0)} end`);
    await clock.settle();
    expect(await shown(ui)).toBe(`key ${value(0)} end`);

    expect(written.length).toBeGreaterThan(0);
    const all = written.join('\n');
    expect(all).not.toContain('VALUE-0');
    expect(all).not.toContain('scrubbed');
  });

  test(`${surface}: masked mode draws the badge, never a value`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    answering(on, 'masked');

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(1)} end`);
    await clock.settle();

    expect(await shown(ui)).toBe(`key ${badge(1)} end`);
  });

  test(`${surface}: reveal off leaves the pointer as written`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'off');

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(0)} end`);
    await clock.settle();
    await ui.redraw();
    await clock.settle();

    expect(await shown(ui)).toBe(`key ${pointer(0)} end`);
    expect(asked).toHaveLength(1);
  });

  test(`${surface}: a trailing partial pointer is left alone and nothing is spawned for it`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');
    const partial = pointer(0).slice(0, 30);

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${partial}`);
    await clock.settle();

    expect(await shown(ui)).toBe(`key ${partial}`);
    expect(asked).toHaveLength(0);
  });

  test(`${surface}: a partial pointer grows into a complete one and is then drawn`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');
    const whole = pointer(0);

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${whole.slice(0, 40)}`);
    expect(await shown(ui)).toBe(`key ${whole.slice(0, 40)}`);
    await ui.redraw({ text: `key ${whole}`, isFirstOfReply: true });
    await clock.settle();

    expect(await shown(ui)).toBe(`key ${value(0)}`);
    expect(asked).toHaveLength(1);
  });

  test(`${surface}: garbled pointers stay plain text`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');
    const good = pointer(0);
    const garbled = [
      good.slice(0, -2) + ']', // one closing bracket
      good.replace('secret', 'nonsense'), // unknown category
      good.replace('AB.', 'ab.'), // not base32
      good.replace('.' + 'B'.repeat(16), '.' + 'B'.repeat(15)), // short tag
    ];

    const ui = await mountRow($, surface, 'AssistantMessage', garbled.join(' | '));
    await clock.settle();

    expect(await shown(ui)).toBe(garbled.join(' | '));
    expect(asked).toHaveLength(0);
  });

  test(`${surface}: many redraws cost one helper run per distinct pointer`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');

    const ui = await mountRow($, surface, 'AssistantMessage', `a ${pointer(0)}`);
    await clock.settle();
    for (let i = 0; i < 12; i += 1) {
      await ui.redraw({ text: `a ${pointer(0)} ${'x'.repeat(i)}`, isFirstOfReply: true });
    }
    expect(asked).toHaveLength(1);

    await ui.redraw({ text: `a ${pointer(0)} b ${pointer(1)}`, isFirstOfReply: true });
    await clock.settle();
    for (let i = 0; i < 12; i += 1) {
      await ui.redraw({
        text: `a ${pointer(0)} b ${pointer(1)} ${'y'.repeat(i)}`,
        isFirstOfReply: true,
      });
    }

    expect(asked).toHaveLength(2);
    expect(await shown(ui)).toBe(`a ${value(0)} b ${value(1)} ${'y'.repeat(11)}`);
  });

  test(`${surface}: redraws while the helper is still running do not start another`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    let runs = 0;
    on('session.id', () => ({ value: 'session-1' }));
    on('process.run', async () => {
      runs += 1;
      await clock.sleep(500);
      return {
        value: {
          exitCode: 0,
          stdout: JSON.stringify({
            v: 1,
            mode: 'full',
            items: [{ token: pointer(0), badge: badge(0), revealed: value(0) }],
          }),
          stderr: '',
          isStdoutTruncated: false,
          isStderrTruncated: false,
        },
      };
    });

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(0)}`);
    for (let i = 0; i < 10; i += 1) {
      await ui.redraw({ text: `key ${pointer(0)} ${'x'.repeat(i)}`, isFirstOfReply: true });
      await clock.advance(20);
    }
    expect(await shown(ui)).toBe(`key ${pointer(0)} ${'x'.repeat(9)}`);
    await clock.advance(500);

    expect(runs).toBe(1);
    expect(await shown(ui)).toBe(`key ${value(0)} ${'x'.repeat(9)}`);
  });

  test(`${surface}: a pointer already resolved is drawn at once, in a new row, with no helper run`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');

    const first = await mountRow($, surface, 'AssistantMessage', pointer(0));
    await clock.settle();
    expect(await shown(first)).toBe(value(0));
    const second = await mountRow($, surface, 'UserMessage', `again ${pointer(0)}`);

    expect(await shown(second)).toBe(`again ${value(0)}`);
    expect(asked).toHaveLength(1);
  });

  test(`${surface}: a helper that fails leaves the pointer as written and is not respawned per redraw`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = helper(on, { deny: 'ENOENT' });

    const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(0)} end`);
    await clock.settle();
    expect(await shown(ui)).toBe(`key ${pointer(0)} end`);
    for (let i = 0; i < 5; i += 1) await ui.redraw();
    await clock.settle();

    expect(await shown(ui)).toBe(`key ${pointer(0)} end`);
    expect(asked).toHaveLength(1);

    // After the retry interval the next draw asks again.
    await clock.advance(31_000);
    await ui.redraw();
    await clock.settle();
    expect(asked).toHaveLength(2);
  });

  for (const [label, reply] of [
    ['prints garbage', { stdout: 'not json' }],
    ['answers the wrong version', { stdout: '{"v":2,"mode":"full","items":[]}' }],
    ['exits non-zero', { stdout: '', exitCode: 1 }],
    ['leaves out the pointer it was asked', { stdout: '{"v":1,"mode":"full","items":[]}' }],
  ] as const) {
    test(`${surface}: a helper that ${label} shows the pointer as written`, async ($, on) => {
      const clock = mock.clock(on);
      engineRow(on);
      helper(on, reply);

      const ui = await mountRow($, surface, 'AssistantMessage', `key ${pointer(2)} end`);
      await clock.settle();

      expect(await shown(ui)).toBe(`key ${pointer(2)} end`);
    });
  }

  test(`${surface}: a pointer in code, a code span or a quote is masked, one in prose is revealed`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');
    const text = [
      `prose ${pointer(0)}`,
      '```',
      pointer(1),
      '```',
      `span \`${pointer(2)}\``,
      `> ${pointer(3)}`,
    ].join('\n');

    const ui = await mountRow($, surface, 'AssistantMessage', text);
    await clock.settle();

    expect(await shown(ui)).toBe(
      [`prose ${value(0)}`, '```', badge(1), '```', `span \`${badge(2)}\``, `> ${badge(3)}`].join(
        '\n',
      ),
    );
    const sent = (asked[0]?.stdin as unknown as { items: { reveal: boolean }[] }).items;
    expect(sent.map((i) => i.reveal)).toEqual([true, false, false, false]);
  });

  test(`${surface}: the per-message reveal cap masks the pointers past it`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    answering(on, 'full');

    const ui = await mountRow(
      $,
      surface,
      'AssistantMessage',
      `${pointer(0)} ${pointer(1)} ${pointer(2)}`,
    );
    await clock.settle();

    expect(await shown(ui)).toBe(`${value(0)} ${value(1)} ${badge(2)}`);
  });

  test(`${surface}: the reveal cap holds across the blocks of one message and across redraws`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    answering(on, 'full');

    // cap + 1 distinct pointers, split over two blocks of one reply.
    const first = await mountRow($, surface, 'AssistantMessage', `${pointer(0)} ${pointer(1)}`);
    const second = await mountRow($, surface, 'AssistantMessage', `${pointer(2)}`, false);
    await clock.settle();
    await first.redraw();
    await second.redraw();
    await clock.settle();
    for (let i = 0; i < 3; i += 1) {
      await second.redraw();
      await first.redraw();
    }

    expect(await shown(first)).toBe(`${value(0)} ${value(1)}`);
    expect(await shown(second)).toBe(badge(2));

    // The same pointer keeps its choice when a later block repeats it.
    await second.redraw({ text: `${pointer(2)} ${pointer(0)}`, isFirstOfReply: false });
    await clock.settle();
    expect(await shown(second)).toBe(`${badge(2)} ${value(0)}`);

    // A new message starts a fresh count.
    const next = await mountRow($, surface, 'AssistantMessage', pointer(2));
    await clock.settle();
    expect(await shown(next)).toBe(value(2));
  });

  test(`${surface}: text with no pointer is handed on untouched and spawns nothing`, async ($, on) => {
    const clock = mock.clock(on);
    engineRow(on);
    const asked = answering(on, 'full');

    const ui = await mountRow($, surface, 'AssistantMessage', 'plain [[not a pointer]] text');
    await clock.settle();

    expect(await shown(ui)).toBe('plain [[not a pointer]] text');
    expect(asked).toHaveLength(0);
  });
}
