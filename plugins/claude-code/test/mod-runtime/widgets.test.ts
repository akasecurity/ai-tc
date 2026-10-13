import { expect, mock, test } from 'claude-code/testing';

import { FINDINGS_PATH, HOME, fileSystem, helper, model, snapshotText } from './harness.js';
import type { Hooks } from './harness.js';
import { SECRET } from './samples.generated.js';
import { ACTION_OF, fill, RULE_IDS, SCENARIOS } from './scenarios.generated.js';

// The findings pane, mounted on the terminal: what the store tests read back.
type Dollar = Parameters<Parameters<typeof test>[1]>[0];

async function mountPane(
  $: Dollar,
  surface: 'terminal' | 'desktop' = 'terminal',
): Promise<PaneMounted> {
  return $.ui.mount({
    plugin: 'aka',
    surface,
    component: 'Pane',
    requestId: 'aka-findings',
    props: { title: 'AKA findings', isFocused: false, bodyColumns: 80, placement: 'inline' },
  } as never) as unknown as PaneMounted;
}

interface PaneMounted {
  find(query: { key: string }): Promise<{ text: string } | undefined>;
  findAll(query: {
    type: string;
  }): Promise<{ key: string | undefined; text: string; props: Record<string, unknown> }[]>;
  press(target: { key: string }): Promise<unknown>;
}

async function paneRowKeys($: Dollar): Promise<string[]> {
  const pane = await mountPane($);
  const boxes = await pane.findAll({ type: 'Box' });
  return boxes.map((b) => b.key ?? '').filter((key) => key.startsWith('row-'));
}

// The mod's findings store: what it holds from helper answers and from the
// session's findings file, observed through the version counter in $.state.

const record = (id: string, extra: Record<string, unknown> = {}) => ({
  v: 1,
  id,
  at: '2026-10-13T10:00:00.000Z',
  ruleId: 'secrets/test-key',
  shortName: 'Test key',
  category: 'secret',
  severity: 'high',
  action: 'redacted',
  where: 'prompt',
  ...extra,
});
const ID_A = 'a'.repeat(16);
const ID_B = 'b'.repeat(16);

const SECRET_REDACT = {
  text: snapshotText({ categoryActions: { secret: 'redact' } }),
  mtimeMs: 1,
};

// Every value written to the findings counter, as a plugin hooking state.set sees it.
function counter(on: Hooks): unknown[] {
  const values: unknown[] = [];
  on('state.set', (_$, e, next) => {
    const write = e as { key?: unknown; value?: unknown };
    if (write.key === 'findings') values.push(write.value);
    return next(e);
  });
  return values;
}

function answering(on: Hooks, findings: unknown) {
  return helper(on, (request) =>
    JSON.stringify({
      v: 1,
      text: request.stdin.text.replaceAll(SECRET, '[REDACTED:SECRET]'),
      note: null,
      findings,
    }),
  );
}

// Spelled by joining so no pointer-shaped literal sits in the source.
const POINTER = ['[[aka:secret:', 'AB.', 'A'.repeat(26), '.', 'B'.repeat(16), ']]'].join('');

const prompt = `deploy with ${SECRET} please`;

test('a finding in the tokenize helper answer is held', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(bumps).toEqual([1]);
});

test('an invalid finding is dropped and does not fail the answer', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, [record(ID_A, { action: 'vaulted' }), 'junk', record(ID_B)]);

  await $.prompt.submit({ text: prompt });

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([1]);
  expect(await paneRowKeys($)).toEqual([`row-${ID_B}`]);
});

test('a findings value that is not a list is read as none', async ($, on) => {
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, { not: 'a list' });

  await $.prompt.submit({ text: prompt });

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([]);
});

test('the same finding from the helper and the file is held once', async ($, on) => {
  const bumps = counter(on);
  const line = JSON.stringify(record(ID_A));
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: `${line}\n`, mtimeMs: 5 }),
  );
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(reads).toContain(FINDINGS_PATH);
  expect(bumps).toEqual([1]);
  expect(await paneRowKeys($)).toEqual([`row-${ID_A}`]);
});

test('a truncated last line in the file leaves the complete lines taken', async ($, on) => {
  const bumps = counter(on);
  const text = `${JSON.stringify(record(ID_A))}\n${JSON.stringify(record(ID_B))}\n{"v":1,"id":"cccc`;
  fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text, mtimeMs: 6 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'nothing sensitive here' });

  expect(bumps).toEqual([1]);
  expect((await paneRowKeys($)).sort()).toEqual([`row-${ID_A}`, `row-${ID_B}`]);
});

test('a file over 4 MiB per stat is not read', async ($, on) => {
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), size: 4 * 1024 * 1024 + 1, mtimeMs: 7 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'hello' });

  expect(reads).not.toContain(FINDINGS_PATH);
  expect(bumps).toEqual([]);
});

test('an unchanged file is read once', async ($, on) => {
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), mtimeMs: 8 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'one' });
  await $.prompt.submit({ text: 'two' });

  expect(reads.filter((path) => path === FINDINGS_PATH)).toHaveLength(1);
  expect(bumps).toEqual([1]);
});

test('only numbers are ever written under aka', async ($, on) => {
  const written: { key?: unknown; value?: unknown }[] = [];
  on('state.set', (_$, e, next) => {
    written.push(e as never);
    return next(e);
  });
  fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_B)), mtimeMs: 9 }),
  );
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });

  expect(written.length).toBeGreaterThan(0);
  const all = JSON.stringify(written);
  expect(all).not.toContain('secrets/test-key');
  expect(all).not.toContain('Test key');
  for (const write of written) {
    const value = (write as { value?: unknown }).value;
    expect(typeof value).toBe('number');
  }
});

// The band above the prompt: AbovePrompt mounted on both surfaces that draw mods,
// the findings file and the helper answered from beneath, the engine's own
// AbovePrompt (a marker Box) beneath the plugin.

const NOW = Date.parse('2026-10-13T10:00:30.000Z');
const SURFACES = ['terminal', 'desktop'] as const;
type Surface = (typeof SURFACES)[number];

interface Mounted {
  find(query: { key: string }): Promise<{ text: string } | undefined>;
  findAll(query: {
    type: string;
  }): Promise<{ key: string | undefined; text: string; props: Record<string, unknown> }[]>;
  press(target: { key: string }): Promise<unknown>;
  redraw(props?: unknown): Promise<void>;
}

const BAND_PROPS = { hasSurvey: false, isWorking: false, maxRows: 5, bodyColumns: 80 };

function engineBand(on: Hooks): void {
  on('ui.render', () => ({ type: 'Box', props: { key: 'engine' }, children: [] }));
}

async function mountBand(
  $: Parameters<Parameters<typeof test>[1]>[0],
  surface: Surface,
  props: Record<string, unknown> = BAND_PROPS,
): Promise<Mounted> {
  return $.ui.mount({
    plugin: 'aka',
    surface,
    component: 'AbovePrompt',
    props: props as never,
  } as never) as unknown as Mounted;
}

const lines = (...records: Record<string, unknown>[]): string =>
  records.map((r) => JSON.stringify(r)).join('\n') + '\n';
const recent = (id: string, extra: Record<string, unknown> = {}) =>
  record(id, { at: new Date(NOW - 5000).toISOString(), ...extra });

// A findings file the test can change between draws, under a session id of its
// own: the mod keeps its list in module memory, and a new id starts it empty.
let sessions = 0;
function fileOf(
  on: Hooks,
  initial: string,
): { set(text: string): void; session(id: string): void; id: string } {
  sessions += 1;
  const state = { id: `band-${String(sessions)}`, text: initial, stamp: 1 };
  const first = state.id;
  const pathOf = (): string => [HOME, '.aka', 'data', 'mod-findings', `${first}.jsonl`].join('/');
  mock.env(on, { HOME });
  on('session.id', () => ({ value: state.id }));
  on('fs.stat', (_$, e) =>
    e.path === pathOf()
      ? {
          value: {
            kind: 'file' as const,
            size: state.text.length,
            mtimeMs: state.stamp,
            isLink: false,
          },
        }
      : { deny: 'ENOENT' },
  );
  on('fs.read', (_$, e) => (e.path === pathOf() ? { value: state.text } : { deny: 'ENOENT' }));
  return {
    get id() {
      return state.id;
    },
    set(next) {
      state.text = next;
      state.stamp += 1;
    },
    session(id) {
      state.id = id;
    },
  };
}

for (const surface of SURFACES) {
  test(`${surface}: a critical finding is one chip in the error colour`, async ($, on) => {
    mock.clock(on, { now: NOW });
    engineBand(on);
    fileOf(
      on,
      lines(
        recent(ID_A, {
          shortName: 'GitHub token',
          severity: 'critical',
          action: 'vaulted',
          pointer: POINTER,
        }),
      ),
    );

    const ui = await mountBand($, surface);

    const chips = await ui.findAll({ type: 'Text' });
    expect(chips.map((c) => c.text)).toEqual(['CRITICAL  GitHub token · vaulted · prompt']);
    expect(chips[0]?.props).toMatchObject({ color: 'error', bold: true });
    expect(await ui.find({ key: 'engine' })).toBeUndefined();
  });

  test(`${surface}: five recent findings draw three chips and a count`, async ($, on) => {
    mock.clock(on, { now: NOW });
    engineBand(on);
    const ids = ['1', '2', '3', '4', '5'].map((n) => n.repeat(16));
    fileOf(on, lines(...ids.map((id) => recent(id))));

    const ui = await mountBand($, surface);

    const texts = (await ui.findAll({ type: 'Text' })).map((c) => c.text);
    expect(texts).toHaveLength(4);
    expect(texts[3]).toBe('+2 more · /aka:findings-pane');
  });

  test(`${surface}: a finding older than two minutes draws nothing`, async ($, on) => {
    mock.clock(on, { now: NOW });
    engineBand(on);
    fileOf(on, lines(record(ID_A, { at: new Date(NOW - 121_000).toISOString() })));

    const ui = await mountBand($, surface);

    expect(await ui.find({ key: 'aka-band' })).toBeUndefined();
    expect(await ui.find({ key: 'engine' })).toBeDefined();
  });

  test(`${surface}: nothing is drawn while a survey is up`, async ($, on) => {
    mock.clock(on, { now: NOW });
    engineBand(on);
    fileOf(on, lines(recent(ID_A)));

    const ui = await mountBand($, surface, { ...BAND_PROPS, hasSurvey: true });

    expect(await ui.find({ key: 'aka-band' })).toBeUndefined();
    expect(await ui.find({ key: 'engine' })).toBeDefined();
  });

  test(`${surface}: dismiss hides the chips and a newer finding brings the band back`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    engineBand(on);
    const file = fileOf(on, lines(recent(ID_A)));

    const ui = await mountBand($, surface);
    expect(await ui.find({ key: 'aka-band' })).toBeDefined();

    await ui.press({ key: 'dismiss' });
    await clock.settle();
    expect(await ui.find({ key: 'aka-band' })).toBeUndefined();

    await clock.advance(1000);
    file.set(lines(recent(ID_A), record(ID_B, { at: new Date(clock.now() - 100).toISOString() })));
    await ui.redraw({ ...BAND_PROPS, maxRows: 6 });
    await clock.settle();

    const texts = (await ui.findAll({ type: 'Text' })).map((c) => c.text);
    expect(texts).toHaveLength(1);
    expect(texts[0]).toContain('Test key');
  });

  test(`${surface}: a fault while drawing hands on the engine's band`, async ($, on) => {
    mock.clock(on, { now: NOW });
    engineBand(on);
    fileOf(on, lines(recent(ID_A, { shortName: '__ENGINE_THROWS__' })));

    const ui = await mountBand($, surface);

    expect(await ui.find({ key: 'aka-band' })).toBeUndefined();
    expect(await ui.find({ key: 'engine' })).toBeDefined();
  });

  test(`${surface}: a new session id starts an empty band`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    engineBand(on);
    const file = fileOf(on, lines(recent(ID_A)));

    const ui = await mountBand($, surface);
    expect(await ui.find({ key: 'aka-band' })).toBeDefined();

    file.session(`${file.id}-after-clear`);
    await ui.redraw({ ...BAND_PROPS, maxRows: 6 });
    await clock.settle();

    expect(await ui.find({ key: 'aka-band' })).toBeUndefined();
    expect(await ui.find({ key: 'engine' })).toBeDefined();
  });
}

// The toast: only a block raises one.

const UNGRANTED = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');
const VALUES = {
  SECRET,
  IP: ['45', '79', '142', '6'].join('.'),
  EMAIL: ['user1', 'example.com'].join('@'),
  GRANTED: POINTER,
  UNGRANTED,
};

function snapshotFor(policy: Record<string, string>): string {
  const ruleActions: Record<string, string> = {};
  for (const [rule, archetype] of Object.entries(policy)) {
    ruleActions[RULE_IDS[rule]] = ACTION_OF[archetype];
  }
  return snapshotText({ ruleActions });
}

function toasts(on: Hooks): string[] {
  const raised: string[] = [];
  on('ui.toast', (_$, e) => {
    raised.push((e as { text: string }).text);
    return { value: undefined } as never;
  });
  return raised;
}

const ANSWER = (over: Record<string, unknown>): string =>
  JSON.stringify({ v: 1, deny: null, input: null, context: null, message: null, ...over });

function scenarioOf(kind: 'deny' | 'rewrite') {
  const found = SCENARIOS.find((s) => s.helper && s.outcome.kind === kind);
  if (found === undefined) throw new Error('no scenario');
  return found;
}

for (const kind of ['deny', 'rewrite'] as const) {
  test(`a ${kind === 'deny' ? 'blocked' : 'redacted'} tool call ${kind === 'deny' ? 'raises' : 'does not raise'} a toast`, async ($, on) => {
    const scenario = scenarioOf(kind);
    const text = snapshotFor(scenario.policy);
    fileSystem(on, () => ({ text, mtimeMs: 77 }));
    on('tool.call', () => ({ result: {}, text: 'ran' }) as never);
    const clock = mock.clock(on);
    const raised = toasts(on);
    const finding = record(ID_A, {
      shortName: 'Prod key',
      action: kind === 'deny' ? 'blocked' : 'redacted',
    });
    helper(on, {
      stdout:
        kind === 'deny'
          ? ANSWER({ deny: 'blocked by policy', message: 'AKA blocked it', findings: [finding] })
          : ANSWER({
              input: fill(scenario.outcome.input, VALUES),
              message: 'AKA redacted it',
              findings: [finding],
            }),
    });

    await $.tool.call({ tool: scenario.tool, ...fill(scenario.input, VALUES) } as never);

    await clock.settle();

    expect(raised).toEqual(kind === 'deny' ? ['Blocked: Prod key'] : []);
  });
}

// The status line, the findings command and the findings pane.

function statuses(on: Hooks): (string | undefined)[] {
  const calls: (string | undefined)[] = [];
  on('ui.status', (_$, e) => {
    calls.push((e as unknown as { text?: string }).text);
    return { value: undefined } as never;
  });
  return calls;
}

// A helper whose answer carries whatever findings the test sets next.
function answeringWith(on: Hooks): { next(findings: unknown[]): void } {
  let current: unknown[] = [];
  helper(on, (request) =>
    JSON.stringify({
      v: 1,
      text: request.stdin.text.replaceAll(SECRET, '[REDACTED:SECRET]'),
      note: null,
      findings: current,
    }),
  );
  return {
    next(findings) {
      current = findings;
    },
  };
}

test('the status line counts critical, high and other findings', async ($, on) => {
  mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A, { severity: 'critical' }), record(ID_B, { severity: 'high' })]);

  await $.prompt.submit({ text: prompt });

  expect(calls.at(-1)).toBe('AKA · redacting in place · 1 critical  1 high  0 other');
});

test('findings within one second write the status line once, a later one again', async ($, on) => {
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  const answer = answeringWith(on);
  const ids = ['1', '2', '3', '4'].map((n) => n.repeat(16));

  for (const id of ids.slice(0, 3)) {
    answer.next([record(id)]);
    await $.prompt.submit({ text: prompt });
  }
  expect(calls).toEqual(['AKA · redacting in place · 0 critical  1 high  0 other']);

  await clock.advance(1000);
  answer.next([record(ids[3] as string)]);
  await $.prompt.submit({ text: prompt });
  expect(calls).toEqual([
    'AKA · redacting in place · 0 critical  1 high  0 other',
    'AKA · redacting in place · 0 critical  4 high  0 other',
  ]);
});

test('the findings-pane command opens the pane', async ($, on) => {
  const opened: unknown[] = [];
  on('ui.open', (_$, e) => {
    opened.push(e);
    return { value: { isPlaced: true } } as never;
  });
  on('session.start', (_$, e) => ({ cwd: e.cwd }));
  on('env.get', () => ({ value: undefined }));
  const registered: unknown[] = [];
  on('command.register', (_$, e) => {
    registered.push(e);
    return { value: undefined } as never;
  });

  await $.session.start({ cwd: HOME, surface: null, isInteractive: true });
  await $.command.run({ command: 'findings-pane' } as never);

  expect(registered).toEqual([expect.objectContaining({ name: 'findings-pane' })]);
  expect(opened).toEqual([expect.objectContaining({ id: 'aka-findings' })]);
});

for (const surface of SURFACES) {
  const time = (at: string): string => {
    const date = new Date(at);
    return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
  };

  test(`${surface}: pane rows are newest first, in the severity colour, with the time`, async ($, on) => {
    mock.clock(on, { now: NOW });
    const older = '2026-10-13T10:00:00.000Z';
    const newer = '2026-10-13T10:00:10.000Z';
    fileOf(
      on,
      lines(
        record(ID_A, { at: older, severity: 'high', shortName: 'Old one' }),
        record(ID_B, { at: newer, severity: 'critical', shortName: 'New one' }),
      ),
    );

    const pane = await mountPane($, surface);

    const rows = (await pane.findAll({ type: 'Text' })).filter((t) => t.text.includes('·'));
    expect(rows.map((r) => r.text)).toEqual([
      `CRITICAL  New one · redacted · prompt  ${time(newer)}`,
      `HIGH  Old one · redacted · prompt  ${time(older)}`,
    ]);
    expect(rows[0]?.props).toMatchObject({ color: 'error' });
    expect(rows[1]?.props).toMatchObject({ color: 'warning' });
  });

  test(`${surface}: filter buttons narrow the rows and filter-all restores them`, async ($, on) => {
    mock.clock(on, { now: NOW });
    fileOf(
      on,
      lines(
        recent(ID_A, { severity: 'high' }),
        recent(ID_B, { severity: 'critical' }),
        recent('c'.repeat(16), { severity: 'low' }),
      ),
    );

    const pane = await mountPane($, surface);
    const keys = async (): Promise<string[]> =>
      (await pane.findAll({ type: 'Box' }))
        .map((b) => b.key ?? '')
        .filter((k) => k.startsWith('row-'))
        .sort();

    expect(await keys()).toHaveLength(3);
    await pane.press({ key: 'filter-critical' });
    expect(await keys()).toEqual([`row-${ID_B}`]);
    await pane.press({ key: 'filter-all' });
    expect(await keys()).toHaveLength(3);
  });

  test(`${surface}: an empty pane says so`, async ($, on) => {
    mock.clock(on, { now: NOW });
    fileOf(on, '');

    const pane = await mountPane($, surface);

    expect((await pane.findAll({ type: 'Text' })).map((t) => t.text)).toEqual([
      'No findings in this session.',
    ]);
  });

  test(`${surface}: a pointer is drawn masked, never whole`, async ($, on) => {
    mock.clock(on, { now: NOW });
    fileOf(on, lines(recent(ID_A, { action: 'vaulted', pointer: POINTER })));

    const pane = await mountPane($, surface);

    const texts = (await pane.findAll({ type: 'Text' })).map((t) => t.text);
    expect(texts).toContain('[[aka:secret:…]]');
    expect(texts.join('\n')).not.toContain('A'.repeat(26));
  });
}
