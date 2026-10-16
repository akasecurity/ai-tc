import { expect, mock, test } from 'claude-code/testing';

import { FINDINGS_PATH, HOME, fileSystem, helper, model, snapshotText } from './harness.js';
import type { HelperRequest, Hooks } from './harness.js';
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
  redraw(props?: unknown): Promise<void>;
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
  const clock = mock.clock(on);
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A)]);

  await $.prompt.submit({ text: prompt });
  await clock.settle();

  expect(bumps).toEqual([1]);
});

test('an invalid finding is dropped and does not fail the answer', async ($, on) => {
  const clock = mock.clock(on);
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, [record(ID_A, { action: 'vaulted' }), 'junk', record(ID_B)]);

  await $.prompt.submit({ text: prompt });
  await clock.settle();

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([1]);
  expect(await paneRowKeys($)).toEqual([`row-${ID_B}`]);
});

test('a findings value that is not a list is read as none', async ($, on) => {
  const clock = mock.clock(on);
  const bumps = counter(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, { not: 'a list' });

  await $.prompt.submit({ text: prompt });
  await clock.settle();

  expect(seen[0]).toContain('[REDACTED:SECRET]');
  expect(bumps).toEqual([]);
});

test('the same finding from the helper and the file is held once', async ($, on) => {
  const clock = mock.clock(on);
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
  await clock.settle();

  expect(reads).toContain(FINDINGS_PATH);
  expect(bumps).toEqual([1]);
  expect(await paneRowKeys($)).toEqual([`row-${ID_A}`]);
});

test('a truncated last line in the file leaves the complete lines taken', async ($, on) => {
  const clock = mock.clock(on);
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
  await clock.settle();

  expect(bumps).toEqual([1]);
  expect((await paneRowKeys($)).sort()).toEqual([`row-${ID_A}`, `row-${ID_B}`]);
});

test('a file over 4 MiB per stat is not read', async ($, on) => {
  const clock = mock.clock(on);
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), size: 4 * 1024 * 1024 + 1, mtimeMs: 7 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'hello' });
  await clock.settle();

  expect(reads).not.toContain(FINDINGS_PATH);
  expect(bumps).toEqual([]);
});

test('an unchanged file is read once', async ($, on) => {
  const clock = mock.clock(on);
  const bumps = counter(on);
  const reads = fileSystem(
    on,
    () => SECRET_REDACT,
    () => ({ text: JSON.stringify(record(ID_A)), mtimeMs: 8 }),
  );
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'one' });
  await clock.settle();
  await $.prompt.submit({ text: 'two' });
  await clock.settle();

  expect(reads.filter((path) => path === FINDINGS_PATH)).toHaveLength(1);
  expect(bumps).toEqual([1]);
});

test('only numbers are ever written under aka', async ($, on) => {
  const clock = mock.clock(on);
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
  await clock.settle();

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

// The toast: a block, or a message the helper left because it says more than the
// band (the helper drops a message that only repeats the findings).

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

const REVEAL_MESSAGE =
  'AKA revealed granted vault value(s) to this Write call — the reveal exception you approved authorized it.';

for (const [name, kind, message, expected] of [
  [
    'a blocked tool call raises Blocked: and the label',
    'deny',
    'AKA blocked it',
    ['Blocked: Prod key'],
  ],
  ['a redacted tool call with no message raises no toast', 'rewrite', null, []],
  ['a message beyond the findings is raised as it is', 'rewrite', REVEAL_MESSAGE, [REVEAL_MESSAGE]],
] as const) {
  test(name, async ($, on) => {
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
          ? ANSWER({ deny: 'blocked by policy', message, findings: [finding] })
          : ANSWER({
              input: fill(scenario.outcome.input, VALUES),
              message,
              findings: [finding],
            }),
    });

    await $.tool.call({ tool: scenario.tool, ...fill(scenario.input, VALUES) } as never);

    await clock.settle();

    expect(raised).toEqual(expected);
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
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A, { severity: 'critical' }), record(ID_B, { severity: 'high' })]);

  await $.prompt.submit({ text: prompt });
  await clock.settle();

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
  await clock.settle();
  expect(calls).toEqual([
    'AKA · redacting in place · 0 critical  1 high  0 other',
    'AKA · redacting in place · 0 critical  3 high  0 other',
  ]);
});

test('a later hook with no new finding also writes the held-back count', async ($, on) => {
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  const answer = answeringWith(on);
  for (const n of ['5', '6']) {
    answer.next([record(n.repeat(16))]);
    await $.prompt.submit({ text: prompt });
  }
  expect(calls).toHaveLength(1);
  await clock.advance(1000);
  answer.next([]);
  await $.prompt.submit({ text: 'nothing sensitive' });
  expect(calls.at(-1)).toBe('AKA · redacting in place · 0 critical  2 high  0 other');
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

  test(`${surface}: a filter with no matches names the severity`, async ($, on) => {
    mock.clock(on, { now: NOW });
    fileOf(on, lines(recent(ID_A, { severity: 'high' })));

    const pane = await mountPane($, surface);
    await pane.press({ key: 'filter-low' });

    expect((await pane.findAll({ type: 'Text' })).map((t) => t.text)).toEqual(['No low findings.']);
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

// Vault reveal controls in the pane.

const REVEALED = 'VALUE-SHOWN-ONCE';

type Answer = { stdout: string; exitCode?: number } | { deny: string };

// The reveal helper, answered from beneath the mod: a function of the request, a
// non-zero exit, or a refusal. The pane's consent question (a pane request with no
// items) is answered apart and kept in `probes`: by `probe` when given, else by
// the function, else `off` for mode 'off' and consent for any other.
function revealing(
  on: Hooks,
  mode: 'full' | 'off' | Answer | ((request: HelperRequest) => string) = 'full',
  probe?: Answer,
): { asked: HelperRequest[]; probes: HelperRequest[] } & HelperRequest[] {
  const asked: HelperRequest[] = [];
  const probes: HelperRequest[] = [];
  const answer = (stdout: string, exitCode = 0) => ({
    value: { exitCode, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  });
  on('process.run', (_$, e) => {
    const request: HelperRequest = {
      argv: e.argv,
      stdin: JSON.parse(e.init?.stdin ?? 'null') as HelperRequest['stdin'],
      timeoutMs: e.init?.timeoutMs,
    };
    const items = (request.stdin as unknown as { items: { token: string }[] }).items;
    if (items.length === 0) {
      probes.push(request);
      if (probe !== undefined)
        return 'deny' in probe ? { deny: probe.deny } : answer(probe.stdout, probe.exitCode);
      if (typeof mode === 'function') return answer(mode(request));
      return answer(JSON.stringify({ v: 1, mode: mode === 'off' ? 'off' : 'full', items: [] }));
    }
    asked.push(request);
    if (typeof mode === 'object' && 'deny' in mode) return { deny: mode.deny };
    const stdout =
      typeof mode === 'function'
        ? mode(request)
        : typeof mode === 'object'
          ? mode.stdout
          : JSON.stringify({
              v: 1,
              mode,
              items: items.map((i) => ({
                token: i.token,
                badge: '[badge]',
                revealed: mode === 'off' ? null : REVEALED,
              })),
            });
    return {
      value: {
        exitCode: typeof mode === 'object' ? (mode.exitCode ?? 0) : 0,
        stdout,
        stderr: '',
        isStdoutTruncated: false,
        isStderrTruncated: false,
      },
    };
  });
  return Object.assign(asked, { asked, probes });
}

// A reveal helper whose answer waits for release().
function held(on: Hooks): { release(): void } {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  on('process.run', async (_$, e) => {
    const items = (JSON.parse(e.init?.stdin ?? 'null') as { items: { token: string }[] }).items;
    if (items.length > 0) await gate;
    return {
      value: {
        exitCode: 0,
        stdout: JSON.stringify({
          v: 1,
          mode: 'full',
          items: items.map((i) => ({ token: i.token, badge: '[badge]', revealed: REVEALED })),
        }),
        stderr: '',
        isStdoutTruncated: false,
        isStderrTruncated: false,
      },
    };
  });
  return { release: () => release() };
}

const vaulted = (id: string) => recent(id, { action: 'vaulted', pointer: POINTER });

async function texts(pane: PaneMounted): Promise<string[]> {
  return (await pane.findAll({ type: 'Text' })).map((t) => t.text);
}

async function buttonKeys(pane: PaneMounted): Promise<string[]> {
  return (await pane.findAll({ type: 'Button' })).map((b) => b.key ?? '');
}

for (const surface of SURFACES) {
  test(`${surface}: Show reveals one value, once per press, and nothing on open`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    const asked = revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    expect(asked).toHaveLength(0);
    expect(asked.probes.map((r) => r.stdin)).toEqual([{ v: 1, pane: true, items: [] }]);
    expect(await buttonKeys(pane)).toContain(`show-${ID_A}`);
    expect(await texts(pane)).not.toContain(REVEALED);

    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();

    expect(asked).toHaveLength(1);
    expect(asked[0]?.stdin).toMatchObject({
      v: 1,
      pane: true,
      items: [{ token: POINTER, reveal: true }],
    });
    expect(await texts(pane)).toContain(REVEALED);
    expect(await buttonKeys(pane)).toContain(`hide-${ID_A}`);
  });

  test(`${surface}: Show reveals under the default masked inline setting`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    // The helper as it answers with consent and vaultInlineReveal 'masked': an
    // inline request is masked, a pane request is revealed.
    const asked = revealing(on, (request) => {
      const { items, pane } = request.stdin as unknown as {
        items: { token: string }[];
        pane?: boolean;
      };
      return JSON.stringify({
        v: 1,
        mode: pane === true ? 'full' : 'masked',
        items: items.map((i) => ({
          token: i.token,
          badge: '[badge]',
          revealed: pane === true ? REVEALED : null,
        })),
      });
    });

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();

    expect(asked.at(-1)?.stdin).toMatchObject({ pane: true });
    expect(await texts(pane)).toContain(REVEALED);
    expect(await texts(pane)).not.toContain("couldn't reveal");
  });

  test(`${surface}: no Show is drawn until the helper answers consent`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    on('process.run', async () => {
      await gate;
      return {
        value: {
          exitCode: 0,
          stdout: JSON.stringify({ v: 1, mode: 'full', items: [] }),
          stderr: '',
          isStdoutTruncated: false,
          isStderrTruncated: false,
        },
      };
    });

    const pane = await mountPane($, surface);
    expect((await buttonKeys(pane)).filter((k) => k.startsWith('show-'))).toEqual([]);

    release();
    await clock.settle();

    expect(await buttonKeys(pane)).toContain(`show-${ID_A}`);
  });

  for (const [name, probe] of [
    ['exits 1', { stdout: '', exitCode: 1 }],
    ['times out', { deny: 'timeout' }],
  ] as const) {
    test(`${surface}: a consent question that ${name} draws no Show`, async ($, on) => {
      const clock = mock.clock(on, { now: NOW });
      fileOf(on, lines(vaulted(ID_A)));
      const asked = revealing(on, 'full', probe);

      const pane = await mountPane($, surface);
      await clock.settle();
      await pane.redraw();

      expect(asked.probes).toHaveLength(1);
      expect((await buttonKeys(pane)).filter((k) => k.startsWith('show-'))).toEqual([]);
      expect(await texts(pane)).toContain('[[aka:secret:…]]');
    });
  }

  test(`${surface}: a pane with no vaulted finding asks nothing`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(recent(ID_A)));
    const asked = revealing(on);

    await mountPane($, surface);
    await clock.settle();

    expect(asked.probes).toHaveLength(0);
  });

  test(`${surface}: forgetting the reveals forgets the answer and the pane asks again`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    const file = fileOf(on, lines(vaulted(ID_A)));
    let consent: 'full' | 'off' = 'off';
    const asked = revealing(on, () => JSON.stringify({ v: 1, mode: consent, items: [] }));

    const pane = await mountPane($, surface);
    await clock.settle();
    expect((await buttonKeys(pane)).filter((k) => k.startsWith('show-'))).toEqual([]);

    consent = 'full';
    const firstId = file.id;
    file.session(`${firstId}-after-clear`);
    await pane.redraw();
    file.session(firstId);
    await pane.redraw();
    await clock.settle();

    expect(asked.probes).toHaveLength(2);
    expect(await buttonKeys(pane)).toContain(`show-${ID_A}`);
  });

  test(`${surface}: a shown value is masked again after 30 seconds`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();
    expect(await texts(pane)).toContain(REVEALED);

    await clock.advance(30_000);
    await clock.settle();

    expect(await texts(pane)).not.toContain(REVEALED);
    expect(await texts(pane)).toContain('[[aka:secret:…]]');
  });

  test(`${surface}: two presses before the helper answers start one run`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    const asked = revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await Promise.all([pane.press({ key: `show-${ID_A}` }), pane.press({ key: `show-${ID_A}` })]);
    await clock.settle();

    expect(asked).toHaveLength(1);
  });

  test(`${surface}: with no consent there are no Show buttons and nothing is revealed`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A), vaulted(ID_B)));
    const asked = revealing(on, 'off');

    const pane = await mountPane($, surface);
    await clock.settle();

    expect(asked).toHaveLength(0);
    expect(asked.probes).toHaveLength(1);

    expect((await buttonKeys(pane)).filter((k) => k.startsWith('show-'))).toEqual([]);
    expect(await texts(pane)).not.toContain(REVEALED);
    expect(await texts(pane)).not.toContain("couldn't reveal");
  });

  for (const [name, reply] of [
    ['exits 1', { stdout: '', exitCode: 1 }],
    ['times out', { deny: 'timeout' }],
  ] as const) {
    test(`${surface}: a helper that ${name} draws couldn't reveal and stays masked`, async ($, on) => {
      const clock = mock.clock(on, { now: NOW });
      fileOf(on, lines(vaulted(ID_A)));
      const asked = revealing(on, reply);

      const pane = await mountPane($, surface);
      await clock.settle();
      await pane.press({ key: `show-${ID_A}` });
      await clock.settle();

      expect(asked[0]?.timeoutMs).toBe(3000);
      const drawn = await texts(pane);
      expect(drawn).toContain("couldn't reveal");
      expect(drawn).toContain('[[aka:secret:…]]');
      expect(drawn).not.toContain(REVEALED);
    });
  }

  test(`${surface}: Hide masks the value at once`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();
    await pane.press({ key: `hide-${ID_A}` });

    expect(await texts(pane)).not.toContain(REVEALED);
    expect(await buttonKeys(pane)).toContain(`show-${ID_A}`);
  });

  test(`${surface}: a revealed value is never written to state, a toast or the status line`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A)));
    revealing(on);
    const written: string[] = [];
    on('state.set', (_$, e, next) => {
      written.push(JSON.stringify(e));
      return next(e);
    });
    const raised = toasts(on);
    const calls = statuses(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();
    expect(await texts(pane)).toContain(REVEALED);

    expect(written.length).toBeGreaterThan(0);
    expect(written.join('\n')).not.toContain(REVEALED);
    expect(raised.join('\n')).not.toContain(REVEALED);
    expect(calls.join('\n')).not.toContain(REVEALED);
  });

  test(`${surface}: an answer that lands after the session changed is never drawn`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    const file = fileOf(on, lines(vaulted(ID_A)));
    const gate = held(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    const pressed = pane.press({ key: `show-${ID_A}` });
    await clock.settle();
    const firstId = file.id;
    file.session(`${firstId}-after-clear`);
    await pane.redraw();
    file.session(firstId);
    await pane.redraw();
    gate.release();
    await pressed;
    await clock.settle();
    await pane.redraw();

    expect(await texts(pane)).not.toContain(REVEALED);
  });

  test(`${surface}: two findings with one pointer reveal only the one pressed`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    fileOf(on, lines(vaulted(ID_A), vaulted(ID_B)));
    revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();

    expect(await texts(pane).then((t) => t.filter((x) => x === REVEALED))).toHaveLength(1);
    expect(await buttonKeys(pane)).toContain(`hide-${ID_A}`);
    expect(await buttonKeys(pane)).toContain(`show-${ID_B}`);
    expect(await buttonKeys(pane)).not.toContain(`hide-${ID_B}`);
  });

  test(`${surface}: a new session never shows the session before's value`, async ($, on) => {
    const clock = mock.clock(on, { now: NOW });
    const file = fileOf(on, lines(vaulted(ID_A)));
    revealing(on);

    const pane = await mountPane($, surface);
    await clock.settle();
    await pane.press({ key: `show-${ID_A}` });
    await clock.settle();
    expect(await texts(pane)).toContain(REVEALED);

    file.session(`${file.id}-after-clear`);
    await pane.redraw();

    expect(await texts(pane)).not.toContain(REVEALED);
    expect(await texts(pane)).toEqual(['No findings in this session.']);
  });
}

// Hooks that must not hold a tool call or a session start.

test('a status write that hangs does not delay a tool call', async ($, on) => {
  mock.clock(on, { now: NOW });
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  let ran = false;
  let hang = false;
  on('tool.call', () => {
    ran = true;
    return { result: {}, text: 'ran' } as never;
  });
  on('ui.status', () =>
    hang ? (new Promise(() => undefined) as never) : ({ value: undefined } as never),
  );
  answering(on, [record(ID_A)]);
  await $.prompt.submit({ text: prompt });
  hang = true;

  await $.tool.call({ tool: 'Bash', command: 'echo hi' } as never);

  expect(ran).toBe(true);
});

test('a clock that throws does not re-schedule the status flush', async ($, on) => {
  let sleeps = 0;
  let now = NOW;
  on('ui.status', () => ({ value: undefined }) as never);
  on('clock.now', () => ({ value: now }) as never);
  on('clock.sleep', () => {
    sleeps += 1;
    return { deny: 'no timers' } as never;
  });
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  const answer = answeringWith(on);
  for (const n of ['7', '8']) {
    answer.next([record(n.repeat(16))]);
    await $.prompt.submit({ text: prompt });
    now += 10;
  }
  await new Promise((resolve) => setTimeout(resolve, 20));

  expect(sleeps).toBeLessThanOrEqual(2);
});

// A findings write the host never answers: the decision a hook makes must not wait
// on the widgets. The bound is a real timer; the mocked clock never moves on its own.
function hangFindingsWrites(on: Hooks): void {
  on('state.set', (_$, e, next) =>
    (e as { key?: unknown }).key === 'findings' ? (new Promise(() => undefined) as never) : next(e),
  );
}

async function within<T>(work: Promise<T>, ms = 2000): Promise<T | 'held'> {
  return Promise.race([
    work,
    new Promise<'held'>((resolve) => setTimeout(() => resolve('held'), ms)),
  ]);
}

for (const kind of ['deny', 'rewrite'] as const) {
  test(`a findings write that never answers does not hold a tool call's ${kind}`, async ($, on) => {
    mock.clock(on, { now: NOW });
    hangFindingsWrites(on);
    const scenario = scenarioOf(kind);
    const text = snapshotFor(scenario.policy);
    fileSystem(on, () => ({ text, mtimeMs: 78 }));
    let ran = false;
    on('tool.call', () => {
      ran = true;
      return { result: {}, text: 'ran' } as never;
    });
    const finding = record(ID_A, { shortName: 'Prod key' });
    helper(on, {
      stdout:
        kind === 'deny'
          ? ANSWER({ deny: 'blocked by policy', findings: [finding] })
          : ANSWER({ input: fill(scenario.outcome.input, VALUES), findings: [finding] }),
    });

    const result = await within(
      $.tool.call({ tool: scenario.tool, ...fill(scenario.input, VALUES) } as never),
    );

    expect(result).not.toBe('held');
    expect(ran).toBe(kind === 'rewrite');
  });
}

test('a findings write that never answers does not hold a prompt', async ($, on) => {
  mock.clock(on, { now: NOW });
  hangFindingsWrites(on);
  fileSystem(on, () => SECRET_REDACT);
  const seen = model(on);
  answering(on, [record(ID_A)]);

  expect(await within($.prompt.submit({ text: prompt }))).not.toBe('held');
  expect(seen[0]).toContain('[REDACTED:SECRET]');
});

test('a findings write that never answers does not hold a row', async ($, on) => {
  mock.clock(on, { now: NOW });
  hangFindingsWrites(on);
  fileSystem(on, () => SECRET_REDACT);
  const appended = mock.session(on).appended;
  answering(on, [record(ID_A)]);

  const row = {
    message: {
      type: 'user',
      role: 'user',
      isMeta: true,
      content: [{ type: 'text', text: `file: ${SECRET}` }],
    },
    door: 'attachment',
    origin: { kind: 'engine' },
    uuid: 'row-hang',
  };

  expect(await within($.session.append(row as never))).not.toBe('held');
  expect(JSON.stringify(appended()[0])).toContain('[REDACTED:SECRET]');
});

// The status line from the session's start: the mod says it is on before any finding.

function startSession(on: Hooks): void {
  on('session.start', (_$, e) => ({ cwd: e.cwd }));
  on('command.register', () => ({ value: undefined }) as never);
}

test('the session start writes the status line with nothing found', async ($, on) => {
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  helper(on, { stdout: '' });
  startSession(on);

  await $.session.start({ cwd: HOME, surface: null, isInteractive: true });
  await clock.settle();

  expect(calls).toEqual(['AKA · redacting in place · 0 critical  0 high  0 other']);
});

test('a finding within a second of the start waits out the window', async ($, on) => {
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, [record(ID_A)]);
  startSession(on);

  await $.session.start({ cwd: HOME, surface: null, isInteractive: true });
  await clock.settle();
  await $.prompt.submit({ text: prompt });
  await clock.settle();
  expect(calls).toEqual(['AKA · redacting in place · 0 critical  0 high  0 other']);

  await clock.advance(1000);
  await clock.settle();
  expect(calls).toEqual([
    'AKA · redacting in place · 0 critical  0 high  0 other',
    'AKA · redacting in place · 0 critical  1 high  0 other',
  ]);
});

test('with no session start, a prompt with nothing found writes no status line', async ($, on) => {
  const clock = mock.clock(on, { now: NOW });
  const calls = statuses(on);
  fileSystem(on, () => SECRET_REDACT);
  model(on);
  answering(on, []);

  await $.prompt.submit({ text: 'nothing sensitive here' });
  await clock.settle();

  expect(calls).toEqual([]);
});
