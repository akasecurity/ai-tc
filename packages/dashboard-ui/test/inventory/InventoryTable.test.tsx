// @vitest-environment jsdom
import type { AssetSummary, ProjectSummary } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InventoryTable, PAGE_SIZE } from '../../src/inventory/InventoryTable.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const NOW = Date.parse('2026-10-15T12:00:00.000Z');

function project(id: string, overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return {
    id,
    name: id,
    repo: `acme/${id}`,
    visibility: 'private',
    language: 'TypeScript',
    policyDefault: 'approved',
    updatedAt: '2026-10-15T10:00:00.000Z',
    accessCounts: { open: 1, approved: 0, blocked: 0, total: 1 },
    findingsCount: 0,
    ...overrides,
  };
}

function skill(id: string, overrides: Partial<AssetSummary> = {}): AssetSummary {
  return {
    id,
    type: 'skill',
    name: id,
    sub: 'Skill · acme',
    flags: [],
    meta: {
      source: 'acme/skills',
      scope: 'user',
      installedVersion: '1.0.0',
      latestVersion: '1.0.0',
    },
    ...overrides,
  };
}

let mounted: MountedRoot;
beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

const bodyRows = (): HTMLTableRowElement[] => [
  ...mounted.host.querySelectorAll<HTMLTableRowElement>('tbody tr'),
];
const names = (): string[] => bodyRows().map((r) => r.querySelector('td')?.textContent ?? '');
const headers = (): string[] =>
  [...mounted.host.querySelectorAll('thead th')].map((th) => th.textContent);

function buttonNamed(text: string): HTMLButtonElement {
  const el = [...mounted.host.querySelectorAll('button')].find((b) => b.textContent === text);
  if (!(el instanceof HTMLButtonElement)) throw new Error(`no "${text}" button`);
  return el;
}

function click(el: Element): void {
  act(() => {
    el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
}

const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

function typeInto(input: HTMLInputElement, value: string): void {
  // A property descriptor's `set`, applied with an explicit receiver below.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const setter = valueDescriptor?.set;
  if (setter === undefined) throw new Error('HTMLInputElement has no value setter');
  act(() => {
    Reflect.apply(setter, input, [value]);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

function mount(props: Partial<Parameters<typeof InventoryTable>[0]>): void {
  renderRoot(
    mounted.root,
    <InventoryTable
      title="Claude Code"
      subtitle="sub"
      avatar={null}
      rows={[]}
      type={null}
      searchNoun="inventory"
      onOpen={vi.fn()}
      renderedAt={NOW}
      {...props}
    />,
  );
}

describe('InventoryTable, one type', () => {
  it("shows that type's own columns", () => {
    mount({ type: 'skill', rows: [skill('a')] });
    expect(headers()).toEqual([
      'Name',
      'Source',
      'Scope',
      'Installed',
      'Latest',
      'Updated',
      'Status',
    ]);
    mount({ type: 'hook', rows: [] });
    expect(headers()[0]).toBe('Command');
  });

  it('keeps an active status pill on screen after its rows are gone', () => {
    mount({ type: 'skill', rows: [skill('a', { flags: ['update'] }), skill('b')] });
    click(buttonNamed('Update1'));
    mount({ type: 'skill', rows: [skill('a'), skill('b')] });
    expect(names()).toEqual([]);
    expect(buttonNamed('Update0').getAttribute('data-state')).toBe('on');
    click(buttonNamed('All2'));
    expect(names()).toEqual(['a', 'b']);
  });

  it('searches the text a cell shows, not its raw value', () => {
    mount({
      type: 'skill',
      rows: [skill('a', { meta: { updatedAt: '2026-08-15T12:00:00.000Z' } }), skill('b')],
    });
    const input = mounted.host.querySelector('input');
    if (!(input instanceof HTMLInputElement)) throw new Error('no search field');
    typeInto(input, 'months ago');
    expect(names()).toEqual(['a']);
    typeInto(input, '2026-08');
    expect(names()).toEqual([]);
  });

  it('offers a pill per status present plus All and OK, and filters by the one picked', () => {
    mount({
      type: 'skill',
      rows: [skill('a', { flags: ['update'] }), skill('b', { flags: ['stale'] }), skill('c')],
    });
    const pills = [...mounted.host.querySelectorAll('[data-slot="segmented-control-item"]')].map(
      (p) => p.textContent,
    );
    expect(pills).toEqual(['All3', 'Update1', 'Stale1', 'OK1']);

    click(buttonNamed('Update1'));
    expect(names()).toEqual(['a']);
    click(buttonNamed('OK1'));
    expect(names()).toEqual(['c']);
  });
});

describe('InventoryTable, a harness', () => {
  const rows = [
    project('p1', { findingsCount: 2 }),
    skill('s1'),
    skill('s2', { flags: ['update'] }),
  ];

  it('shows Type and Detail columns and a pill per type that toggles off on a second click', () => {
    mount({ rows });
    expect(headers()).toEqual(['Name', 'Type', 'Detail', 'Status']);

    click(buttonNamed('Skills2'));
    expect(names()).toEqual(['s1', 's2']);
    click(buttonNamed('Skills2'));
    expect(names()).toEqual(['p1', 's1', 's2']);
  });

  it('searches name, detail and column values', () => {
    mount({ rows });
    const input = mounted.host.querySelector('input');
    if (!(input instanceof HTMLInputElement)) throw new Error('no search field');
    typeInto(input, 'acme/p1');
    expect(names()).toEqual(['p1']);
    typeInto(input, 'nothing-matches');
    expect(names()).toEqual([]);
    expect(mounted.host.textContent).toContain('Nothing matches this filter.');
  });

  it('sorts by a column and flips direction on a second click', () => {
    mount({ rows: [skill('b'), skill('c'), skill('a')], type: 'skill' });
    const nameHeader = buttonNamed('Name');
    click(nameHeader);
    expect(names()).toEqual(['a', 'b', 'c']);
    expect(nameHeader.closest('th')?.getAttribute('aria-sort')).toBe('ascending');
    click(nameHeader);
    expect(names()).toEqual(['c', 'b', 'a']);
  });

  it(`pages ${String(PAGE_SIZE)} rows at a time`, () => {
    const many = Array.from({ length: PAGE_SIZE + 3 }, (_, i) =>
      skill(`s${String(i).padStart(2, '0')}`),
    );
    mount({ rows: many });
    expect(bodyRows()).toHaveLength(PAGE_SIZE);
    expect(mounted.host.textContent).toContain(
      `1–${String(PAGE_SIZE)} of ${String(PAGE_SIZE + 3)}`,
    );
    expect(mounted.host.textContent).toContain('Page 1 of 2');

    const next = mounted.host.querySelector('[data-slot="pagination-next"]');
    if (next === null) throw new Error('no Next button');
    click(next);
    expect(bodyRows()).toHaveLength(3);
    expect(mounted.host.textContent).toContain('Page 2 of 2');
  });

  it('keeps an active type pill on screen after its rows are gone, so it can be cleared', () => {
    mount({ rows });
    click(buttonNamed('Projects1'));
    expect(names()).toEqual(['p1']);

    mount({ rows: rows.slice(1) });
    expect(names()).toEqual([]);
    click(buttonNamed('Projects0'));
    expect(names()).toEqual(['s1', 's2']);
  });

  it('opens a row on click', () => {
    const onOpen = vi.fn();
    mount({ rows, onOpen });
    const second = bodyRows()[1];
    if (second === undefined) throw new Error('no second row');
    click(second);
    expect(onOpen).toHaveBeenCalledWith(rows[1]);
  });
});

describe('InventoryTable endpoint counts', () => {
  const cellsOf = (name: string): string[] => {
    const row = bodyRows().find((r) => r.querySelector('td')?.textContent === name);
    return [...(row?.querySelectorAll('td') ?? [])].map((td) => td.textContent);
  };

  it('shows no Endpoints column when the rows carry no count', () => {
    mount({ type: 'skill', rows: [skill('a')] });
    expect(headers()).not.toContain('Endpoints');
    mount({ type: 'project', rows: [project('p')] });
    expect(headers()).not.toContain('Endpoints');
  });

  it('shows each row’s endpoints, the cap as "100+", and the versions it is reported in', () => {
    mount({
      type: 'skill',
      rows: [
        skill('few', { machines: 3, variants: 1 }),
        skill('split', { machines: 12, variants: 2 }),
        skill('fleet', { machines: 100, variants: 1 }),
      ],
    });

    expect(headers()).toContain('Endpoints');
    expect(cellsOf('few')).toContain('3');
    expect(cellsOf('fleet')).toContain('100+');
    const split = bodyRows().find((r) => r.querySelector('td')?.textContent === 'split');
    const cell = [...(split?.querySelectorAll('td') ?? [])].find((td) =>
      td.textContent.includes('versions'),
    );
    expect(cell?.firstChild?.textContent).toBe('12');
    expect(cell?.lastChild?.textContent).toBe('2 versions');
    expect(mounted.host.textContent).not.toContain('1 versions');
  });

  it('shows a project’s endpoints in a harness’s mixed table', () => {
    mount({ type: null, rows: [project('p', { machines: 4 }), skill('s', { machines: 2 })] });

    expect(headers()).toContain('Endpoints');
    expect(cellsOf('p')).toContain('4');
    expect(cellsOf('s')).toContain('2');
  });

  it('sorts by endpoints as numbers', () => {
    mount({
      type: 'skill',
      rows: [
        skill('nine', { machines: 9 }),
        skill('eleven', { machines: 11 }),
        skill('two', { machines: 2 }),
      ],
    });
    click(buttonNamed('Endpoints'));
    expect(names()).toEqual(['two', 'nine', 'eleven']);
  });
});
