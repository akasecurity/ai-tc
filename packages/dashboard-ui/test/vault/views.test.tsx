import type { VaultDeref, VaultInventoryEntry } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DerefAuditTableView } from '../../src/vault/DerefAuditTableView.tsx';
import { VaultInventoryView } from '../../src/vault/VaultInventoryView.tsx';
import { VaultReuseView } from '../../src/vault/VaultReuseView.tsx';

// Static-render coverage for the vault views (this package's test environment
// is node, with no DOM). Everything a view receives is already raw-free —
// masked previews, locations, counts — so the assertions here pin the display
// contract: the reveal-grant badge only on granted rows, the batched-deref
// hiding, the model-crossing prominence, and that no raw-shaped string ever
// appears in the output.
//
// The lists are keyset-paged, so each view also renders a cursor footer. There
// is no DOM here and nothing can be clicked, but every branch of that footer is
// decided at render time — whether the caller can page at all, whether more
// rows remain, whether a page is in flight, and what the count line claims —
// so the whole contract is readable in the markup.

const BADGE = 'Reveal to model';

// ui-kit's LoadMore parts, by the data-slot each one carries. The container
// slot is matched with its closing quote so it cannot also match the button's
// `load-more-button`.
const FOOTER = 'data-slot="load-more"';
const FOOTER_BUTTON = 'data-slot="load-more-button"';
const FOOTER_STATUS = 'data-slot="load-more-status"';
// LoadMoreButton sets `disabled={disabled ?? loading}`, so the attribute lands
// on the footer button itself. It is matched there rather than anywhere in the
// markup, where every Button's `disabled:` utility classes would match.
const FOOTER_BUTTON_DISABLED = `${FOOTER_BUTTON} disabled=""`;
const SPINNER = 'animate-spin';

// The masked preview is the only value-shaped string allowed through: nothing
// matching a live AWS key id or a generic long token may appear. Shared by both
// hygiene cases so the unpaginated and paginated shapes are held to one rule.
const RAW_AWS_KEY_ID = /AKIA[0-9A-Z]{16}/;
const RAW_LONG_TOKEN = /\b(?:sk|ghp|gho|xoxb)-?_?[A-Za-z0-9]{20,}/;

function entry(overrides: Partial<VaultInventoryEntry>): VaultInventoryEntry {
  return {
    pointerId: 'ptr-1111',
    category: 'secret',
    provider: 'aws',
    maskedMatch: 'AKIA****MASK',
    occurrences: 1,
    firstSeen: '2026-07-01T00:00:00.000Z',
    lastSeen: '2026-07-02T00:00:00.000Z',
    revealGrantId: null,
    sightings: [
      {
        location: '~/.claude/projects/demo/transcript.jsonl',
        kind: 'transcript',
        firstSeen: '2026-07-01T00:00:00.000Z',
        lastSeen: '2026-07-02T00:00:00.000Z',
      },
    ],
    ...overrides,
  };
}

// Three rows of which only two are reused: `ptr-once` has a single occurrence
// and a single sighting, so VaultReuseView filters it out. Every count that
// view renders is therefore 2 against an input length of 3 — a numerator taken
// from the wrong array reads differently.
function mixedReuseRows(): VaultInventoryEntry[] {
  return [
    entry({ pointerId: 'ptr-five', maskedMatch: 'five****MASK', occurrences: 5 }),
    entry({ pointerId: 'ptr-once', maskedMatch: 'once****MASK' }),
    entry({ pointerId: 'ptr-three', maskedMatch: 'three****MASK', occurrences: 3 }),
  ];
}

function deref(overrides: Partial<VaultDeref>): VaultDeref {
  return {
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    pointerId: 'ptr-1111',
    at: '2026-07-02T00:00:00.000Z',
    target: 'human',
    reason: 'explicit-reveal',
    outcome: 'revealed',
    pointerCount: 1,
    ...overrides,
  };
}

describe('VaultInventoryView', () => {
  it('flags only rows covered by an active reveal grant', () => {
    const html = renderToStaticMarkup(
      <VaultInventoryView
        entries={[
          entry({ pointerId: 'ptr-granted', revealGrantId: 'grant-1' }),
          entry({ pointerId: 'ptr-plain', maskedMatch: 'ghp_****MASK' }),
        ]}
      />,
    );
    expect(html.split(BADGE).length - 1).toBe(1);
  });

  it('renders each sighting with its location and kind chip', () => {
    const html = renderToStaticMarkup(<VaultInventoryView entries={[entry({})]} />);
    expect(html).toContain('~/.claude/projects/demo/transcript.jsonl');
    expect(html).toContain('Transcript');
    // The consequence of a written pointer is stated, not implied.
    expect(html).toContain('sees the correlation');
  });

  it('renders row actions only when the callbacks are supplied', () => {
    const rows = [entry({ revealGrantId: 'grant-1' })];
    const readOnly = renderToStaticMarkup(<VaultInventoryView entries={rows} />);
    expect(readOnly).not.toContain('Reveal</button>');
    expect(readOnly).not.toContain('Revoke grant');
    const actionable = renderToStaticMarkup(
      <VaultInventoryView entries={rows} onReveal={() => undefined} onRevoke={() => undefined} />,
    );
    expect(actionable).toContain('Reveal</button>');
    expect(actionable).toContain('Revoke grant');
    // No revoke affordance without an active grant to revoke.
    const ungranted = renderToStaticMarkup(
      <VaultInventoryView
        entries={[entry({})]}
        onReveal={() => undefined}
        onRevoke={() => undefined}
      />,
    );
    expect(ungranted).not.toContain('Revoke grant');
  });

  it('states the honest empty state', () => {
    const html = renderToStaticMarkup(<VaultInventoryView entries={[]} />);
    expect(html).toContain('Nothing vaulted yet');
  });

  it('states the truncation rather than the footer when the caller cannot page', () => {
    const rows = [entry({ pointerId: 'ptr-a' }), entry({ pointerId: 'ptr-b' })];
    // Nothing beyond the page and no way to page: neither branch renders.
    const complete = renderToStaticMarkup(<VaultInventoryView entries={rows} />);
    expect(complete).not.toContain(FOOTER);
    expect(complete).not.toContain('the rest are in the store');
    // More rows exist and there is no callback to reach them — saying so is
    // the honest render, and silence would hide the missing rows entirely.
    const truncated = renderToStaticMarkup(<VaultInventoryView entries={rows} hasMore={true} />);
    expect(truncated).not.toContain(FOOTER);
    expect(truncated).toContain('Showing the first 2 values — the rest are in the store.');
  });

  it('offers the footer button only while more values remain', () => {
    const rows = [entry({ pointerId: 'ptr-a' }), entry({ pointerId: 'ptr-b' })];
    const more = renderToStaticMarkup(
      <VaultInventoryView entries={rows} hasMore={true} onLoadMore={() => undefined} total={40} />,
    );
    expect(more).toContain(FOOTER);
    expect(more).toContain(FOOTER_BUTTON);
    // The label names what is loaded, and is the button's own text.
    expect(more).toContain('>Load more values</button>');
    expect(more).not.toContain('the rest are in the store');
    // Exhausted: no button to press, but the count line stays — it is what
    // tells a reader the list is complete rather than merely stalled.
    const done = renderToStaticMarkup(
      <VaultInventoryView entries={rows} hasMore={false} onLoadMore={() => undefined} total={40} />,
    );
    expect(done).toContain(FOOTER);
    expect(done).not.toContain(FOOTER_BUTTON);
    expect(done).toContain(FOOTER_STATUS);
  });

  it('disables the footer button while a page is in flight', () => {
    const html = renderToStaticMarkup(
      <VaultInventoryView
        entries={[entry({})]}
        hasMore={true}
        onLoadMore={() => undefined}
        loadingMore={true}
        total={40}
      />,
    );
    expect(html).toContain(FOOTER_BUTTON_DISABLED);
    expect(html).toContain(SPINNER);
    expect(html).toContain('Loading…</button>');
    expect(html).not.toContain('Load more values');
    // The idle render is the control: without it the assertions above would
    // hold for a button that is disabled whatever the caller passes.
    const idle = renderToStaticMarkup(
      <VaultInventoryView
        entries={[entry({})]}
        hasMore={true}
        onLoadMore={() => undefined}
        total={40}
      />,
    );
    expect(idle).toContain(FOOTER_BUTTON);
    expect(idle).not.toContain(FOOTER_BUTTON_DISABLED);
    expect(idle).not.toContain(SPINNER);
  });

  it('counts the page against the store-wide total', () => {
    const rows = [entry({ pointerId: 'ptr-a' }), entry({ pointerId: 'ptr-b' })];
    const html = renderToStaticMarkup(
      <VaultInventoryView entries={rows} hasMore={true} onLoadMore={() => undefined} total={40} />,
    );
    expect(html).toContain('2 of 40 values</p>');
    // With no total the view claims only what it can see.
    const untotalled = renderToStaticMarkup(
      <VaultInventoryView entries={rows} hasMore={true} onLoadMore={() => undefined} />,
    );
    expect(untotalled).toContain('2 shown</p>');
    expect(untotalled).not.toContain('2 of');
  });
});

describe('VaultReuseView', () => {
  it('shows only reused entries, ranked by occurrences, scoped to this machine', () => {
    const html = renderToStaticMarkup(
      <VaultReuseView
        entries={[
          entry({ pointerId: 'ptr-once', maskedMatch: 'once****MASK' }),
          entry({ pointerId: 'ptr-three', maskedMatch: 'three****MASK', occurrences: 3 }),
          entry({ pointerId: 'ptr-nine', maskedMatch: 'nine****MASK', occurrences: 9 }),
        ]}
      />,
    );
    expect(html).not.toContain('once****MASK');
    expect(html).toContain('on this machine');
    // Ranked by occurrences, descending.
    expect(html.indexOf('nine****MASK')).toBeLessThan(html.indexOf('three****MASK'));
  });

  it('counts multi-sighting single-occurrence values as reused', () => {
    const html = renderToStaticMarkup(
      <VaultReuseView
        entries={[
          entry({
            sightings: [
              {
                location: 'a.env',
                kind: 'file',
                firstSeen: '2026-07-01T00:00:00.000Z',
                lastSeen: '2026-07-01T00:00:00.000Z',
              },
              {
                location: 'b.env',
                kind: 'file',
                firstSeen: '2026-07-01T00:00:00.000Z',
                lastSeen: '2026-07-01T00:00:00.000Z',
              },
            ],
          }),
        ]}
      />,
    );
    expect(html).toContain('a.env');
    expect(html).toContain('b.env');
  });

  it('scopes the empty-state claim to this machine', () => {
    const html = renderToStaticMarkup(<VaultReuseView entries={[]} />);
    expect(html).toContain('No reused values detected on this machine.');
  });

  it('states the truncation rather than the footer when the caller cannot page', () => {
    const rows = mixedReuseRows();
    const complete = renderToStaticMarkup(<VaultReuseView entries={rows} />);
    expect(complete).not.toContain(FOOTER);
    expect(complete).not.toContain('the rest are in the store');
    const truncated = renderToStaticMarkup(<VaultReuseView entries={rows} hasMore={true} />);
    expect(truncated).not.toContain(FOOTER);
    // Counted over the rendered rows, like the status line below — two of the
    // three inputs survive `isReused`.
    expect(truncated).toContain('Showing the first 2 reused values — the rest are in the store.');
  });

  it('offers the footer button only while more reused values remain', () => {
    const rows = mixedReuseRows();
    const more = renderToStaticMarkup(
      <VaultReuseView entries={rows} hasMore={true} onLoadMore={() => undefined} total={40} />,
    );
    expect(more).toContain(FOOTER);
    expect(more).toContain(FOOTER_BUTTON);
    expect(more).toContain('>Load more reused values</button>');
    expect(more).not.toContain('the rest are in the store');
    const done = renderToStaticMarkup(
      <VaultReuseView entries={rows} hasMore={false} onLoadMore={() => undefined} total={40} />,
    );
    expect(done).toContain(FOOTER);
    expect(done).not.toContain(FOOTER_BUTTON);
    expect(done).toContain(FOOTER_STATUS);
  });

  it('disables the footer button while a page is in flight', () => {
    const rows = mixedReuseRows();
    const html = renderToStaticMarkup(
      <VaultReuseView
        entries={rows}
        hasMore={true}
        onLoadMore={() => undefined}
        loadingMore={true}
        total={40}
      />,
    );
    expect(html).toContain(FOOTER_BUTTON_DISABLED);
    expect(html).toContain(SPINNER);
    expect(html).toContain('Loading…</button>');
    expect(html).not.toContain('Load more reused values');
    const idle = renderToStaticMarkup(
      <VaultReuseView entries={rows} hasMore={true} onLoadMore={() => undefined} total={40} />,
    );
    expect(idle).toContain(FOOTER_BUTTON);
    expect(idle).not.toContain(FOOTER_BUTTON_DISABLED);
    expect(idle).not.toContain(SPINNER);
  });

  it('counts the rendered rows against the total, not the rows it was handed', () => {
    // One of the three inputs is not reused, so the view drops it. A numerator
    // taken from `entries` would claim a row that is not on screen and could
    // never reach its denominator by paging.
    const html = renderToStaticMarkup(
      <VaultReuseView
        entries={mixedReuseRows()}
        hasMore={true}
        onLoadMore={() => undefined}
        total={40}
      />,
    );
    expect(html).not.toContain('once****MASK');
    expect(html).toContain('2 of 40 reused values</p>');
    expect(html).not.toContain('3 of 40 reused values');
    const untotalled = renderToStaticMarkup(
      <VaultReuseView entries={mixedReuseRows()} hasMore={true} onLoadMore={() => undefined} />,
    );
    expect(untotalled).toContain('2 shown</p>');
    expect(untotalled).not.toContain('3 shown');
  });
});

describe('DerefAuditTableView', () => {
  it('hides batched rows behind a muted count line by default', () => {
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={[deref({})]}
        hiddenBatched={4}
        showBatched={false}
        onToggleBatched={() => undefined}
      />,
    );
    expect(html).toContain('4 display/render resolutions hidden');
    expect(html).not.toContain('Display render');
  });

  it('shows batched rows with their pointerCount under the flag', () => {
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={[deref({ reason: 'display', pointerCount: 12 })]}
        hiddenBatched={0}
        showBatched={true}
      />,
    );
    expect(html).toContain('Display render');
    expect(html).toContain('×12');
  });

  it('marks a refused model crossing with the prominence hook', () => {
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={[deref({ target: 'model', reason: 'model-input', outcome: 'refused' })]}
        hiddenBatched={0}
        showBatched={false}
      />,
    );
    expect(html).toContain('data-model-crossing="refused"');
    expect(html).toContain('bg-sev-high-fill');
  });

  it('marks a revealed model crossing and its grant prefix', () => {
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={[
          deref({
            target: 'model',
            reason: 'model-input',
            outcome: 'revealed',
            grantId: 'aaaabbbb-cccc-dddd-eeee-ffff00001111',
          }),
        ]}
        hiddenBatched={0}
        showBatched={false}
      />,
    );
    expect(html).toContain('data-model-crossing="revealed"');
    expect(html).toContain('aaaabbbb');
    expect(html).not.toContain('aaaabbbb-cccc');
  });

  it('renders a purge as a distinguished event line', () => {
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={[deref({ reason: 'purge', outcome: 'unavailable', pointerCount: 7 })]}
        hiddenBatched={0}
        showBatched={false}
      />,
    );
    expect(html).toContain('data-purge');
    expect(html).toContain('Vault purge');
    expect(html).toContain('7 pointers');
  });

  it('states the truncation rather than the footer when the caller cannot page', () => {
    const rows = [deref({}), deref({ id: 'second-row-id' })];
    const complete = renderToStaticMarkup(
      <DerefAuditTableView rows={rows} hiddenBatched={0} showBatched={false} />,
    );
    expect(complete).not.toContain(FOOTER);
    expect(complete).not.toContain('Showing the most recent');
    const truncated = renderToStaticMarkup(
      <DerefAuditTableView rows={rows} hiddenBatched={0} showBatched={false} hasMore={true} />,
    );
    expect(truncated).not.toContain(FOOTER);
    expect(truncated).toContain('Showing the most recent 2 resolutions.');
  });

  it('offers the footer button only while more resolutions remain', () => {
    const rows = [deref({}), deref({ id: 'second-row-id' })];
    const more = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={0}
        showBatched={false}
        hasMore={true}
        onLoadMore={() => undefined}
      />,
    );
    expect(more).toContain(FOOTER);
    expect(more).toContain(FOOTER_BUTTON);
    expect(more).toContain('>Load more resolutions</button>');
    expect(more).not.toContain('Showing the most recent');
    const done = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={0}
        showBatched={false}
        hasMore={false}
        onLoadMore={() => undefined}
      />,
    );
    expect(done).toContain(FOOTER);
    expect(done).not.toContain(FOOTER_BUTTON);
    expect(done).toContain(FOOTER_STATUS);
    expect(done).toContain('2 shown</p>');
  });

  it('disables the footer button while a page is in flight', () => {
    const rows = [deref({}), deref({ id: 'second-row-id' })];
    const html = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={0}
        showBatched={false}
        hasMore={true}
        onLoadMore={() => undefined}
        loadingMore={true}
      />,
    );
    expect(html).toContain(FOOTER_BUTTON_DISABLED);
    expect(html).toContain(SPINNER);
    expect(html).toContain('Loading…</button>');
    expect(html).not.toContain('Load more resolutions');
    const idle = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={0}
        showBatched={false}
        hasMore={true}
        onLoadMore={() => undefined}
      />,
    );
    expect(idle).toContain(FOOTER_BUTTON);
    expect(idle).not.toContain(FOOTER_BUTTON_DISABLED);
    expect(idle).not.toContain(SPINNER);
  });

  it('keeps the batched-hidden line and its toggle alongside the load-more footer', () => {
    // Two different counts that must not displace each other: `hiddenBatched`
    // spans the whole trail, the footer status counts the page.
    const rows = [deref({}), deref({ id: 'second-row-id' })];
    const hidden = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={4}
        showBatched={false}
        onToggleBatched={() => undefined}
        hasMore={true}
        onLoadMore={() => undefined}
      />,
    );
    expect(hidden).toContain('4 display/render resolutions hidden');
    expect(hidden).toContain('Show them');
    expect(hidden).toContain(FOOTER_BUTTON);
    expect(hidden).toContain('2 shown</p>');
    // Under the flag the trail-wide line gives way to the Hide toggle, and the
    // page footer is untouched by that switch.
    const shown = renderToStaticMarkup(
      <DerefAuditTableView
        rows={rows}
        hiddenBatched={4}
        showBatched={true}
        onToggleBatched={() => undefined}
        hasMore={true}
        onLoadMore={() => undefined}
      />,
    );
    expect(shown).toContain('Hide display/render resolutions');
    expect(shown).not.toContain('resolutions hidden');
    expect(shown).toContain(FOOTER_BUTTON);
    expect(shown).toContain('2 shown</p>');
  });
});

describe('raw-value hygiene', () => {
  it('never renders a raw-shaped credential from raw-free props', () => {
    const html = renderToStaticMarkup(
      <>
        <VaultInventoryView entries={[entry({ revealGrantId: 'grant-1' })]} />
        <VaultReuseView entries={[entry({ occurrences: 2 })]} />
        <DerefAuditTableView
          rows={[deref({ target: 'model', reason: 'model-input', outcome: 'revealed' })]}
          hiddenBatched={2}
          showBatched={false}
        />
      </>,
    );
    // The masked preview is the only value-shaped string allowed through:
    // nothing matching a live AWS key id or a generic long token may appear.
    expect(html).not.toMatch(RAW_AWS_KEY_ID);
    expect(html).not.toMatch(RAW_LONG_TOKEN);
  });

  it('never renders a raw-shaped credential in the paginated shape either', () => {
    const html = renderToStaticMarkup(
      <>
        <VaultInventoryView
          entries={[entry({ revealGrantId: 'grant-1' })]}
          hasMore={true}
          onLoadMore={() => undefined}
          loadingMore={true}
          total={40}
        />
        <VaultReuseView
          entries={[entry({ occurrences: 2 })]}
          hasMore={true}
          onLoadMore={() => undefined}
          total={40}
        />
        <DerefAuditTableView
          rows={[deref({ target: 'model', reason: 'model-input', outcome: 'revealed' })]}
          hiddenBatched={2}
          showBatched={false}
          onToggleBatched={() => undefined}
          hasMore={true}
          onLoadMore={() => undefined}
        />
      </>,
    );
    // Positive control: all three footers really rendered, so the absence
    // checks below are reading paginated markup rather than passing vacuously
    // on a shape that never grew a footer at all.
    expect(html.split(FOOTER_BUTTON).length - 1).toBe(3);
    expect(html).not.toMatch(RAW_AWS_KEY_ID);
    expect(html).not.toMatch(RAW_LONG_TOKEN);
  });
});
