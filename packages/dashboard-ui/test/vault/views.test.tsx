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

const BADGE = 'Reveal to model';

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
    expect(html).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(html).not.toMatch(/\b(?:sk|ghp|gho|xoxb)-?_?[A-Za-z0-9]{20,}/);
  });
});
