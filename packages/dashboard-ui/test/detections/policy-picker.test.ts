import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { policyMeta } from '../../src/detections/meta.ts';
import { PolicyPicker } from '../../src/detections/PolicyPicker.tsx';

// The picker's three states, and specifically the third one: an archetype this
// HOST cannot assign, offered anyway with the reason.
//
// It exists because a control plane can write policy and still be unable to
// deliver Redact & Vault to a device — the attached gateway refuses a remote
// custody instruction — and the shape that fixes gets rendered as a live button
// that takes a click, fails on the server, and snaps back under an error banner.
// A disabled control that says why answers the question in place.

const REASON = 'Devices will not accept this from a control plane yet.';

function render(props: Parameters<typeof PolicyPicker>[0]): string {
  return renderToStaticMarkup(createElement(PolicyPicker, props));
}

describe('PolicyPicker', () => {
  it('renders every archetype live when the host can assign them all', () => {
    const html = render({ value: 'redact', onChange: () => undefined });

    // Every archetype's own label, derived from the catalog rather than listed
    // here — a sixth one added tomorrow is covered without editing this. Via
    // policyMeta because the picker renders that, and asserting a literal '' for
    // the ids I did not spell out would have passed on all of them.
    for (const id of KNOWN_BUILTIN_IDS) {
      const label = policyMeta(id).label.replace('&', '&amp;');
      expect(html, `missing the ${id} option`).toContain(label);
    }
    // Nothing disabled, and no reason line, when nothing is restricted.
    expect(html).not.toContain('data-unavailable');
    expect(html).not.toContain('data-slot="policy-unavailable-reason"');
  });

  it('still OFFERS an unassignable archetype, disabled, rather than hiding it', () => {
    // Hiding turns "you cannot pick this here, because X" into "this does not
    // exist", and the reader's next move is to go looking for it.
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON },
    });

    expect(html).toContain('Redact &amp; Vault');
    expect(html).toContain('data-unavailable');
    expect(html).toContain('disabled');
  });

  it('says why, both on the control and in text beside it', () => {
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON },
    });

    // A disabled button is not focusable, so `title` alone is unreachable by
    // keyboard and invisible on touch. The line below the control is the
    // accessible copy of the same sentence, which is why both are asserted.
    expect(html).toContain(`title="${REASON}"`);
    expect(html).toContain('data-slot="policy-unavailable-reason"');
    expect(html).toContain(REASON);
  });

  it('leaves the other archetypes assignable', () => {
    // The restriction is per-option. Disabling the whole control because one
    // value is unavailable would take away the four choices that still work.
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON },
    });

    // One disabled button, not five.
    expect(html.match(/data-unavailable/g)?.length).toBe(1);
  });

  it('shows one reason line per distinct reason, not one per option', () => {
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON, block: REASON },
    });

    expect(html.match(/data-unavailable/g)?.length).toBe(2);
    expect(html.match(/data-slot="policy-unavailable-reason"/g)?.length).toBe(1);
  });

  it('is unchanged for a host that passes nothing', () => {
    // The OSS dashboard assigns against its own local store and knows of no
    // restriction. It must get exactly the control it had before this prop.
    const before = render({ value: 'redact', onChange: () => undefined });
    const after = render({ value: 'redact', onChange: () => undefined, unavailable: {} });
    expect(after).toBe(before);
  });

  it('does not make a read-only picker look restricted', () => {
    // No onChange is a different statement — the host has no write path at all,
    // not that one value is undeliverable. It must not sprout a reason line.
    const html = render({ value: 'redact' });
    expect(html).not.toContain('data-slot="policy-unavailable-reason"');
  });
});
