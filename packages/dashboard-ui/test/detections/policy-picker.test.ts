import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { createElement, Fragment } from 'react';
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

/**
 * The whole element carrying `id`, open tag through close.
 *
 * String slicing rather than a RegExp, deliberately: every caller's id comes
 * from useId(), and building a pattern out of one is a hand-rolled escaping
 * step — the category this file removed from the label assertions. indexOf
 * takes the id as a literal whatever characters React puts in it.
 */
function reasonParagraph(html: string, id: string): string {
  const at = html.indexOf(`id="${id}"`);
  if (at === -1) return '';
  return html.slice(html.lastIndexOf('<', at), html.indexOf('</p>', at) + 4);
}

describe('PolicyPicker', () => {
  it('renders every archetype live when the host can assign them all', () => {
    const html = render({ value: 'redact', onChange: () => undefined });

    // Every archetype's own label, derived from the catalog rather than listed
    // here — a sixth one added tomorrow is covered without editing this. Via
    // policyMeta because the picker renders that, and asserting a literal '' for
    // the ids I did not spell out would have passed on all of them.
    //
    // The EXPECTATION is escaped by the renderer rather than by hand. Escaping
    // '&' with a string-argument replace fixed only the first occurrence and
    // covered only that one character, so a future label with two ampersands —
    // or with '<' — would build an expected string React never emits, failing
    // against correct markup and pointing at the component instead of at this
    // line. That is the specific way the promise above stops being kept. A
    // Fragment renders the label and nothing around it, so what is searched for
    // cannot drift from what React actually produces for that text.
    for (const id of KNOWN_BUILTIN_IDS) {
      const label = renderToStaticMarkup(createElement(Fragment, null, policyMeta(id).label));
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
    // `aria-disabled`, NOT the native attribute — and asserted precisely,
    // because `toContain('disabled')` matches the aria form too and would pass
    // whichever one the component emitted.
    expect(html).toContain('aria-disabled="true"');
    expect(html).not.toContain('disabled=""');
  });

  it('keeps an unassignable option in the tab order, described by its reason', () => {
    // The reason for this state existing is that the reason REACHES the person
    // who wanted that archetype. A natively disabled button leaves the tab
    // order, so a keyboard or screen-reader user never lands on it and never
    // hears why — `title` alone does not reach them either.
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON },
    });

    const describedBy = /aria-describedby="([^"]+)"/.exec(html);
    expect(describedBy, 'the unavailable option describes nothing').not.toBeNull();
    // And it points at an element actually in the markup — an id referencing
    // nothing announces nothing, and reads identically here.
    expect(html).toContain(`id="${describedBy?.[1] ?? ''}"`);
    // Via a string slice rather than a RegExp built from the captured id: that
    // id is a useId() output, so interpolating it into a pattern hand-rolls an
    // escaping step whose correctness depends on what React decides an id looks
    // like — `identifierPrefix` is a render option, and this is the same
    // category the label assertion above stopped hand-rolling.
    expect(reasonParagraph(html, describedBy?.[1] ?? '')).toContain(
      'data-slot="policy-unavailable-reason"',
    );
  });

  it('still uses the NATIVE disabled attribute for a read-only picker', () => {
    // The whole-control case is different from the per-option one: there is no
    // reason to convey, so keeping these out of the tab order is right.
    const html = render({ value: 'redact' });
    expect(html).toContain('disabled=""');
  });

  it('says why, both on the control and in text beside it', () => {
    const html = render({
      value: 'redact',
      onChange: () => undefined,
      unavailable: { vault: REASON },
    });

    // `title` is invisible on touch and unreliable for assistive tech, so the
    // line below the control is the accessible copy of the same sentence —
    // and the one `aria-describedby` points at. Both are asserted because they
    // reach different people.
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
    //
    // Driven WITH `unavailable`, because without it this holds however the
    // component treats the pair — the combination is the only thing that can
    // fail, and asserting it over a picker that was given no restriction proved
    // nothing about the sentence above.
    const html = render({ value: 'redact', unavailable: { vault: REASON } });
    expect(html).not.toContain('data-slot="policy-unavailable-reason"');
    expect(html).not.toContain(REASON);
    expect(html).not.toContain('data-unavailable');
    // And no dangling description: natively disabled is not focusable, so an
    // aria-describedby here would point a keyboard user at nothing they can
    // reach — the exact failure dropping the native attribute elsewhere avoids.
    expect(html).not.toContain('aria-describedby');
  });

  it('points each option at ITS OWN reason when two differ', () => {
    // `reasons.indexOf(reason)` is the mapping, and one shared reason cannot
    // tell a correct index from a constant — both buttons would point at the
    // one line either way. Two DISTINCT reasons is the case that can fail.
    const OTHER = 'This deployment has not enabled that archetype.';
    const html = render({
      value: 'monitor',
      onChange: () => undefined,
      unavailable: { vault: REASON, block: OTHER },
    });

    const ids = [...html.matchAll(/aria-describedby="([^"]+)"/g)].map((m) => m[1]);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size, 'both options point at the same line').toBe(2);
    // Each id names the paragraph carrying its own sentence, not merely some
    // paragraph — a swapped pair would satisfy every count above.
    expect(html.match(/data-slot="policy-unavailable-reason"/g)).toHaveLength(2);
    for (const [id, reason] of [
      [ids[0], REASON],
      [ids[1], OTHER],
    ] as const) {
      expect(reasonParagraph(html, id ?? '')).toContain(reason);
    }
  });
});
