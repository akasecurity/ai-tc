// @vitest-environment jsdom
//
// The Dismiss confirmation dialog, driven through real clicks.
//
// It needs a DOM for a reason that is not incidental: the dialog is PORTALLED,
// and Radix's Portal renders nothing at all on the server — so every server
// render of this card returns markup in which the dialog does not exist. A
// whole confirmation flow was therefore reachable by no assertion in this
// package, and the bug that found is the one this file opens with: the
// instruction naming the word to type sat inside a `uppercase` heading, so it
// read TYPE "DISMISS" while the gate compares exactly, and a reader following
// it could never enable the button.
import type { DismissRecommendation, RecommendedAction } from '@akasecurity/schema';
import { DISMISS_CONFIRMATION } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DISMISS_METHODS } from '../../src/security/dismiss-gate.ts';
import { RecommendedActionsCardView } from '../../src/security/RecommendedActionsCardView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const RULE = 'secrets/aws-access-key';

const ITEM: RecommendedAction = {
  id: 'local-secret',
  category: 'secret',
  severity: 'critical',
  title: 'Exposed secret detected',
  description: 'Rotate it.',
  subjects: [{ type: 'rule', id: RULE, label: `${RULE} · 3 findings` }],
  action: {
    mode: 'navigate',
    type: 'review_findings',
    label: 'Review findings',
    href: '/findings',
  },
};

let mounted: MountedRoot;
/** Every request the view handed to the host, in order. */
let requests: DismissRecommendation[];
/** What the next dismissal resolves to — the host's "did the write land?". */
let outcome: boolean;

beforeEach(() => {
  mounted = mountRoot();
  requests = [];
  outcome = true;
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

function render(props: { isMutating?: boolean; mutationError?: string | null } = {}): void {
  renderRoot(
    mounted.root,
    <RecommendedActionsCardView
      items={[ITEM]}
      isLoading={false}
      error={null}
      applyAction={() => undefined}
      dismissAction={(request) => {
        requests.push(request);
        return Promise.resolve(outcome);
      }}
      isMutating={props.isMutating ?? false}
      mutationError={props.mutationError ?? null}
    />,
  );
}

/** Every element in the document (portalled content included) matching `sel`. */
function all(sel: string): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>(sel)];
}

function byText(sel: string, text: string): HTMLElement | undefined {
  return all(sel).find((el) => el.textContent.trim() === text);
}

function click(el: Element | undefined): void {
  expect(el, 'element to click was not found').toBeDefined();
  act(() => {
    (el as HTMLElement).click();
  });
}

/**
 * Let the host's promise settle and React re-render on the result.
 *
 * `dismissAction` resolves in a microtask, which lands AFTER the `act()` block
 * that dispatched the click — so a close-on-success assertion made straight
 * after `click` reads the dialog one tick before it goes.
 */
async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
}

function openDialog(): void {
  render();
  click(byText('button', 'Dismiss'));
}

/** The confirmation text box inside the open dialog. */
function confirmationInput(): HTMLInputElement {
  const input = document.querySelector<HTMLInputElement>('[data-slot="dismiss-confirmation"]');
  // Thrown rather than asserted-and-cast: a throw narrows the type, where an
  // `expect` leaves it nullable and a cast past it would be a claim the
  // compiler cannot check.
  if (input === null) throw new Error('the confirmation input is not in the document');
  return input;
}

/** The danger button that performs the write. */
function confirmButton(): HTMLButtonElement {
  const button = byText('button', 'Dismiss findings') ?? byText('button', 'Dismissing…');
  expect(button, 'the confirm button is not in the document').toBeDefined();
  return button as HTMLButtonElement;
}

/**
 * Type `value` into the confirmation box the way a person does.
 *
 * The value goes through the PROTOTYPE's setter before the event is dispatched.
 * React installs its own value tracker on the element and skips a change event
 * whose value it believes it already has, so `input.value = x` followed by a
 * dispatch updates the DOM while the component's state stays empty — the box
 * looks filled and the gate never arms. Measured rather than assumed: with the
 * plain assignment, four of this file's cases fail, and every one of them is a
 * case that types into this box.
 */
const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

function type(value: string): void {
  const input = confirmationInput();
  // A property descriptor's `set` is a plain function reached off an object, not
  // a class method that could lose its receiver — and `Reflect.apply` below
  // supplies the receiver explicitly, which is the thing the rule exists to
  // ensure. There is no way to drive a React-controlled input without it.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const setter = valueDescriptor?.set;
  if (setter === undefined) {
    throw new Error('HTMLInputElement has no value setter — the typing helper cannot work');
  }
  act(() => {
    Reflect.apply(setter, input, [value]);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

describe('the instruction a reader follows', () => {
  it('shows the confirmation word in the case the gate accepts', () => {
    openDialog();
    const hint = document.querySelector<HTMLElement>('[data-slot="dismiss-confirmation-hint"]');
    expect(hint).not.toBeNull();
    // The word itself, exactly. `toContain` on the lower-cased text would pass
    // on a hint rendering DISMISS, which is the defect.
    expect(hint?.textContent).toContain(DISMISS_CONFIRMATION);
  });

  it('renders that instruction outside every uppercased element', () => {
    // `uppercase` is a CSS transform, so the DOM text stays lower-case and the
    // check above cannot see the bug at all — only the class can. An ancestor
    // carrying it is the same defect as the element carrying it, so the whole
    // chain up to the dialog is walked.
    openDialog();
    const hint = document.querySelector<HTMLElement>('[data-slot="dismiss-confirmation-hint"]');
    for (let el = hint; el !== null; el = el.parentElement) {
      expect(el.classList.contains('uppercase'), `"${el.className}" uppercases the hint`).toBe(
        false,
      );
    }
  });

  it('keeps the uppercased heading beside it — the fix is placement, not styling', () => {
    // The control. Removing `uppercase` everywhere would also pass the case
    // above while losing the section heading this dialog shares with the rest of
    // the dashboard, so the heading is pinned as still uppercased.
    openDialog();
    const heading = document.querySelector<HTMLElement>('#dismiss-confirmation-label');
    expect(heading?.classList.contains('uppercase')).toBe(true);
    expect(heading?.textContent).not.toContain(DISMISS_CONFIRMATION);
  });
});

describe('choosing a disposition', () => {
  it('offers every method as a radio, in one group', () => {
    openDialog();
    const radios = all('input[type="radio"]');
    expect(radios).toHaveLength(DISMISS_METHODS.length);
    // One `name`, so the browser treats them as a single group and gives arrow
    // -key movement and a grouped announcement for free.
    expect(new Set(radios.map((r) => r.getAttribute('name'))).size).toBe(1);
    expect(document.querySelector('[role="radiogroup"]')).not.toBeNull();
  });

  it('shows EVERY option description at once, not only the chosen one', () => {
    // The reason this is a radio list. With one help line under a segmented
    // control a reader had to pick an answer to find out what it meant — and
    // the two answers differ in what they CLAIM, not in presentation.
    openDialog();
    const text = document.body.textContent;
    for (const m of DISMISS_METHODS) {
      expect(text).toContain(m.description);
    }
  });

  it('starts with nothing chosen', () => {
    // No default: a pre-selected disposition is one the reader never made, and
    // it would be recorded against every finding the dismissal closes.
    openDialog();
    expect(all('input[type="radio"]').every((r) => !(r as HTMLInputElement).checked)).toBe(true);
    expect(confirmButton().disabled).toBe(true);
  });

  it('sends the method the reader picked', () => {
    openDialog();
    const second = DISMISS_METHODS[1];
    // Clicked through the radio itself rather than its label text, so the case
    // does not depend on where inside the card a click lands.
    click(all('input[type="radio"]')[1]);
    type(DISMISS_CONFIRMATION);
    click(confirmButton());
    expect(requests).toEqual([
      { ruleId: RULE, method: second?.value, confirmation: DISMISS_CONFIRMATION },
    ]);
  });
});

describe('the confirmation gate', () => {
  it('stays disabled until BOTH a method and the exact word are given', () => {
    openDialog();
    expect(confirmButton().disabled).toBe(true);

    click(all('input[type="radio"]')[0]);
    expect(confirmButton().disabled, 'a method alone must not arm it').toBe(true);

    type(DISMISS_CONFIRMATION);
    expect(confirmButton().disabled).toBe(false);
  });

  it('refuses a capitalized word — the case the uppercase heading used to invite', () => {
    openDialog();
    click(all('input[type="radio"]')[0]);
    type(DISMISS_CONFIRMATION.toUpperCase());
    expect(confirmButton().disabled).toBe(true);
    // The control: the same box with the right case arms it, so what is refused
    // is the case rather than the typing.
    type(DISMISS_CONFIRMATION);
    expect(confirmButton().disabled).toBe(false);
  });

  it('writes nothing while it is disabled', () => {
    openDialog();
    click(confirmButton());
    expect(requests).toEqual([]);
  });
});

describe('what happens after the host answers', () => {
  function arm(): void {
    openDialog();
    click(all('input[type="radio"]')[0]);
    type(DISMISS_CONFIRMATION);
  }

  it('closes on a write that landed', async () => {
    outcome = true;
    arm();
    click(confirmButton());
    await settle();
    expect(document.querySelector('[data-slot="dismiss-confirmation"]')).toBeNull();
  });

  it('stays open on a refusal, keeping what was typed', async () => {
    // `isMutating` falls back to false on a refusal exactly as on a success, so
    // a dialog that closed either way would report a refused dismissal as a
    // completed one — and the row it was opened from is still there.
    outcome = false;
    arm();
    click(confirmButton());
    await settle();
    const input = document.querySelector<HTMLInputElement>('[data-slot="dismiss-confirmation"]');
    expect(input).not.toBeNull();
    expect(input?.value).toBe(DISMISS_CONFIRMATION);
  });

  it('shows the host error inside the dialog, not behind its overlay', () => {
    render({ mutationError: 'The local store refused the write.' });
    click(byText('button', 'Dismiss'));
    const dialog = document.querySelector<HTMLElement>('[data-slot="dialog-content"]');
    expect(dialog?.textContent).toContain('The local store refused the write.');
  });

  it('disables both the confirm and the cancel while a write is in flight', () => {
    // Closing the dialog does not cancel the write, so a dismissal would land
    // with nothing on screen saying it had.
    //
    // Opened BEFORE the in-flight re-render, because the row's own Dismiss
    // button is disabled while mutating too — rendering straight into that state
    // leaves no way to open the dialog, and the case would fail for the wrong
    // reason. Same root, so the dialog stays open across the re-render.
    openDialog();
    render({ isMutating: true });
    expect(confirmButton().disabled).toBe(true);
    expect((byText('button', 'Cancel') as HTMLButtonElement | undefined)?.disabled).toBe(true);
  });
});

describe('cancelling', () => {
  it('closes without asking the host to write anything', () => {
    openDialog();
    click(all('input[type="radio"]')[0]);
    type(DISMISS_CONFIRMATION);
    click(byText('button', 'Cancel'));
    expect(requests).toEqual([]);
    expect(document.querySelector('[data-slot="dismiss-confirmation"]')).toBeNull();
  });

  it('forgets what was typed, so a later dismissal starts from nothing', () => {
    // A retained confirmation would arm the button for the NEXT row the instant
    // its dialog opened, which is the gate not being a gate.
    openDialog();
    click(all('input[type="radio"]')[0]);
    type(DISMISS_CONFIRMATION);
    click(byText('button', 'Cancel'));

    click(byText('button', 'Dismiss'));
    expect(confirmationInput().value).toBe('');
    expect(all('input[type="radio"]').every((r) => !(r as HTMLInputElement).checked)).toBe(true);
    expect(confirmButton().disabled).toBe(true);
  });
});
