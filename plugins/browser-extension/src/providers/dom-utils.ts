// Shared DOM mechanics every contenteditable-composer adapter needs, so a new
// provider (providers/registry.ts) implements only its own selectors — not a
// second copy of "how do I read/write a contenteditable prompt box" or "how
// do I notice Enter-to-send".

export function firstMatch(selectors: string[]): HTMLElement | null {
  for (const selector of selectors) {
    const el = document.querySelector<HTMLElement>(selector);
    if (el) return el;
  }
  return null;
}

// Whether a composer holds its text in a `value` property rather than as child
// nodes. Both spellings are live: a contenteditable composer stores the prompt
// as rich-text DOM, while a `<textarea>` stores it in `value` and exposes its
// DEFAULT content — usually empty — through innerText and textContent. Reading
// the wrong one returns '' for a composer the user has typed into, and writing
// the wrong one leaves the original text in place.
function isValueBacked(el: HTMLElement): el is HTMLTextAreaElement | HTMLInputElement {
  return el.tagName === 'TEXTAREA' || el.tagName === 'INPUT';
}

// The `value` setter from the element's own prototype. Selected by tagName
// rather than `instanceof`, which compares against a realm's constructors.
function nativeValueSetter(
  el: HTMLTextAreaElement | HTMLInputElement,
): ((this: HTMLElement, value: string) => void) | undefined {
  const proto =
    el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  // Typed with an explicit receiver: the descriptor's own `set` carries none,
  // and every call below supplies one, which is the whole point of reaching for
  // the prototype's setter rather than the instance's.
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value') as
    { set?: (this: HTMLElement, value: string) => void } | undefined;
  return descriptor?.set;
}

// What the user sees they have typed, whichever kind of composer holds it.
export function extractComposerText(el: HTMLElement): string {
  return isValueBacked(el) ? el.value : el.innerText;
}

// Overwrites a composer's content with plain text and fires an `input` event so
// the site's own React/ProseMirror state picks up the change — a raw DOM
// mutation alone leaves the framework's internal model out of sync, and the
// next keystroke (or the send itself) could revert it.
//
// A value-backed composer is written through the PROTOTYPE's setter rather than
// by assigning to `el.value`. A framework may redefine `value` as an own
// accessor that caches what it last saw written, and compare that cache against
// the live value to decide whether an input event represents a real change;
// assigning updates the cache, so the framework concludes nothing changed and
// keeps its model of the original text. Going through the prototype leaves the
// cache stale, which is what makes the change observable. Falls back to
// assignment where no such descriptor exists.
export function setComposerText(el: HTMLElement, text: string): void {
  el.focus();
  if (isValueBacked(el)) {
    const setter = nativeValueSetter(el);
    if (setter) setter.call(el, text);
    else el.value = text;
  } else {
    el.textContent = text;
  }
  el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true }));
}

// Enter-without-Shift is the universal "send" gesture on every chat composer
// this package targets; Shift+Enter inserts a newline instead. `isComposing`
// is excluded so an IME candidate confirmation (Japanese/Chinese input) isn't
// mistaken for a send. A site-specific Send-button click is layered on top
// by each adapter.
export function watchEnterToSend(
  composer: HTMLElement,
  onSubmit: (event: Event) => void,
): () => void {
  const handler = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
    // This listener sees every keystroke on the page, so the composer it was
    // given is what decides whether one is a send. `contains` rather than an
    // identity check: a contenteditable's event target is often a descendant.
    const target = event.target;
    if (!(target instanceof Node) || !composer.contains(target)) return;
    onSubmit(event);
  };
  // Bound on the DOCUMENT, in the capture phase, rather than on the composer.
  //
  // An event's capture descent reaches every ancestor before the target, so a
  // site that handles Enter with a capture-phase listener ABOVE the composer
  // has already sent the message by the time a listener on the composer runs —
  // observed live, where sending with the button was intercepted and sending
  // with Enter was not. `document` is above every such root, so a capture
  // listener here is reached first whatever the site registered and in
  // whatever order.
  document.addEventListener('keydown', handler, true);
  return () => {
    document.removeEventListener('keydown', handler, true);
  };
}

export function watchButtonClick(
  button: HTMLElement,
  onSubmit: (event: Event) => void,
): () => void {
  button.addEventListener('click', onSubmit, true);
  return () => {
    button.removeEventListener('click', onSubmit, true);
  };
}
