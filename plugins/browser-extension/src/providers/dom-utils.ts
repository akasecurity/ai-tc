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

// contenteditable composers store the prompt as rich-text DOM (paragraphs,
// line breaks), not a `value` property — innerText is the closest analogue
// to "what the user sees they've typed".
export function extractContentEditableText(el: HTMLElement): string {
  return el.innerText;
}

// Overwrites a contenteditable composer's content with plain text and fires
// an `input` event so the site's own React/ProseMirror state picks up the
// change — a raw DOM mutation alone leaves the framework's internal model
// out of sync, and the next keystroke (or the send itself) could revert it.
export function setContentEditableText(el: HTMLElement, text: string): void {
  el.focus();
  el.textContent = text;
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
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      onSubmit(event);
    }
  };
  composer.addEventListener('keydown', handler, true);
  return () => {
    composer.removeEventListener('keydown', handler, true);
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
