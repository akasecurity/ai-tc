import { type ClassValue, clsx } from 'clsx';
import { extendTailwindMerge } from 'tailwind-merge';

// Register our custom font-size utilities (theme.css) so tailwind-merge treats
// them as sizes, not colors — otherwise `text-ui`/`text-label` get dropped when
// merged alongside a `text-{color}` class.
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      'font-size': [{ text: ['ui', 'label'] }],
    },
  },
});

/** Merge conditional class names, resolving Tailwind conflicts last-wins. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
