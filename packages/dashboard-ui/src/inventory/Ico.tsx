// Data-driven icon: renders a shared SVG-icon component looked up by its string
// name (see ./icons.ts). Used where the icon identity comes from inventory data
// descriptors rather than being fixed at author time. Uses createElement (not a
// `const Icon = …; <Icon/>` binding) so it never trips the "no components created
// during render" lint — the component comes from a constant registry.
import { cn } from '@akasecurity/ui-kit';
import { createElement } from 'react';

import { iconFor, type IconName } from './icons.ts';

export function Ico({ name, className }: { name: IconName; className?: string }) {
  return createElement(iconFor(name), {
    'aria-hidden': true,
    focusable: false,
    className: cn('size-4', className),
  });
}
