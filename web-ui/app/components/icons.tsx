import type { IconComponent } from '@akasecurity/dashboard-ui';

// Icons that already exist in @akasecurity/dashboard-ui are re-exported here (not
// re-declared) so the AppShell keeps a single import site and the SVG paths live
// in one place.
export {
  BoltIcon,
  BracesIcon,
  ExternalShareIcon,
  LayersIcon,
  SearchIcon,
  ShieldCheckIcon,
  TerminalIcon,
  XIcon,
} from '@akasecurity/dashboard-ui';

// Nav/brand icons unique to the OSS shell. web-ui pulls in no svgr, so these are
// inlined as plain SVG components (same approach as @akasecurity/dashboard-ui's
// security/icons). Each spreads SVG props last so a consumer's className
// (e.g. `size-4`) wins over the defaults.

// Shared <svg> attributes — a 24-grid stroked line icon. width/height are
// defaults that a `size-*` className overrides via CSS.
const base = {
  xmlns: 'http://www.w3.org/2000/svg',
  width: 24,
  height: 24,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.6,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
} as const;

export const ListIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M8 6h12M8 12h12M8 18h12" />
    <circle cx="3.6" cy="6" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="3.6" cy="12" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="3.6" cy="18" r="1.1" fill="currentColor" stroke="none" />
  </svg>
);

export const ActivityIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 12h4l3 8 4-16 3 8h4" />
  </svg>
);

export const KeyIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="M10.7 12.3 21 2M15 8l3 3M18 5l3 3" />
  </svg>
);

export const RefreshIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M21 12a9 9 0 1 1-2.64-6.36" />
    <path d="M21 3v6h-6" />
  </svg>
);

export const SettingsIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.11-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.11 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.08A1.7 1.7 0 0 0 10.12 3V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.08a1.7 1.7 0 0 0 1.56 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.56 1.03Z" />
  </svg>
);

export const PolicyIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 3h9l3 3v15H6z" />
    <path d="M15 3v3h3" />
    <path d="M9 12h6M9 16h4" />
  </svg>
);

// AKA wordmark — inlined so the shell needs no SVG asset loader.
export const AkaLogo: IconComponent = (props) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={510}
    height={236}
    viewBox="0 0 510 236"
    fill="none"
    {...props}
  >
    <path
      d="M329.798 26H302.492V169.68H329.798V126.99H344.796L374.425 169.57H405.11L364.293 113.206L403.6 65.6621H371.909L343.689 101.616H329.798V26.0042V26Z"
      fill="#1B1F24"
    />
    <path
      d="M224.398 172C234.998 172 247.996 167.417 254.994 155.653H255.595V169.607H282.394V66.5446H255.595V80.2995H254.994C247.996 68.5362 234.994 63.7539 224.398 63.7539C194.799 63.7539 178 88.6717 178 117.776C178 146.879 194.799 172 224.398 172ZM205.802 117.776C205.802 101.031 213.201 85.2805 230.998 85.2805C248.796 85.2805 256.195 101.031 256.195 117.776C256.195 134.52 248.796 150.469 230.998 150.469C213.201 150.469 205.802 134.52 205.802 117.776Z"
      fill="#1B1F24"
    />
    <path
      d="M452.006 172C462.606 172 475.604 167.417 482.602 155.653H483.203V169.607H510.002V66.5446H483.203V80.2995H482.602C475.604 68.5362 462.602 63.7539 452.006 63.7539C422.407 63.7539 405.608 88.6717 405.608 117.776C405.608 146.879 422.407 172 452.006 172ZM433.409 117.776C433.409 101.031 440.809 85.2805 458.606 85.2805C476.403 85.2805 483.803 101.031 483.803 117.776C483.803 134.52 476.403 150.469 458.606 150.469C440.809 150.469 433.409 134.52 433.409 117.776Z"
      fill="#1B1F24"
    />
    <path
      d="M54 118H0C0 88.3759 24.3759 64 54 64C83.6241 64 108 88.3759 108 118H54Z"
      fill="#1B1F24"
    />
    <path
      d="M54 118H108C108 147.624 83.6241 172 54 172C24.3759 172 0 147.624 0 118H54Z"
      fill="#00E0B8"
    />
    <path
      d="M81 54C95.9117 54 108 41.9117 108 27C108 12.0883 95.9117 0 81 0C66.0883 0 54 12.0883 54 27C54 41.9117 66.0883 54 81 54Z"
      fill="#1B1F24"
    />
    <path
      d="M27 236C41.9117 236 54 223.912 54 209C54 194.088 41.9117 182 27 182C12.0883 182 0 194.088 0 209C0 223.912 12.0883 236 27 236Z"
      fill="#00E0B8"
    />
  </svg>
);
