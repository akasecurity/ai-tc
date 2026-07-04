// Inlined line icons for @akasecurity/dashboard-ui. The package is bundler-agnostic
// (no Vite/Next svgr asset imports), so every icon the shared views need is
// inlined here as a plain SVG component — a single source of truth rather than
// per-domain files that re-export each other. Paths are shared
// so every host renders identically. Each spreads SVG
// props last so a consumer's className (e.g. `size-4`) and aria attributes win.
import type { IconComponent } from '../lib/icons.ts';

// A 24-grid stroked line icon. width/height are defaults a `size-*` className overrides.
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

export const AlertOctagonIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M8 2.5h8L21.5 8v8L16 21.5H8L2.5 16V8L8 2.5Z" />
    <path d="M12 8v4" />
    <circle cx="12" cy="16" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const SlashCircleIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="m6 6 12 12" />
  </svg>
);

export const RedactIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="3" y="9" width="18" height="6" rx="1.5" fill="currentColor" stroke="none" />
    <path d="M3 5h18M3 19h12" />
  </svg>
);

export const ExternalShareIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M14 4h6v6" />
    <path d="M20 4 11 13" />
    <path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
  </svg>
);

export const ArrowUpIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 19V5M6 11l6-6 6 6" />
  </svg>
);

export const ArrowRightIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </svg>
);

export const ArrowDownIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 5v14M6 13l6 6 6-6" />
  </svg>
);

export const AnalyticsIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
  </svg>
);

export const ShieldCheckIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 3 4.5 6v5.5c0 4.6 3.2 7.6 7.5 9 4.3-1.4 7.5-4.4 7.5-9V6L12 3Z" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);

export const TargetIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="4.5" />
    <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const UserIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="8" r="3.6" />
    <path d="M5.5 20a6.5 6.5 0 0 1 13 0" />
  </svg>
);

export const BranchIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 8.4v7.2" />
    <circle cx="6" cy="6" r="2.4" />
    <circle cx="6" cy="18" r="2.4" />
    <circle cx="18" cy="7" r="2.4" />
    <path d="M18 9.4a8.6 8.6 0 0 1-8.6 8.6" />
  </svg>
);

export const SparklesIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 3.5 13.6 9 19 10.5 13.6 12 12 17.5 10.4 12 5 10.5 10.4 9 12 3.5Z" />
    <path d="M18 16.5 18.7 19 21 19.7 18.7 20.4 18 23 17.3 20.4 15 19.7 17.3 19 18 16.5Z" />
  </svg>
);

// ─── Category icons ──────────────────────────────────────────────────────────

export const KeyIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="8" cy="12" r="4" />
    <path d="M11.5 12H21l-2 2.4M16.5 12v3" />
  </svg>
);

export const CodeIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12" />
  </svg>
);

export const ServerIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="4" y="4" width="16" height="7" rx="2" />
    <rect x="4" y="13" width="16" height="7" rx="2" />
    <circle cx="8" cy="7.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="8" cy="16.5" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const DatabaseIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <ellipse cx="12" cy="6" rx="7" ry="3" />
    <path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6" />
    <path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" />
  </svg>
);

// ─── Action icons ────────────────────────────────────────────────────────────

export const AlertIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 3 2 20h20L12 3Z" />
    <path d="M12 9v5" />
    <circle cx="12" cy="17" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const FlagIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M5 21V4M5 4h11l-2 3 2 3H5" />
  </svg>
);

export const CheckIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m5 12 4.5 4.5L19 7" />
  </svg>
);

export const EyeIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
    <circle cx="12" cy="12" r="2.6" />
  </svg>
);

export const ShieldIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 3 4.5 6v5.5c0 4.6 3.2 7.6 7.5 9 4.3-1.4 7.5-4.4 7.5-9V6L12 3Z" />
  </svg>
);

export const LayersIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m12 3 9 5-9 5-9-5 9-5Z" />
    <path d="m3 13 9 5 9-5M3 16.5l9 5 9-5" />
  </svg>
);

// ─── Toolbar / table / detail chrome ─────────────────────────────────────────

export const SearchIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.2-3.2" />
  </svg>
);

export const ChevronDownIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m6 9 6 6 6-6" />
  </svg>
);

export const CalendarIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="4" y="5" width="16" height="16" rx="2" />
    <path d="M4 9h16M8 3v4M16 3v4" />
  </svg>
);

export const ChevronRightIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m9 6 6 6-6 6" />
  </svg>
);

export const ChevronLeftIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="m15 6-6 6 6 6" />
  </svg>
);

export const SlidersIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M4 8h10M18 8h2M4 16h2M10 16h10" />
    <circle cx="16" cy="8" r="2.2" />
    <circle cx="8" cy="16" r="2.2" />
  </svg>
);

export const EyeOffIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M4 4 20 20" />
    <path d="M9.5 9.6A2.6 2.6 0 0 0 12 14.6c.7 0 1.3-.25 1.8-.7M6.5 6.7C3.8 8.3 2.5 12 2.5 12S6 18.5 12 18.5c1.5 0 2.8-.4 4-1M17.5 17.3C20.2 15.7 21.5 12 21.5 12S18 5.5 12 5.5c-.5 0-1 0-1.4.1" />
  </svg>
);

export const BracesIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M8 4c-2 0-2 2-2 4s0 3-2 4c2 1 2 2 2 4s0 4 2 4M16 4c2 0 2 2 2 4s0 3 2 4c-2 1-2 2-2 4s0 4-2 4" />
  </svg>
);

export const FingerprintIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4" />
    <path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2" />
    <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
    <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
    <path d="M8.65 22c.21-.66.45-1.32.57-2" />
    <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
    <path d="M2 16h.01" />
    <path d="M21.8 16c.2-2 .13-5.354 0-6" />
    <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
  </svg>
);

export const GlobeIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18" />
    <path d="M12 3c2.6 2.6 2.6 15.4 0 18M12 3c-2.6 2.6-2.6 15.4 0 18" />
  </svg>
);

export const BuildingIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M4 21V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v16" />
    <path d="M15 9h4a1 1 0 0 1 1 1v11" />
    <path d="M3 21h18" />
    <path d="M8 8h3M8 12h3M8 16h3" />
  </svg>
);

export const MoreVertIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="5" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    <circle cx="12" cy="19" r="1.4" fill="currentColor" stroke="none" />
  </svg>
);

export const PlusIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 5v14M5 12h14" />
  </svg>
);

export const CheckCircleIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="m8.5 12 2.3 2.3 4.7-4.6" />
  </svg>
);

export const XIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 6 18 18M18 6 6 18" />
  </svg>
);

export const ListIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M8 6h12M8 12h12M8 18h12" />
    <circle cx="3.6" cy="6" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="3.6" cy="12" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="3.6" cy="18" r="1.1" fill="currentColor" stroke="none" />
  </svg>
);

// ─── Transport icons ─────────────────────────────────────────────────────────

export const LockIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="5" y="11" width="14" height="9" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </svg>
);

export const UploadIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 20V9M7 13l5-5 5 5M5 4h14" />
  </svg>
);

export const RouteIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="6" cy="18" r="2.4" />
    <path d="M8.4 18H16a3 3 0 0 0 0-6H8a3 3 0 0 1 0-6h7.6" />
    <circle cx="18" cy="6" r="2.4" />
  </svg>
);

export const InboxIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 13h5l1.5 3h5L16 13h5" />
    <path d="M5 5h14l2 8v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-5L5 5Z" />
  </svg>
);

// ─── Data-classification icons ───────────────────────────────────────────────

export const PulseIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 12h3l2-5 4 14 3-9 2 2h4" />
  </svg>
);

export const ActivityIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 12h4l3 8 4-16 3 8h4" />
  </svg>
);

export const InfoIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5" />
    <circle cx="12" cy="7.7" r="1" fill="currentColor" stroke="none" />
  </svg>
);

// ─── Destination-mark & chrome icons ─────────────────────────────────────────

export const PinIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 21s7-6.3 7-11a7 7 0 1 0-14 0c0 4.7 7 11 7 11Z" />
    <circle cx="12" cy="10" r="2.4" />
  </svg>
);

export const RepoIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 3h11a1 1 0 0 1 1 1v17l-3-2-3 2-3-2-3 2V4a1 1 0 0 1 1-1Z" />
    <path d="M9 8h6M9 12h5" />
  </svg>
);

export const ArrowUpRightIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M7 17 17 7M8 7h9v9" />
  </svg>
);

export const PolicyIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 3h9l3 3v15H6z" />
    <path d="M15 3v3h3" />
    <path d="M9 12h6M9 16h4" />
  </svg>
);

// ─── LLM Providers hosting / chrome icons ────────────────────────────────────

export const CloudIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M7 18a4 4 0 0 1-.5-7.97A5.5 5.5 0 0 1 17 9.5a3.75 3.75 0 0 1 .5 7.5H7Z" />
  </svg>
);

export const LaptopIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="3" y="5" width="18" height="11" rx="1.5" />
    <path d="M2 20h20" />
  </svg>
);

export const SettingsIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2Z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

// ─── Activity / audit-log chrome ─────────────────────────────────────────────

export const TerminalIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="m7 9 3 3-3 3M13 15h4" />
  </svg>
);

export const ClockIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7.5V12l3 2" />
  </svg>
);

export const BoltIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" />
  </svg>
);

export const EditIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M4 20h4L19 9l-4-4L4 16v4Z" />
    <path d="m14 6 4 4" />
  </svg>
);

export const FileIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M6 3h8l4 4v14H6z" />
    <path d="M14 3v4h4" />
  </svg>
);

export const FolderIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
  </svg>
);

export const RefreshIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
    <path d="M3 21v-5h5" />
  </svg>
);

export const SwapIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M7 4 3 8l4 4" />
    <path d="M3 8h14" />
    <path d="m17 20 4-4-4-4" />
    <path d="M21 16H7" />
  </svg>
);

export const DownloadIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M12 4v11M7 11l5 5 5-5M5 20h14" />
  </svg>
);

// ─── Operations dashboard chrome ─────────────────────────────────────────────

export const FlowIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <circle cx="5" cy="6" r="2.4" />
    <circle cx="5" cy="18" r="2.4" />
    <circle cx="19" cy="12" r="2.4" />
    <path d="M7.3 7 16.8 11M7.3 17 16.8 13" />
  </svg>
);

export const IntegrationsIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M14 7h3a3 3 0 0 1 3 3v0a3 3 0 0 1-3 3h-3M10 7H7a3 3 0 0 0-3 3v0a3 3 0 0 0 3 3h3" />
    <path d="M9 10h6" />
  </svg>
);

export const LinkIcon: IconComponent = (props) => (
  <svg {...base} {...props}>
    <path d="M9 15 15 9" />
    <path d="M11 6.5 12.5 5a3.5 3.5 0 0 1 5 5l-1.5 1.5M13 17.5 11.5 19a3.5 3.5 0 0 1-5-5L8 12.5" />
  </svg>
);
