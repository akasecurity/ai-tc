// String → SVG-component registry for the data-driven <Ico> used by the Inventory
// views. Inventory data descriptors (asset tiles, flag/access/trust meta, event
// kinds) carry a plain icon-name string and the UI resolves it here. Mapped onto
// the shared @akasecurity/dashboard-ui icon set so the module stays bundler-agnostic
// (no svgr). A few names without a dedicated glyph map to the closest shared icon.
import type { IconComponent } from '../lib/icons.ts';
import {
  AlertIcon,
  ArrowUpIcon,
  BoltIcon,
  BranchIcon,
  CheckCircleIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ClockIcon,
  CloudIcon,
  CodeIcon,
  DatabaseIcon,
  EditIcon,
  EyeIcon,
  EyeOffIcon,
  FileIcon,
  FlagIcon,
  FolderIcon,
  GlobeIcon,
  InfoIcon,
  LayersIcon,
  ListIcon,
  LockIcon,
  RedactIcon,
  RefreshIcon,
  RepoIcon,
  RouteIcon,
  SearchIcon,
  ServerIcon,
  SettingsIcon,
  ShieldCheckIcon,
  SlashCircleIcon,
  SlidersIcon,
  SparklesIcon,
  SwapIcon,
  TerminalIcon,
  XIcon,
} from '../shared/icons.tsx';

const ICONS = {
  alert: AlertIcon,
  'arrow-up': ArrowUpIcon,
  bolt: BoltIcon,
  book: FileIcon,
  branch: BranchIcon,
  check: CheckIcon,
  'check-circle': CheckCircleIcon,
  'chevron-down': ChevronDownIcon,
  'chevron-right': ChevronRightIcon,
  clock: ClockIcon,
  cloud: CloudIcon,
  code: CodeIcon,
  database: DatabaseIcon,
  edit: EditIcon,
  eye: EyeIcon,
  'eye-off': EyeOffIcon,
  file: FileIcon,
  flag: FlagIcon,
  folder: FolderIcon,
  globe: GlobeIcon,
  help: InfoIcon,
  layers: LayersIcon,
  list: ListIcon,
  lock: LockIcon,
  redact: RedactIcon,
  refresh: RefreshIcon,
  repo: RepoIcon,
  route: RouteIcon,
  search: SearchIcon,
  server: ServerIcon,
  settings: SettingsIcon,
  'shield-check': ShieldCheckIcon,
  'slash-circle': SlashCircleIcon,
  sliders: SlidersIcon,
  sparkles: SparklesIcon,
  swap: SwapIcon,
  terminal: TerminalIcon,
  x: XIcon,
  'x-circle': SlashCircleIcon,
} satisfies Record<string, IconComponent>;

export type IconName = keyof typeof ICONS;

/** Resolve an icon by its data-driven name. */
export function iconFor(name: IconName): IconComponent {
  return ICONS[name];
}
