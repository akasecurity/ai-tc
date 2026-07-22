// @akasecurity/dashboard-ui — shared presentational composites for the AKA
// dashboard surfaces (the Next.js web-ui, plus anything else that renders the
// same views). Built on @akasecurity/ui-kit primitives; bundler-agnostic (no
// svgr/asset imports). Data-fetching stays in the apps — these take data via props.
export { COLORS } from './lib/colors.ts';
export type { IconComponent } from './lib/icons.ts';
export { relativeTime, relativeTimeShort } from './lib/relativeTime.ts';
export {
  BLOCKED_WINDOW_MS,
  BLOCKED_WINDOW_PHRASE,
  BLOCKED_WINDOWS,
  type BlockedWindow,
  type BlockedWindowOption,
  DEFAULT_BLOCKED_WINDOW,
  DEFAULT_TIME_RANGE,
  RANGE_DAYS,
  rangeToFromIso,
  resolveBlockedWindow,
  TIME_RANGE_OPTIONS,
  type TimeRange,
  type TimeRangeOption,
} from './lib/timeRanges.ts';
export {
  AreaChart,
  type AreaSeries,
  Donut,
  type DonutSegment,
  Sparkline,
  useMeasuredWidth,
} from './shared/charts.tsx';
export { PageHead } from './shared/PageHead.tsx';
export { Provider, type ProviderId, type ProviderMeta, PROVIDERS } from './shared/Provider.tsx';
export { type StatDelta, StatTile } from './shared/StatTile.tsx';
export { TimeRangeSelect } from './shared/TimeRangeSelect.tsx';
export { WidgetEmpty, WidgetError } from './shared/widget-state.tsx';

// Shared detail-pane primitives (section headings, label/value rows) reused by
// every detail view and by app-injected footers.
export { MetaItem, SectionLabel } from './shared/DetailFields.tsx';

// Activity views — props-driven (no data fetching). All domain shapes are the
// @akasecurity/schema /v1/activity contract types (ActivitySession, ActivitySessionSummary,
// AuditEvent, Harness…); the views consume them directly. Presentation — event/
// status styling, the harness/kind vocabularies — lives in activity/meta.ts, and
// the semantic → display derivations (day grouping, time/duration/token labels)
// in activity/format.ts.
export {
  ActivitySummaryStripView,
  type SummaryStatItem,
} from './activity/ActivitySummaryStripView.tsx';
export { ActivityTokenUsageView } from './activity/ActivityTokenUsageView.tsx';
export { MetaChips, Metric, SessionStatusBadge, StatusDot, ToolChip } from './activity/atoms.tsx';
export { AuditTimelineView, type BuildActivityLinkHref } from './activity/AuditTimelineView.tsx';
export {
  cacheHitPct,
  dayLabel,
  durationLabel,
  eventTime,
  formatCostTotal,
  formatUsd,
  groupSessionsByDay,
  type SessionDay,
  startLabel,
  tokenLabel,
} from './activity/format.ts';
export { HarnessSelect } from './activity/HarnessSelect.tsx';
export {
  EVENT_META,
  HARNESS_IDS,
  HARNESS_KIND,
  LINK_LABEL,
  STATUS_META,
  TOOL_META,
  toolEntries,
  toolTotal,
} from './activity/meta.ts';
export { SessionDetailView } from './activity/SessionDetailView.tsx';
export { SessionListView } from './activity/SessionListView.tsx';

// Findings views — props-driven (no data fetching); the apps supply data. The
// detail view takes an optional `footer` so a host app can append its own
// sections without forking the body.
export { ActionTag, AggregateActionTag } from './findings/ActionTag.tsx';
export { FindingDetailView, formatConfidence } from './findings/FindingDetailView.tsx';
export { FindingsTableView } from './findings/FindingsTableView.tsx';
export { ColumnsMenu, FindingsToolbarView } from './findings/FindingsToolbarView.tsx';
export {
  ACTION_META,
  CATEGORY_ICON,
  CATEGORY_ICON_FALLBACK,
  CATEGORY_LABEL,
  CATEGORY_STYLE,
  categoryStyle,
  type ColumnVisibility,
  EMPTY_FILTERS,
  type FindingColumn,
  FINDINGS_COLUMNS,
  type FindingsFilters,
  type Selection,
  SEVERITIES,
} from './findings/meta.ts';
export { ProviderChips, ProviderTag } from './findings/ProviderChips.tsx';

// Inlined line icons shared with app shells (the OSS web-ui reuses these rather
// than re-declaring identical SVG paths).
export {
  BoltIcon,
  BracesIcon,
  ExternalShareIcon,
  LayersIcon,
  SearchIcon,
  ShieldCheckIcon,
  TerminalIcon,
  XIcon,
} from './shared/icons.tsx';

// Detections views — props-driven (no data fetching); the apps supply data. The
// detail view takes optional action callbacks (onToggleEnabled / onChangePolicy /
// onOpenUpdate) so host apps with different data layers
// share one body; omitting a callback renders that control read-only.
export {
  MetaStat,
  OriginBadge,
  PolicyTag,
  PublisherTag,
  TonePill,
  UpdateBadge,
} from './detections/atoms.tsx';
export { DetectionDetailView } from './detections/DetectionDetailView.tsx';
// Stat-strip icon reused by the detections page.
export { DETECTION_FILTER_TABS, DetectionsListView } from './detections/DetectionsListView.tsx';
export { MatcherModal } from './detections/MatcherModal.tsx';
export {
  CATEGORY_LABEL as DETECTION_CATEGORY_LABEL,
  MATCHER_META,
  type MatcherMeta,
  matcherSummary,
  ORIGIN_META,
  PLACEHOLDER_POLICY,
  POLICY_META,
  type PolicyMeta,
  policyMeta,
  type ProvenanceState,
  provenanceState,
  PUBLISHER_META,
  type Tone,
  toneColors,
} from './detections/meta.ts';
export { PolicyPicker } from './detections/PolicyPicker.tsx';
export { ProvenanceBlock } from './detections/ProvenanceBlock.tsx';
export { UpdateModal } from './detections/UpdateModal.tsx';

// Policies views — props-driven built-in enforcement-policy catalog (stat strip +
// master/detail). Fed by client hooks or @akasecurity/persistence Server
// Components, depending on the host.
export { PolicyDetailView, PolicyListView, PolicyStatsView } from './policies/PoliciesView.tsx';

// Inventory views — props-driven register of every locally-governed asset
// (harnesses → skills/MCP/hooks/config, projects → files with per-file LLM
// access). The nav + panes take data + callbacks; the apps supply data (via
// client hooks or Server Components + Server Actions, depending on the host) and
// own the selection/file-browser state. Icon identity is data-driven
// via the local Ico registry (./inventory/icons.ts).
// Only the view components + EmptyState + the data-driven <Ico> and the shared
// selection resolver are public; the data descriptors, chips and icon registry
// stay module-internal so a future rename is a private refactor, not a break.
export { AssetDetail } from './inventory/AssetDetail.tsx';
export { EmptyState } from './inventory/chips.tsx';
export {
  type InventoryNavData,
  type Selection as InventorySelection,
  resolveInventorySelection,
} from './inventory/data.ts';
export { FileDetailDrawer } from './inventory/FileDetailDrawer.tsx';
export { HarnessOverview } from './inventory/HarnessOverview.tsx';
export { Ico } from './inventory/Ico.tsx';
export { InventoryNav } from './inventory/InventoryNav.tsx';
export { ProjectPane } from './inventory/ProjectPane.tsx';

// Security widget views — props-driven (no data fetching); the apps supply data.
export {
  type EnforcementActionsView,
  EnforcementCardView,
} from './security/EnforcementCardView.tsx';
export {
  type FindingsChartPoint,
  FindingsOverTimeCardView,
  type FindingsTimeseriesView,
} from './security/FindingsOverTimeCardView.tsx';
export { formatMttrDuration } from './security/format.ts';
export { ENFORCEMENT_META, SEVERITY_META, SEVERITY_TILE } from './security/meta.ts';
export {
  type MttrChartPoint,
  MttrTrendCardView,
  type MttrTrendView,
} from './security/MttrTrendCardView.tsx';
export {
  RecentlyResolvedCardView,
  type RecentlyResolvedView,
} from './security/RecentlyResolvedCardView.tsx';
export {
  buildRecommendations,
  buildRecommendedActions,
  type FindingStatus,
  findingStatus,
  healthScore,
  type Recommendation,
} from './security/recommendations.ts';
export {
  RecommendedActionsCardView,
  type RecommendedActionsView,
} from './security/RecommendedActionsCardView.tsx';
export { ScanCoverageCardView, type ScanCoverageView } from './security/ScanCoverageCardView.tsx';
export { SeverityCardView, type SeveritySummaryView } from './security/SeverityCardView.tsx';
export { TopSourcesCardView, type TopSourcesView } from './security/TopSourcesCardView.tsx';

// Exceptions views — props-driven (no data fetching); the web twin of the
// `aka exception` verbs. Fed by @akasecurity/persistence Server Components /
// Server Actions in the OSS web-ui; all domain shapes are @akasecurity/schema types.
export {
  AddExceptionForm,
  type AddExceptionFormProps,
  type AddExceptionRuleOption,
  type AddExceptionSubmission,
} from './exceptions/AddExceptionForm.tsx';
export {
  ApproveExceptionDialog,
  type ApproveExceptionDialogProps,
  type ApproveSubmission,
} from './exceptions/ApproveExceptionDialog.tsx';
export { ScopePicker, StateTag, StateTagFor } from './exceptions/atoms.tsx';
export { BlockedLedgerView, type BlockedLedgerViewProps } from './exceptions/BlockedLedgerView.tsx';
export { BlockedWindowSelect } from './exceptions/BlockedWindowSelect.tsx';
export {
  ExceptionDetailView,
  type ExceptionDetailViewProps,
} from './exceptions/ExceptionDetailView.tsx';
export {
  ExceptionsTableView,
  type ExceptionsTableViewProps,
} from './exceptions/ExceptionsTableView.tsx';
export {
  type ExceptionState,
  exceptionState,
  SCOPE_ANSWER_LABEL,
  SCOPE_ANSWERS,
  SCOPE_LABEL,
  type ScopeAnswer,
  STATE_TONE,
  VIA_LABEL,
} from './exceptions/meta.ts';
export {
  ROTATE_CONFIRMATION,
  RotateKeyDialog,
  type RotateKeyDialogProps,
} from './exceptions/RotateKeyDialog.tsx';

// Updates views — props-driven; the web twin of `aka check-updates` / `aka
// update` / `aka plugins`. Fed by @akasecurity/local-ops via server actions in the
// OSS web-ui.
export {
  AvailablePluginsCardView,
  type AvailablePluginsCardViewProps,
} from './updates/AvailablePluginsCardView.tsx';
export {
  type UpdateOutcome,
  UpdateStatusCardView,
  type UpdateStatusCardViewProps,
} from './updates/UpdateStatusCardView.tsx';

// Settings views — the web twin of the `/aka:setup` wizard's editable knobs.
export {
  WorkspaceSettingsFormView,
  type WorkspaceSettingsFormViewProps,
} from './settings/WorkspaceSettingsFormView.tsx';

// Data Shares views — props-driven (no data fetching). Fed by the web-ui
// (persistence-backed Server Components); all domain shapes are @akasecurity/schema
// types. Only the UI-only ShareSelection lives here.
export {
  ClassTag,
  DestMark,
  MethodTag,
  TemplatePill,
  TemplateUrl,
  TransportTag,
  TrustTag,
} from './data-shares/atoms.tsx';
export {
  DataShareDetailView,
  type DataShareDetailViewProps,
} from './data-shares/DataShareDetailView.tsx';
export {
  DataSharesTableView,
  type DataSharesTableViewProps,
} from './data-shares/DataSharesTableView.tsx';
export {
  CLASS_META,
  type ClassMeta,
  destMarkStyle,
  flagReason,
  hasInsecureTransport,
  KIND_LABEL,
  KIND_ORDER,
  type ProviderMark,
  providerMark,
  REVIEW_REASON_META,
  TRANSPORT_META,
  type TransportMeta,
  TRUST_META,
  type TrustMeta,
} from './data-shares/meta.ts';
export {
  NeedsReviewStripView,
  type NeedsReviewStripViewProps,
} from './data-shares/NeedsReviewStripView.tsx';
export type { ShareSelection } from './data-shares/types.ts';
