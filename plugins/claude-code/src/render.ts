// Pure renderers for the read surfaces: plain data from the data gateway → a
// formatted, monochrome string. Kept free of I/O so they unit-test without a DB
// and a future interactive TUI can reuse them; query.ts owns the gateway + stdout.
//
// No color anywhere — the surfaces are echoed verbatim into the Claude Code
// transcript, which doesn't render ANSI. Severity / intensity is carried by the
// shade glyphs from present.ts (█ ▓ ▒ ░), so every screen reads in plain text.
import type {
  DataGateway,
  DayActivity,
  FindingView,
  HealthSummary,
  PostureChange,
  SessionTokenReport,
} from '@akasecurity/plugin-sdk';
import {
  aggregateTokenUsage,
  detectPostureChanges,
  formatCostTotal,
  formatUsd,
} from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  BuiltinPolicyId,
  DetectionException,
  DetectionListItem,
  SetupHandoffOffer,
} from '@akasecurity/schema';
import { BUILTIN_ORDER, DetectionCategory, toApiAction } from '@akasecurity/schema';

import { selectRegisteredCommands } from './command-registry.ts';
import { NAME } from './identity.ts';
import {
  bar,
  defList,
  indent,
  padEnd,
  padStart,
  paint,
  SHADE,
  stackedBar,
  table,
  wrapText,
} from './present.ts';

// The fail-open note shown when the local store can't be READ (missing / corrupt
// / locked db) mid-wizard: the calibration and first-run frames print this instead
// of throwing, so a store fault never breaks the Claude session. This is the
// store-UNAVAILABLE (read-failure) path only. The found-nothing / empty-store case
// (a store that reads fine but holds nothing) is a distinct path with its own
// honest copy — frameEmptyState in calibration.ts — not this note.
export const STORE_UNAVAILABLE_NOTE =
  "I couldn't read the local store right now. AKA stays fail-open — your Claude session is unaffected, and it populates as you use Claude Code.";

const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// Severity → shade glyph: heavier fill = more severe (critical solid, low light),
// so the severity column reads as texture with no color. The same four glyphs
// carry intensity on the /health chart and the unreviewed tallies.
const SEVERITY_GLYPH: Record<string, string> = {
  critical: SHADE.full,
  high: SHADE.dark,
  medium: SHADE.medium,
  low: SHADE.light,
};

function severityGlyph(severity: string): string {
  return SEVERITY_GLYPH[severity] ?? SHADE.light;
}

// Plain-language next step per detection category, shown by `/recommend`.
const ADVICE: Record<string, string> = {
  secret:
    'Rotate the exposed credentials and move them out of prompts (secrets manager / env vars).',
  pii: 'Remove or mask personal data before it reaches the model.',
  financial: 'Strip card and account numbers; share only non-sensitive references.',
  phi: 'Remove protected health information — it should never reach an external model.',
  code_context: 'Confirm this proprietary code context is safe to share.',
  code_flaw:
    'Review the flagged pattern and apply the secure alternative (parameterized queries, safe deserializers, etc.).',
  custom: 'Review against your organization’s custom policy.',
};

// "2026-06-19T11:14:53.000Z" → "06-19 11:14" (compact, table-friendly). A
// finding missing its timestamp renders a placeholder rather than a blank cell
// so the table doesn't read as broken.
function shortTime(iso: string): string {
  if (!iso) return '—';
  return iso.length >= 16 ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : iso;
}

function empty(message: string): string {
  return message;
}

// ActionTaken (the DB enum: warn|redact|block|allow|log) -> the user-facing
// palette label the wizard uses (monitor|warn|redact|block|allow). Only 'log'
// differs (-> 'monitor'); everything else is identity. Kept local to the
// render surface so the DB vocabulary never leaks into the first-run screen.
const ACTION_LABEL: Record<string, string> = {
  log: 'monitor',
  warn: 'warn',
  redact: 'redact',
  block: 'block',
  allow: 'allow',
};

// Canonical category order for the posture card, from the schema enum. Rows
// come out of the store in DB order; rendering in this fixed order keeps the
// card stable regardless of how the caller read them. An unknown category (a
// custom rule's) sorts after the known ones, in its incoming order.
const CATEGORY_ORDER: readonly string[] = DetectionCategory.options;
function categoryRank(category: string): number {
  const i = CATEGORY_ORDER.indexOf(category);
  return i === -1 ? CATEGORY_ORDER.length : i;
}

// Compact, aligned per-category posture block for the first-run screen: one
// row per category, its stored action translated to the palette label. Rows
// are rendered in the canonical category order above so the card is stable.
// Pure (no I/O) so it unit-tests without a DB; the caller (firstrun.ts)
// supplies rows read from the policies store.
export function renderPosture(rows: { category: string; action: string }[]): string {
  const width = Math.max(0, ...rows.map((r) => r.category.length));
  return [...rows]
    .sort((a, b) => categoryRank(a.category) - categoryRank(b.category))
    .map((r) => `  ${r.category.padEnd(width)}  ${ACTION_LABEL[r.action] ?? r.action}`)
    .join('\n');
}

// The condensed recommended-posture view for the calibrated-result frame: one
// compact row per pack showing the level AKA recommends, in canonical category
// order. This is the recommend-and-confirm glance — distinct from the start-light
// branch's full 8×4 level table, which lays every level out per pack. Pure (no
// I/O); the caller hands in the recommended posture (severityFloorPosture()),
// whose palette levels (monitor/warn/redact/block) render verbatim.
export function renderRecommendedPosture(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
): string {
  const rows = (Object.keys(posture) as DetectionCategory[]).map((category) => ({
    category,
    level: posture[category] ?? '',
  }));
  const width = Math.max(0, ...rows.map((r) => r.category.length));
  return rows
    .sort((a, b) => categoryRank(a.category) - categoryRank(b.category))
    .map((r) => `  ${r.category.padEnd(width)}  ${r.level}`)
    .join('\n');
}

// The full 8×4 posture matrix for the start-light branch: every pack laid out
// against all four levels (monitor/warn/redact/block), the chosen level marked,
// in canonical category order. This lays the whole choice space out per pack —
// distinct from renderRecommendedPosture's condensed one-level-per-pack glance.
// The level columns come from BUILTIN_ORDER (the schema's palette order), so the
// DB action vocabulary (log/allow) never appears. Pure (no I/O); the caller
// hands in the posture map (severityFloorPosture() for the recommended defaults).
const GRID_MARK = '●';
export function renderPostureGrid(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
): string {
  const packs = (Object.keys(posture) as DetectionCategory[]).sort(
    (a, b) => categoryRank(a) - categoryRank(b),
  );
  const rows = packs.map((category) => [
    category,
    ...BUILTIN_ORDER.map((level) => (posture[category] === level ? GRID_MARK : '')),
  ]);
  return indent(table(['Pack', ...BUILTIN_ORDER], rows));
}

// The re-tune hint that closes the start-light card and the applied frame,
// pointing at the two surfaces that re-open calibration: the /aka:setup wizard
// and the web-ui settings grid (the deep-tuning surface). Exported so the wizard
// prose (setup.md) and the applied-frame copy single-source it instead of
// repeating the string and letting the two drift.
export const RE_TUNE_HINT = 'Re-tune anytime with /aka:setup or the dashboard';

// Why each pack sits at its default: calm, plain-language reasons in the product
// voice — "notifications" not alarms. The warn packs surface sensitive data for
// the user's call; the monitor packs (code_context, config) watch quietly to keep
// the noise down. Presentation copy only — not a persisted contract.
const PACK_RATIONALE: Record<DetectionCategory, string> = {
  secret: 'live credentials are the costliest thing to leak, so I bring them to you on sight.',
  pii: 'personal data carries real obligations, so I surface it before it moves.',
  financial: 'card and account numbers are sensitive by default, so these come to you.',
  phi: 'health information is regulated wherever it lands, so I flag it for your call.',
  code_context:
    'proprietary code context is common and mostly benign, so I watch quietly and keep the record.',
  code_flaw: 'an insecure pattern is worth a look before it ships, so I raise it.',
  custom: 'your own policy matches start surfaced so nothing you care about slips by unseen.',
  config:
    'configuration values are noisy to flag, so I keep an eye on them without a notification.',
};

// The start-light card — frame 0.3b of the /aka:setup Not-now branch, shown when
// the user declines the retroactive scan so they still leave setup calibrated.
// Composes the full 8×4 grid (renderPostureGrid) seeded with the conservative
// defaults, a per-pack rationale line explaining why each pack sits at its
// default, and the re-tune hint. Pure (no I/O); the caller hands in the posture
// map (severityFloorPosture() for the severity-floor defaults), whose packs render in
// canonical category order.
export function renderStartLight(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
): string {
  const packs = (Object.keys(posture) as DetectionCategory[]).sort(
    (a, b) => categoryRank(a) - categoryRank(b),
  );
  const rationale = packs.map(
    (pack) => `  ${pack} — ${posture[pack] ?? ''}: ${PACK_RATIONALE[pack]}`,
  );
  return [
    '● Start light — set your packs',
    '',
    indent('No history to calibrate from yet, so each pack starts at a conservative default.'),
    '',
    renderPostureGrid(posture),
    '',
    ...rationale,
    '',
    indent(RE_TUNE_HINT),
  ].join('\n');
}

// The downgrade-approval block appended to the adjust-confirm card when one or
// more packs would be LOWERED below the level already stored — including a pack
// the user never touched this run (it sits at its recommended default because it
// surfaced no findings to escalate, not because anyone chose to weaken it). This
// is the only point in the adjust fork that compares against the existing STORE
// posture rather than just the recommended-vs-chosen table, so a pack hardened
// out of band (e.g. via /aka:config) can't be silently lowered by the wizard.
function renderDowngradeApproval(changes: readonly PostureChange[]): string {
  const noun = changes.length === 1 ? 'pack' : 'packs';
  const lines = changes.map(
    (c) => `  ${c.category}: ${ACTION_LABEL[c.from] ?? c.from} → ${ACTION_LABEL[c.to] ?? c.to}`,
  );
  return [
    `⚠ Downgrade approval needed — ${String(changes.length)} ${noun} would be lowered below ` +
      'the current hardened level (this applies even to a pack with no findings this run):',
    lines.join('\n'),
    'Confirm you intend to weaken enforcement here, or adjust your picks so the pack stays at its current level.',
  ].join('\n');
}

// The 0.4b adjust-confirm card of the /aka:setup Yes-path adjust loop: a
// three-column 'category │ recommended │ yours' table laying each pack's
// recommended level beside the level the user chose, so a changed pack reads as
// a different 'yours' value and the untouched packs repeat their recommended
// level. Closes with the adjust copy and the shared re-tune pointer at the
// deep-tuning surface. Pure (no I/O); the caller hands in the recommended posture
// (severityFloorPosture()) and the chosen map (that base with the user's
// overrides overlaid), whose packs render in canonical category order.
//
// `existingStorePosture` (optional, default {}) is the store's CURRENT
// per-category posture — the caller's own read, done at its I/O boundary so this
// renderer stays pure. When supplied, every pack's effective choice (chosen,
// falling back to recommended) is compared against it via detectPostureChanges;
// any pack that would be lowered gets an explicit downgrade-approval block below
// the table. An empty/omitted map (no store, or a store read failure) renders
// exactly as before — no comparison, no warning.
export function renderAdjustConfirm(
  recommended: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  chosen: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  existingStorePosture: Partial<
    Record<DetectionCategory, { action: ActionTaken; enabled: boolean }>
  > = {},
): string {
  const packs = (Object.keys(recommended) as DetectionCategory[]).sort(
    (a, b) => categoryRank(a) - categoryRank(b),
  );
  const effective: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {};
  for (const category of packs) {
    const level = chosen[category] ?? recommended[category];
    if (level !== undefined) effective[category] = level;
  }
  const rows = packs.map((category) => [
    category,
    recommended[category] ?? '',
    effective[category] ?? '',
  ]);
  const downgrades = detectPostureChanges(effective, existingStorePosture).filter(
    (change) => change.kind === 'downgrade',
  );
  return [
    '● Adjust — set the packs you want, keep the rest',
    '',
    indent(table(['category', 'recommended', 'yours'], rows)),
    '',
    indent("I'll keep the rest as recommended."),
    ...(downgrades.length > 0 ? ['', indent(renderDowngradeApproval(downgrades))] : []),
    '',
    indent(RE_TUNE_HINT),
  ].join('\n');
}

// The applying-confirmation "Ready" line's curated command set — the read
// surfaces to run once calibration is applied (health, findings, recommend), a
// surface-specific subset (not the whole registry) deliberately distinct from the
// Try line's, written in the plugin's `/aka:<command>` namespace (the only form
// that resolves when typed). Validated against the installed command registry
// before it renders, so the call-to-action never names a command the user cannot
// invoke.
export const READY_COMMANDS = ['/aka:health', '/aka:findings', '/aka:recommend'] as const;

// The "tuned" segment — the count of posture categories the writer
// wrote, threaded from the real write (never a literal). Single-sourced here so
// onboard.ts's posture-write confirmation and the composed applying-confirmation
// line read identically.
export function renderCategoriesTuned(categoriesTuned: number): string {
  const noun = categoriesTuned === 1 ? 'category' : 'categories';
  return `✓ ${String(categoriesTuned)} ${noun} tuned`;
}

// The /aka:setup wizard's applying confirmation, shown once the
// calibration takes effect: '✓ K categories tuned · ✓ N routine dismissed ·
// Ready: …'. Both counts are threaded from the real apply result (the posture
// writer's category count and the apply-suppressions result's written count),
// never a literal. When nothing routine was dismissed (N === 0) the middle
// segment is honest empty-state copy rather than a fabricated '✓ 0 routine
// dismissed'. `registry` is the installed command registry (readRegisteredCommands()),
// resolved at the caller's I/O boundary and threaded in so this stays a pure
// formatter: the Ready line's curated set is validated against it, and an
// unregistered curated command throws rather than rendering. Pure (no I/O) so it
// unit-tests without a DB.
export function renderApplied(
  categoriesTuned: number,
  dismissed: number,
  registry: readonly string[],
): string {
  const routine =
    dismissed > 0 ? `✓ ${String(dismissed)} routine dismissed` : 'no routine to dismiss';
  const ready = `Ready: ${selectRegisteredCommands(READY_COMMANDS, registry).join(' · ')}`;
  return `${renderCategoriesTuned(categoriesTuned)} · ${routine} · ${ready}`;
}

const RULE_WIDTH = 64;

// The setup-intro "card" the /aka:setup wizard shows first.
// Factual fields (version, repository) are read from the plugin manifest by the
// intro script; the display copy (name, tagline, one-liner) comes from the
// identity constant. Pure here so it renders without any I/O.
export interface PluginMeta {
  name: string;
  tagline: string;
  oneLiner: string;
  repository: string;
  version: string;
}

export function renderSetupIntro(meta: PluginMeta): string {
  const heading = `● Found ${meta.name} — ${meta.tagline}`;

  // The ' · verified' badge is appended here once the provenance check lands.
  const provenance = `v${meta.version} · ${meta.repository}`;

  return [heading, '', indent(meta.oneLiner), '', indent(provenance)].join('\n');
}

// The "What I do" card the /aka:setup wizard shows after the intro. Static
// explanatory copy — no data to template, so it takes no arguments. Pure here so
// it renders without any I/O and unit-tests as a plain string. The closing line
// hands off to the scan offer that calibrates the notifications.
export function renderWhatIDo(): string {
  return [
    '● I watch out for Claude as it works.',
    '',
    indent(
      'As it codes, I intelligently contain sensitive data — secrets and regulated information — to your computer.',
    ),
    indent("Most of it I handle quietly; I only notify you when it's worth your call."),
    '',
    indent("let's calibrate your notifications based on what Claude's been up to"),
  ].join('\n');
}

// Derived posture score (0–100). HEURISTIC — we don't store a posture score, so
// this blends what we actually have: category coverage (how much sensitive-data
// is under an enabled policy) and the share of findings that were acted on
// (block/redact/warn) rather than let through. Centralized so the /health and
// first-run screens agree, and so it can be swapped for the product's intended
// scoring model in one place.
export function healthScore(summary: HealthSummary): number {
  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledRatio = summary.findings === 0 ? 1 : handled / summary.findings;
  return Math.round(100 * (0.6 * summary.coverage + 0.4 * handledRatio));
}

// The "First run" completion screen. Posture, findings and
// recommendations are real; `health` is the derived score above. The host's
// input box and window chrome are not the plugin's to draw.
export interface FirstRunSummary {
  // Per-category posture block (renderPosture's output) — the wizard's
  // per-category policy read, one row per category. Optional/omittable: the
  // read lives inside firstrun's fail-open try/catch, so a store that can't
  // be read yet just hides the section rather than breaking the card.
  posture?: string;
  health: number;
  findings: number;
  recommendations: number;
  // The surfaced/important count carried over from the calibration
  // preview — drives the 'N worth a look' dashboard handoff. Rendered only when
  // it is a positive count; when nothing surfaced (0/undefined) the card omits
  // the handoff line and its stats degrade to an honest empty-state.
  worthALook?: number;
  // Highest-severity findings from the first scan, ranked + capped by topFindings.
  // Omitted (or empty) on a clean scan — the section is hidden then.
  topFindings?: FindingView[];
}

// The installed-summary "Try" line's curated command set — the dashboard and the
// working-tree scan, a surface-specific subset (not the whole registry), written
// in the plugin's `/aka:<command>` namespace (the only form that resolves when
// typed). Validated against the installed command registry before it renders, so
// the call-to-action never names a command the user cannot invoke.
export const TRY_COMMANDS = ['/aka:dashboard', '/aka:scan'] as const;

// Rank findings for the install card's "Top findings" list: most severe first,
// then most recent within a severity, capped to `limit`. Pure so the first-run
// script and a future TUI rank identically and it unit-tests without a DB.
export function topFindings(findings: FindingView[], limit = 10): FindingView[] {
  return [...findings]
    .sort((a, b) => {
      const sev = (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0);
      return sev !== 0 ? sev : b.occurredAt.localeCompare(a.occurredAt);
    })
    .slice(0, limit);
}

// The handoff-offer payload: the 'M worth a look' count the installed
// summary hands to its frame 0.6 question, plus the offer options.
// `worthALook` is the surfaced/important count the caller carries over from the
// calibration preview (the sum across every category); `liveKeys` is the
// narrower surfaced live-key secret count. Both are real store-derived values —
// this builder never invents them. The prompt layer (setup.md) issues the
// AskUserQuestion; this is the structured payload a harness reads to assert the
// offer.
//
// The chain-entry option is composed in ahead of the dashboard handoff exactly
// when live-key secrets surfaced (`liveKeys > 0`), so remediation is reachable
// without displacing Open dashboard / Not now. When no live keys surfaced — even
// with other important findings present (`worthALook > 0`, `liveKeys` 0) — the
// plain dashboard handoff stands alone — offered exactly when
// live-key secrets surfaced, and never otherwise.
export function buildHandoffOffer(worthALook: number, liveKeys: number): SetupHandoffOffer {
  const dashboardHandoff: SetupHandoffOffer['options'] = [
    { id: 'open-dashboard', label: 'Open dashboard' },
    { id: 'not-now', label: 'Not now' },
  ];
  if (liveKeys > 0) {
    return {
      worthALook,
      liveKeys,
      options: [{ id: 'enter-remediation', label: 'Review leaked keys' }, ...dashboardHandoff],
    };
  }
  return { worthALook, options: dashboardHandoff };
}

// `registry` is the installed command registry (readRegisteredCommands()),
// resolved at the caller's I/O boundary and threaded in so this stays a pure
// formatter: the Try line's curated set is validated against it here, and an
// unregistered curated command throws rather than rendering.
export function renderFirstRun(s: FirstRunSummary, registry: readonly string[]): string {
  const heading = `✓ ${NAME} installed — calibrated to this machine`;

  // Nothing-surfaced degradation: with no findings in the store the numeric
  // Health/Findings/Recommendations triple would read as a scan tally over an
  // empty result. The stats line becomes an honest empty-state instead — an
  // explicit zero-state, never a fabricated count. (The dashboard handoff is
  // withheld on the same nothing-surfaced footing below.)
  const stats =
    s.findings === 0
      ? "Nothing needs your attention — you're starting clean."
      : `Health ${String(s.health)}/100 · Findings ${String(s.findings)} · Recommendations ${String(s.recommendations)}`;

  const tryCommands = selectRegisteredCommands(TRY_COMMANDS, registry);
  const lines = [heading, '', indent(stats), '', indent(`Try: ${tryCommands.join(' · ')}`)];

  // Per-category posture — hidden when unreadable (fail-open upstream leaves
  // it undefined/empty) so the card degrades gracefully instead of showing an
  // empty section.
  if (s.posture !== undefined && s.posture.length > 0) {
    lines.push('', indent('Posture'), '', indent(s.posture));
  }

  lines.push('', indent('─'.repeat(RULE_WIDTH)), '', indent('First scan complete'));

  // Top findings — a compact, severity-ranked glance at what the first scan
  // caught. Hidden on a clean scan so the card stays a tidy success state.
  const top = s.topFindings ?? [];
  if (top.length > 0) {
    const rows = top.map((f) => [
      `${severityGlyph(f.severity)} ${f.severity}`,
      f.category,
      f.ruleId,
      toApiAction(f.actionTaken),
      f.maskedMatch,
    ]);
    lines.push(
      '',
      indent(`Top findings (${String(top.length)})`),
      '',
      indent(
        table(['Severity', 'Category', 'Rule', 'Action', 'Match'], rows, {
          gap: 4,
          rowSep: true,
        }),
      ),
    );
  }

  // Dashboard handoff — the 'N worth a look' offer over the real surfaced count,
  // pairing the AskUserQuestion the prompt layer issues (Open dashboard / Not
  // now). Shown only when something surfaced; when nothing surfaced a 0/absent
  // count omits the line entirely rather than fabricating a '0 worth a look'.
  if (s.worthALook !== undefined && s.worthALook > 0) {
    lines.push(
      '',
      indent(`${String(s.worthALook)} worth a look — see them in the browser?`),
      indent('Open dashboard · Not now'),
    );
  }

  return lines.join('\n');
}

// `severity`, when set, is the active `--severity` filter — it only tailors the
// heading and the empty-state copy; the caller has already narrowed `findings`.
export function renderFindings(
  findings: FindingView[],
  status: FindingStatus,
  severity?: string,
): string {
  if (findings.length === 0) {
    return empty(
      severity !== undefined
        ? `No ${severity} findings recorded yet.`
        : 'No findings recorded yet — AKA scans prompts, file edits, and tool output as you work.',
    );
  }
  const rows = findings.map((f) => [
    shortTime(f.occurredAt),
    `${severityGlyph(f.severity)} ${f.severity}`,
    f.category,
    f.ruleId,
    toApiAction(f.actionTaken),
    f.maskedMatch,
  ]);
  const heading =
    severity !== undefined
      ? `● Recent ${severity} findings (${String(findings.length)})`
      : `● Recent findings (${String(findings.length)})`;
  return [
    heading,
    '',
    indent(
      table(['Time', 'Severity', 'Category', 'Rule', 'Action', 'Match'], rows, {
        gap: 4,
        rowSep: true,
      }),
    ),
    '',
    indent('Filter by level with --severity <critical|high|medium|low>.'),
    '',
    indent(renderStatusBar(status)),
  ].join('\n');
}

// The /health screen (the marquee dashboard). A row of score gauges, a summary
// line, the 7-day detections chart, and a status footer. Pure — the caller builds
// the report (see buildHealthReport) so this stays I/O-free and testable.
export interface HealthGauge {
  label: string;
  score: number; // 0–100
  note: string; // trailing detail, e.g. "3/4 acted on"
  outOf100?: boolean; // Overall renders "/ 100"
}

export interface HealthDay {
  label: string; // "Mon"
  total: number; // findings detected that day
  redacted: number;
  warned: number;
  blocked: number;
}

export interface HealthReport {
  title: string;
  gauges: HealthGauge[];
  openFindings: number;
  scanCoverage: number; // 0..1
  week: HealthDay[];
  weekFindings: number; // sum of the window's per-day totals
  recommendCount: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  score: number; // for the footer "health NN/100"
}

const GAUGE_LABEL_W = 14;
const GAUGE_BAR_W = 18;
const WEEK_LABEL_W = 5;
const WEEK_BAR_W = 44;

function renderGauge(g: HealthGauge): string {
  const fill = bar(g.score, 100, GAUGE_BAR_W);
  const score = padStart(String(g.score), 3);
  const outOf = g.outOf100 === true ? '/ 100' : '     ';
  return `${padEnd(g.label, GAUGE_LABEL_W)}  ${fill}  ${score} ${outOf}   ${g.note}`;
}

// The persistent status line shared by /findings, /health and /recommend.
export interface FindingStatus {
  score: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  openFindings: number;
}

// `color` is opt-in and honored only by the status line (the one ANSI-capable
// surface). The transcript footers on /findings, /health and /recommend call
// this with no options and stay monochrome, since ANSI doesn't render there.
function renderStatusBar(s: FindingStatus, opts: { color?: boolean } = {}): string {
  const u = s.unreviewed;
  if (opts.color !== true) {
    // Monochrome (transcript footers): severity carried by shade-glyph texture,
    // never hue, since these surfaces print as plain text in the transcript.
    const unreviewed =
      `unreviewed ${SHADE.full}${String(u.critical)} ${SHADE.dark}${String(u.high)} ` +
      `${SHADE.medium}${String(u.medium)} ${SHADE.light}${String(u.low)}`;
    return `▸▸ AKA   health ${String(s.score)}/100   ${unreviewed}   ⚑ ${String(s.openFindings)} open findings`;
  }

  // Status line: ANSI colour. Severity is one square glyph tinted per level, bar
  // separators divide the sections, the health dot reflects the score, and the
  // flag goes red when findings are open (plain grey when the slate is clean).
  const sep = ` ${paint.dim('│')} `;
  const sq = '■';
  const dot = s.score >= 80 ? paint.ok('●') : s.score >= 50 ? paint.high('●') : paint.critical('●');
  const score = `${dot} health ${paint.bold(String(s.score))}${paint.dim('/100')}`;
  const tally =
    `${paint.dim('unreviewed')} ` +
    `${paint.critical(sq)}${String(u.critical)} ${paint.high(sq)}${String(u.high)} ` +
    `${paint.medium(sq)}${String(u.medium)} ${paint.low(sq)}${String(u.low)}`;
  const flag = s.openFindings > 0 ? paint.critical('⚑') : paint.dim('⚑');
  const open = `${flag} ${String(s.openFindings)} open findings`;
  return `${paint.brand('▸▸ AKA')}${sep}${score}${sep}${tally}${sep}${open}`;
}

// One line for Claude Code's statusLine command (the persistent footer) — the
// same data and look as the read surfaces' status bar, but ANSI is
// honored here (statusLine renders it), so open findings show in red.
export function renderStatusLine(summary: HealthSummary): string {
  return renderStatusBar(findingStatus(summary), { color: true });
}

// Shared status powering the bar on /findings, /health and /recommend: the
// derived score, the unreviewed-by-severity tally, and the open-findings count.
// All three come from the whole-store health summary — NOT the finding page a
// given command fetched — so the footer reads identically on every surface
// regardless of each command's row limit (25 on /findings vs 500 elsewhere).
// `openFindings` is the real finding total (the store has no resolution state,
// so every finding is open) and sums `bySeverity`.
function findingStatus(summary: HealthSummary): FindingStatus {
  return {
    score: healthScore(summary),
    unreviewed: { ...summary.bySeverity },
    openFindings: summary.findings,
  };
}

export function renderHealth(r: HealthReport): string {
  const lines = [`● ${r.title}`, ''];
  for (const g of r.gauges) lines.push(indent(renderGauge(g)));

  lines.push('');
  const pct = Math.round(r.scanCoverage * 100);
  const stats = `Open findings ${String(r.openFindings)}` + `    Scan coverage ${String(pct)}%`;
  lines.push(indent(stats), '');

  lines.push(indent('Detections & actions — last 7 days'));
  const maxDay = Math.max(1, ...r.week.map((d) => d.total));
  for (const d of r.week) {
    const allowed = Math.max(0, d.total - d.redacted - d.warned - d.blocked);
    const segments = [
      { value: allowed, glyph: SHADE.light },
      { value: d.redacted, glyph: SHADE.medium },
      { value: d.warned, glyph: SHADE.dark },
      { value: d.blocked, glyph: SHADE.full },
    ];
    lines.push(
      indent(
        `${padEnd(d.label, WEEK_LABEL_W)}${stackedBar(segments, d.total, maxDay, WEEK_BAR_W)}  ${padStart(String(d.total), 3)}`,
      ),
    );
  }

  lines.push('');
  lines.push(
    indent(
      `${SHADE.light} allowed   ${SHADE.medium} redacted   ${SHADE.dark} warned   ${SHADE.full} blocked`,
    ),
  );
  lines.push(indent(`${String(r.weekFindings)} findings in the last 7 days`));

  lines.push('');
  lines.push(indent(`Run /recommend to review ${String(r.recommendCount)} prioritized actions.`));

  lines.push('');
  lines.push(
    indent(
      renderStatusBar({ score: r.score, unreviewed: r.unreviewed, openFindings: r.openFindings }),
    ),
  );

  return lines.join('\n');
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

// "2026-06-21" (UTC day from activityByDay) → "Sat". Falls back to the raw day
// string if it can't be parsed, so the chart never breaks on odd input.
function weekday(isoDay: string): string {
  const date = new Date(`${isoDay}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? isoDay : (WEEKDAYS[date.getUTCDay()] ?? isoDay);
}

// Assemble the /health report entirely from gateway data — no placeholders. The
// gauges are the real posture inputs: Overall (the blended score), Coverage (how
// many detection categories sit under an enabled policy) and Handled (the share
// of findings actually acted on). The week chart is the real per-day findings
// breakdown from activityByDay.
//
// NOTE: Skills / Hooks / MCP / Configuration gauges and token accounting are
// intentionally omitted — they need setup-health detectors and a token meter
// this build doesn't capture yet. We show only what we can actually measure
// rather than fabricate numbers.
export function buildHealthReport(
  summary: HealthSummary,
  findings: FindingView[],
  activity: DayActivity[],
): HealthReport {
  const status = findingStatus(summary);

  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledPct = summary.findings === 0 ? 100 : Math.round((handled / summary.findings) * 100);
  const coveragePct = Math.round(summary.coverage * 100);

  const gauges: HealthGauge[] = [
    {
      label: 'Overall',
      score: status.score,
      note: `${String(summary.findings)} finding${summary.findings === 1 ? '' : 's'} total`,
      outOf100: true,
    },
    { label: 'Coverage', score: coveragePct, note: 'categories under policy' },
    {
      label: 'Handled',
      score: handledPct,
      note:
        summary.findings === 0
          ? 'no findings yet'
          : `${String(handled)}/${String(summary.findings)} acted on`,
    },
  ];

  const week: HealthDay[] = activity.map((d) => ({
    label: weekday(d.day),
    total: d.total,
    redacted: d.redacted,
    warned: d.warned,
    blocked: d.blocked,
  }));

  return {
    title: 'Setup health — local Claude Code deployment',
    gauges,
    openFindings: status.openFindings,
    scanCoverage: summary.coverage,
    week,
    weekFindings: week.reduce((n, d) => n + d.total, 0),
    // Exactly the number of rows /recommend renders (one per category, capped),
    // so "review N prioritized actions" always matches that screen.
    recommendCount: buildRecommendations(findings).length,
    unreviewed: status.unreviewed,
    score: status.score,
  };
}

// One row of the /recommend list. Severity drives ordering + the shade label;
// `context` is the meta left of the arrow, `action` the verb after.
export interface Recommendation {
  severity: string;
  title: string;
  description: string;
  context: string;
  action: string;
}

// Per-category copy for findings-derived recommendations (the live source until
// the setup-health recommender lands). Title + the verb after the → arrow.
const REC_TEMPLATE: Record<string, { title: string; action: string }> = {
  secret: { title: 'Exposed secret detected', action: 'Rotate' },
  pii: { title: 'Personal data in a prompt', action: 'Remove' },
  financial: { title: 'Financial data detected', action: 'Strip' },
  phi: { title: 'Health information detected', action: 'Remove' },
  code_context: { title: 'Proprietary code shared', action: 'Review' },
  custom: { title: 'Custom policy match', action: 'Review' },
};

// Cap on the recommendation list. One entry per category, so today it's bounded
// by the handful of REC_TEMPLATE categories — but custom rules can mint new
// categories, so cap it explicitly. Entries are severity-ranked, so the cap keeps
// the most important; the slice only ever drops low-priority overflow.
const MAX_RECOMMENDATIONS = 10;

// Derive recommendations from real findings: one per category, ranked by
// severity then frequency, described with the category's advice. (Setup-health
// items — MCP/hooks/permissions — need detectors we don't have, so
// the live list speaks to the sensitive-data findings we actually capture.)
export function buildRecommendations(findings: FindingView[]): Recommendation[] {
  interface Bucket {
    category: string;
    count: number;
    severity: string;
    weight: number;
    ruleId: string;
  }
  const buckets = new Map<string, Bucket>();
  for (const f of findings) {
    const b = buckets.get(f.category) ?? {
      category: f.category,
      count: 0,
      severity: f.severity,
      weight: 0,
      ruleId: f.ruleId,
    };
    b.count++;
    const w = SEVERITY_WEIGHT[f.severity] ?? 0;
    if (w > b.weight) {
      b.weight = w;
      b.severity = f.severity;
      b.ruleId = f.ruleId;
    }
    buckets.set(f.category, b);
  }

  return [...buckets.values()]
    .sort((a, b) => b.weight - a.weight || b.count - a.count)
    .slice(0, MAX_RECOMMENDATIONS)
    .map((b) => {
      const t = REC_TEMPLATE[b.category] ?? { title: `${b.category} finding`, action: 'Review' };
      return {
        severity: b.severity,
        title: t.title,
        description: ADVICE[b.category] ?? 'Review this finding against your policy.',
        context: `${b.ruleId} · ${String(b.count)} finding${b.count === 1 ? '' : 's'}`,
        action: t.action,
      };
    });
}

// Description wrap width for a recommendation. The body sits indented under the
// severity badge; this keeps the block within a comfortable reading measure on a
// wide terminal while still fitting ~80 columns once indented.
const REC_DESC_WIDTH = 72;
// Indent of the body/meta lines, aligning them under the severity badge that
// follows the "N. " rank prefix.
const REC_BODY_INDENT = '   ';

export function renderRecommend(recs: Recommendation[], status: FindingStatus): string {
  if (recs.length === 0) {
    return empty(
      'No recommendations yet — nothing to act on. Guidance appears as AKA detects sensitive content.',
    );
  }

  const count = `${String(recs.length)} recommendation${recs.length === 1 ? '' : 's'}`;
  const lines = [`● ${count} for your setup, ordered by severity:`, ''];

  recs.forEach((r, i) => {
    // Heading: rank · severity badge (two spaces) · what's wrong.
    const badge = `${severityGlyph(r.severity)} ${r.severity.toUpperCase()}`;
    lines.push(indent(`${String(i + 1)}. ${badge}  ${r.title}`));
    // Description, wrapped and indented under the badge.
    for (const line of wrapText(r.description, REC_DESC_WIDTH)) {
      lines.push(indent(`${REC_BODY_INDENT}${line}`));
    }
    // A blank line, then the finding context and the action verb on one line.
    lines.push('', indent(`${REC_BODY_INDENT}${r.context}  → ${r.action}`), '');
  });

  lines.push(
    indent('Run /recommend <n> to act on one, or /health for the summary.'),
    '',
    indent(renderStatusBar(status)),
  );
  return lines.join('\n');
}

export function renderAudit(findings: FindingView[]): string {
  if (findings.length === 0) {
    return empty('No decisions recorded yet — AKA logs each detection here as it acts.');
  }
  const rows = findings.map((f) => [
    shortTime(f.occurredAt),
    toApiAction(f.actionTaken),
    f.ruleId,
    f.category,
    // Join only the parts that are present so a finding missing sourceTool/kind
    // renders cleanly instead of a bare "/".
    [f.sourceTool, f.kind].filter(Boolean).join('/'),
  ]);
  return [
    `Recent decisions (${String(findings.length)})`,
    '',
    table(['Time', 'Action', 'Rule', 'Category', 'Source'], rows),
  ].join('\n');
}

// Thousands-separated integer for token counts (locale-stable, monochrome).
function num(value: number): string {
  return Math.round(value).toLocaleString('en-US');
}

// /aka:tokens — token usage rolled up across sessions by (provider, model). Token
// counts are saved truth; cost is DERIVED (— for unknown pricing, e.g. local Ollama
// or a non-Anthropic gateway). When any call is unpriced the totals are a LOWER
// bound, rendered with "≥" and a footnote, never silently understated.
export function renderTokens(reports: SessionTokenReport[]): string {
  if (reports.length === 0) {
    return empty('No token usage recorded yet — AKA reconciles your transcripts as you work.');
  }

  // Collapse every rollup onto its (provider, model) via the shared aggregator —
  // the SAME roll-up the OSS Activity page, `aka stats`, and the TUI use, so every
  // surface agrees on the per-model totals and the ≥-lower-bound cost.
  const summary = aggregateTokenUsage(reports);
  const rows = summary.models.map((m) => [
    m.provider,
    m.model,
    num(m.inputTokens),
    num(m.outputTokens),
    num(m.cacheTokens),
    num(m.totalTokens),
    m.estimatedCostUsd !== null ? formatUsd(m.estimatedCostUsd) : '—',
  ]);

  const totalCost = formatCostTotal(summary.estimatedCostUsd, summary.costIsPartial);
  const sessions =
    summary.sessionCount === 1 ? '1 session' : `${String(summary.sessionCount)} sessions`;
  const lines = [
    `Token usage — ${sessions}, ${num(summary.totalTokens)} tokens, ${totalCost}`,
    '',
    table(['Provider', 'Model', 'Input', 'Output', 'Cache', 'Total', 'Cost'], rows),
  ];
  if (summary.costIsPartial) {
    lines.push('', '— = unknown pricing (local / non-Anthropic model); cost is a lower bound.');
  }
  return lines.join('\n');
}

// "in 42m" / "in 3h" / "in 2d" — relative expiry for the /aka:exceptions table.
// A permanent grant has no expiry and renders as —; a just-lapsed one as
// "expired" (list() normally filters those, but the renderer stays honest for
// any caller). Takes `nowMs` so it is pure and unit-tests deterministically.
function relativeExpiry(expiresAt: string | null, nowMs: number): string {
  if (expiresAt === null) return '—';
  const deltaMs = Date.parse(expiresAt) - nowMs;
  if (Number.isNaN(deltaMs)) return expiresAt;
  if (deltaMs <= 0) return 'expired';
  const minutes = Math.ceil(deltaMs / 60_000);
  if (minutes < 60) return `in ${String(minutes)}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${String(hours)}h`;
  return `in ${String(Math.round(hours / 24))}d`;
}

// /aka:exceptions — the ACTIVE detection-exception grants, read-only. Shows the
// masked preview (values are never stored — only a keyed fingerprint), the rule,
// scope, relative expiry, use count, and who granted it. Creation and revocation
// stay in the terminal (`aka exception …`) on purpose: a slash command is
// model-invocable, so this surface only displays and points at the CLI.
export function renderExceptions(exceptions: DetectionException[], nowMs = Date.now()): string {
  if (exceptions.length === 0) {
    return [
      'No active exceptions.',
      'One is granted when a detection blocks you — follow the instructions in the block message.',
    ].join('\n');
  }

  const rows = exceptions.map((e) => [
    e.id.slice(0, 8),
    e.maskedValue,
    e.ruleId,
    e.scope,
    relativeExpiry(e.expiresAt, nowMs),
    e.maxUses === null ? String(e.useCount) : `${String(e.useCount)}/${String(e.maxUses)}`,
    e.createdBy,
  ]);

  const howTo = defList([
    ['Grant from a recent block', 'aka exception approve'],
    ['Undo a grant', 'aka exception revoke <id>'],
  ]);

  return [
    `● Active exceptions (${String(exceptions.length)})`,
    '',
    indent(table(['ID', 'Value', 'Rule', 'Scope', 'Expires', 'Uses', 'Created by'], rows)),
    '',
    indent(howTo),
  ].join('\n');
}

// /aka:detections — the installed detection packs, read-only: installed
// version, rule count, enabled state, effective policy, and whether the
// running plugin ships a newer snapshot. Updates are MANUAL by design (nothing
// auto-updates an installed pack), and applying one stays in the terminal /
// dashboard on purpose — a slash command is model-invocable, so this surface
// only displays and points at the CLI (mirrors renderExceptions).
export function renderDetections(items: DetectionListItem[]): string {
  if (items.length === 0) {
    return [
      'No detection packs installed yet.',
      'They are recorded on the first plugin hook of a session, or by `aka init`.',
    ].join('\n');
  }

  const rows = items.map((i) => [
    i.id,
    `v${i.version}`,
    i.latestVersion ? `v${i.latestVersion}` : `v${i.version}`,
    String(i.ruleCount),
    i.enabled ? 'yes' : 'no',
    i.policyId ?? 'monitor',
    i.latestVersion ? '⬆ update available' : '✓ up to date',
  ]);

  const updates = items.filter((i) => i.latestVersion != null);
  const totalRules = items.reduce((n, i) => n + i.ruleCount, 0);
  const active = items.filter((i) => i.enabled).length;

  const lines = [
    `● Installed detections (${String(items.length)} packs · ${String(totalRules)} rules · ${String(active)} enabled)`,
    '',
    indent(table(['Pack', 'Installed', 'Latest', 'Rules', 'Enabled', 'Policy', 'Status'], rows)),
    '',
  ];
  if (updates.length > 0) {
    lines.push(
      indent(
        `⬆ ${String(updates.length)} update(s) available. Updates are never applied automatically —`,
      ),
      indent('apply them yourself in a terminal or the dashboard:'),
      '',
      indent(
        defList([
          ['Update every pack', 'aka detections update --all'],
          ['Update one pack', `aka detections update ${updates[0]?.packId ?? '<pack-id>'}`],
          ['Review in the dashboard', 'aka dashboard → Detections → Update'],
        ]),
      ),
    );
  } else {
    lines.push(indent('✓ All detection packs are up to date with this plugin.'));
  }
  return lines.join('\n');
}

export type QuerySubcommand = 'findings' | 'health' | 'recommend' | 'audit' | 'tokens';

// Severity levels accepted by the `--severity` filter on /findings.
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface QueryOptions {
  severity?: Severity;
}

// `exceptions` is listed for the user-facing usage line but dispatched
// UPSTREAM in query.ts (it reads the local store directly, not the gateway) —
// runQuery itself never receives it.
const USAGE = 'Usage: query <findings|health|recommend|audit|tokens|exceptions|detections>';

// Dispatch a read subcommand against a resolved data gateway and return the text
// to print. Reads only — nothing is mutated here. Async because the DataGateway
// contract is async.
export async function runQuery(
  sub: string,
  gateway: DataGateway,
  opts: QueryOptions = {},
): Promise<string> {
  switch (sub) {
    case 'findings': {
      // Pull a wider window when filtering so the severity isn't limited to the
      // 25 most recent overall; otherwise keep the default recent slice.
      const limit = opts.severity !== undefined ? 500 : 25;
      // Independent reads — fetch concurrently.
      const [findings, summary] = await Promise.all([
        gateway.recentFindings({ limit }),
        gateway.healthSummary(),
      ]);
      // Narrow to the requested level when a `--severity` filter is given; the
      // status bar still reflects the whole-store summary, so its tally stays put
      // even though the listed rows are a recent (and possibly filtered) slice.
      const rows =
        opts.severity !== undefined
          ? findings.filter((f) => f.severity === opts.severity)
          : findings;
      return renderFindings(rows, findingStatus(summary), opts.severity);
    }
    case 'health': {
      const [summary, findings, activity] = await Promise.all([
        gateway.healthSummary(),
        gateway.recentFindings({ limit: 500 }),
        gateway.activityByDay(7),
      ]);
      return renderHealth(buildHealthReport(summary, findings, activity));
    }
    case 'recommend': {
      const [findings, summary] = await Promise.all([
        gateway.recentFindings({ limit: 500 }),
        gateway.healthSummary(),
      ]);
      return renderRecommend(buildRecommendations(findings), findingStatus(summary));
    }
    case 'audit':
      return renderAudit(await gateway.recentFindings({ limit: 25 }));
    case 'tokens':
      return renderTokens(await gateway.tokenReports());
    default:
      return USAGE;
  }
}
