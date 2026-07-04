// Configuration-posture rules over one ConfigScanResult (the Skills & Hooks
// inventory scan). STRUCTURAL rules — they compare hook entries against each
// other and against small allowlists — so they live here as pure functions
// rather than in the regex/keyword pack format (which matches single text
// spans and cannot express "two hooks on the same event overlap").
//
// Pure like everything in @akasecurity/detections: no I/O, no Node APIs — input is the
// schema-typed scan, output is the gateway's natural-key finding shape. The
// rules are versioned Inspection Definitions (id = sha256(ruleId + version) is
// minted in @akasecurity/persistence); bumping RULE_VERSION on a behavior change mints
// new definition rows while historical findings keep citing the version that
// fired.
//
// Fixture-tested (fixtures/*.json) with positives AND negatives per rule —
// the same bar the rule-pack CI gate sets for regex rules.
import type {
  ConfigPostureFindingInput,
  ConfigScanResult,
  HookScanEntry,
  InspectionDefinitionInput,
} from '@akasecurity/schema';

// One version for the v1 heuristics below; bump on any behavior change.
const RULE_VERSION = '1';

// First-executable-token basenames that identify a recognizable, widely-known
// tool — the v1 stand-in for the future known-hooks registry. Deliberately
// SMALL: a bare project script (guard.sh) is exactly what the rule should
// surface until a registry can vouch for it.
const KNOWN_TOOLS = new Set([
  'prettier',
  'eslint',
  'biome',
  'black',
  'ruff',
  'gofmt',
  'rustfmt',
  'node',
  'npx',
  'npm',
  'pnpm',
  'yarn',
  'make',
  'git',
  'jq',
  'echo',
]);

// Network-egress primitives inside a hook command. Hooks receive prompt/tool
// payloads on stdin, so a command that can ship bytes off the machine is the
// highest-signal posture finding this surface has.
const EGRESS_RE = /\b(curl|wget|nc|ncat|netcat|ssh|scp|rsync)\b|https?:\/\//;

// A command that MUTATES the tool target (vs merely reading it) — the
// ingredient that turns same-event matcher overlap into an ordering hazard.
// The redirect branch excludes fd/stderr redirects (`2>`, `&>`, `2>>`): they
// route diagnostics, not the target. `-i`/`-w` remain heuristic (read-only for
// some tools, e.g. `grep -i`) — harmless alone, since a conflict needs TWO
// overlapping mutating hooks.
const MUTATION_RE = /(--write|--fix|\s-w\b|\s-i\b|(?<![\d&>])>\s?\S)/;

export const CONFIG_POSTURE_RULES: readonly InspectionDefinitionInput[] = [
  {
    ruleId: 'hook-conflict',
    version: RULE_VERSION,
    name: 'Overlapping hooks — run order is undefined',
    category: 'config',
    severity: 'medium',
    definition: JSON.stringify({
      kind: 'hook-conflict',
      mutation: MUTATION_RE.source,
      note: 'two hooks on the same event with overlapping matchers, both mutating the tool target',
    }),
  },
  {
    ruleId: 'hook-unknown',
    version: RULE_VERSION,
    name: 'Unknown hook — not attributable to a plugin or known tool',
    category: 'config',
    // medium, not high: with a deliberately tiny allowlist this v1 heuristic
    // fires on ordinary interpreter hooks (python3 x.py) and compound commands
    // (cd … && tool); 'high' is reserved for egress, which is genuinely
    // dangerous. Revisit when the known-hooks registry replaces the allowlist.
    severity: 'medium',
    definition: JSON.stringify({ kind: 'hook-unknown', knownTools: [...KNOWN_TOOLS] }),
  },
  {
    ruleId: 'hook-external-egress',
    version: RULE_VERSION,
    name: 'Hook command can send data externally',
    category: 'config',
    severity: 'high',
    definition: JSON.stringify({ kind: 'hook-external-egress', pattern: EGRESS_RE.source }),
  },
];

/**
 * Evaluate the v1 posture rules against one scan. Returns natural-key finding
 * inputs (`ruleId` + `version`); the persistence layer resolves definition ids
 * and mints row ids. `maskedMatch` carries the offending COMMAND — it is the
 * correlation key the read surface matches back to a hook row, and it is
 * config the user already holds locally, not captured secret content.
 */
export function evaluateConfigPosture(scan: ConfigScanResult): ConfigPostureFindingInput[] {
  const findings: ConfigPostureFindingInput[] = [];
  for (const hook of scan.hooks) {
    const egress = EGRESS_RE.exec(hook.command);
    if (egress) {
      findings.push(
        finding(
          'hook-external-egress',
          hook.command,
          {
            start: egress.index,
            end: egress.index + egress[0].length,
          },
          0.9,
        ),
      );
    }
    if (isUnknown(hook)) {
      findings.push(finding('hook-unknown', hook.command, whole(hook.command), 0.6));
    }
  }
  for (const conflicted of conflictingHooks(scan.hooks)) {
    findings.push(finding('hook-conflict', conflicted.command, whole(conflicted.command), 0.7));
  }
  return findings;
}

// The rule metadata the writer upserts alongside the findings (idempotent —
// INSERT OR IGNORE on the content-addressed definition id).
export function configPostureDefinitions(): InspectionDefinitionInput[] {
  return [...CONFIG_POSTURE_RULES];
}

// ── hook-unknown ─────────────────────────────────────────────────────────────

// v1 heuristic (pending a known-hooks registry): a settings-scope hook whose
// first executable token is not a recognizable tool. Plugin-scope hooks are
// attributed by the install manifest and skipped.
function isUnknown(hook: HookScanEntry): boolean {
  if (hook.scope === 'plugin') return false;
  const token = firstExecutableToken(hook.command);
  if (token === undefined) return true;
  return !KNOWN_TOOLS.has(basename(token));
}

// The first token that isn't an env assignment (FOO=bar cmd …). Known v1 gap:
// compound commands are NOT split, so `cd /x && prettier …` resolves to `cd`
// (unknown) even though the real tool is prettier — one more reason the rule
// severity stays medium until the registry lands.
function firstExecutableToken(command: string): string | undefined {
  for (const token of command.trim().split(/\s+/)) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue;
    return token.replace(/^['"]|['"]$/g, '');
  }
  return undefined;
}

// Pure string basename — no node:path in this package.
function basename(token: string): string {
  const slash = token.lastIndexOf('/');
  return slash === -1 ? token : token.slice(slash + 1);
}

// ── hook-conflict ────────────────────────────────────────────────────────────

// Hooks on the same event with overlapping matchers where BOTH mutate the tool
// target: Claude Code defines no run order between separate entries, so the
// last write wins nondeterministically (the prettier/eslint --fix case). One
// finding per extra mutating hook beyond the first (the report attaches the
// warning to the later entries, mirroring the mock).
function conflictingHooks(hooks: HookScanEntry[]): HookScanEntry[] {
  const conflicted: HookScanEntry[] = [];
  const mutating = hooks.filter((h) => MUTATION_RE.test(h.command));
  for (let i = 0; i < mutating.length; i++) {
    for (let j = i + 1; j < mutating.length; j++) {
      const a = mutating[i];
      const b = mutating[j];
      if (a === undefined || b === undefined) continue;
      if (a.event !== b.event) continue;
      if (!matchersOverlap(a.matcher, b.matcher)) continue;
      if (!conflicted.includes(b)) conflicted.push(b);
    }
  }
  return conflicted;
}

// Matchers are treated as literal '|'-separated tool names; absent or '*'
// matches all tools. Claude Code matchers are actually REGEX ('Edit.*'), so
// this literal comparison UNDER-reports: 'Edit.*' vs 'Edit' is not detected as
// overlapping unless a literal token coincides. A v1 simplification — false
// negatives only, never a spurious conflict.
function matchersOverlap(a: string | undefined, b: string | undefined): boolean {
  if (isUniversal(a) || isUniversal(b)) return true;
  const tokens = new Set((a ?? '').split('|').map((t) => t.trim()));
  return (b ?? '').split('|').some((t) => tokens.has(t.trim()));
}

function isUniversal(matcher: string | undefined): boolean {
  return matcher === undefined || matcher.trim() === '' || matcher.trim() === '*';
}

// ── shared ───────────────────────────────────────────────────────────────────

function finding(
  ruleId: string,
  command: string,
  span: { start: number; end: number },
  confidence: number,
): ConfigPostureFindingInput {
  return {
    ruleId,
    version: RULE_VERSION,
    span,
    maskedMatch: command,
    actionTaken: 'warn',
    confidence,
  };
}

function whole(command: string): { start: number; end: number } {
  return { start: 0, end: command.length };
}
