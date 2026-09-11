import { binExists, runCapture, runInherit } from './exec.ts';
import { isSemver } from './semver.ts';

// Generic delegator onto a host CLI's own plugin manager — the supported way
// to install and update its plugins. The AKA CLI is a hub over these, never a
// reimplementation: each host CLI owns its own plugin cache, enable/disable
// state, and restart lifecycle.
//
// The hosts share the SHAPE (`<bin> plugin …`) but NOT the verbs, and assuming
// they did is the defect this replaced — every Codex install and update emitted
// `codex plugin install|update`, which Codex rejects outright with
// "unrecognized subcommand". Claude Code takes `install` and `update`; Codex
// takes `add` for both, having no update verb at all (`add` re-resolves the
// plugin, so a refresh IS a re-add). The marketplace verbs diverge the same
// way: both hosts cache a snapshot of the marketplace and both can reconcile it
// with its source, but Claude Code spells that `marketplace update` and Codex
// spells it `marketplace upgrade`. Verified against the hosts themselves —
// `claude plugin marketplace --help` on Claude Code 2.1.220 and
// `codex plugin marketplace --help` on codex-cli 0.147.0 — not inferred from
// one host and assumed for the other, which is the mistake this table exists
// to stop.
//
// Two kinds of command come out of this table and they are NOT interchangeable:
//
//   - the PLUGIN OP (`installSteps`/`updateSteps`) — what the user asked for.
//     A failure here is the operation failing, so apply.ts runs it fatally.
//   - MARKETPLACE PREP (`marketplaceSteps`) — registering the source, and for a
//     host whose `add` reads a local snapshot, refreshing that snapshot. This is
//     best-effort: it is a precondition that is usually already met, and a
//     transient failure (offline, a git fetch error, a marketplace registered
//     from a source that cannot be upgraded) must not abort an operation that
//     would have succeeded against the cached snapshot.
export type CliPluginBin = 'claude' | 'codex';

/**
 * The version a host CLI reports for itself, or undefined when it cannot be
 * read (not on PATH, a non-zero exit, no version-shaped token in the output).
 *
 * SOUND AT INSTALL TIME, AND ONLY THERE. `aka plugins install` delegates to the
 * host binary resolved from PATH, so the version that binary reports is the one
 * being installed into. Inside a session it would NOT be sound: the host running
 * the session can be a different install from the one on PATH — measured, 2.1.258
 * on PATH against 2.1.260 actually running — so the hook path reads the version
 * off the transcript instead of asking here.
 *
 * Fail-silent by construction: every caller treats undefined as "do not warn".
 */
// Wrapping punctuation a version is commonly printed inside, and nothing more.
// Both are bounded so neither can backtrack; see `versionTokenFrom` for why an
// unbounded or open-ended strip was wrong in two different directions.
const LEADING_WRAP = /^[([{"'`]{0,2}[vV]?/;
const TRAILING_WRAP = /[)\]}"'`,;]{0,4}$/;

/**
 * The first token in a `--version` output that parses as a version.
 *
 * Separated from the spawn so it can be tested directly: the shape of this scan
 * is the whole of what the install gate depends on, and driving it through a
 * child process would test the child instead. `hostCliVersion` is then only the
 * spawn.
 *
 * Validated with `isSemver` from this package rather than a private regex, so
 * one grammar serves the parse and the comparison. A local copy would sit
 * outside the mirroring convention both `semver.ts` headers already name, and a
 * grammar widened under that convention (accepting `+build`, say) would leave
 * this behind — the gate would then reject versions the comparator accepts and
 * go silent.
 *
 * The two strips are an ENUMERATED, BOUNDED set of wrapping punctuation, not
 * "everything up to the first digit". Both properties are load-bearing:
 *
 * - Bounded, because an unbounded trailing `[^\w.-]+$` is polynomial on a token
 *   the host CLI controls — measured 281/1089/4276 ms at 25k/50k/100k commas,
 *   clean n². (Reproducing it needs a LEADING DIGIT: without one the leading
 *   strip eats the commas first and it measures 0 ms.)
 * - Enumerated, because `^[^\d]*` accepts any prefix, so
 *   `@anthropic-ai/claude-code@3.0.0` resolved to `3.0.0` — an npm notice on the
 *   first line then outranked the real version, which is a MISSED warning on a
 *   security gate. `foo-2.1.258` and a URL path went the same way.
 *
 * The PRERELEASE is deliberately kept: `2.1.251-rc.1` must not collapse to
 * `2.1.251`, which compares EQUAL to a floor that build predates, letting it
 * clear a gate it should trip.
 *
 * The first line wins over the rest, because that is where a `--version` prints.
 * That narrows, but does not eliminate, a version-shaped token appearing before
 * the real one: a notice on a LATER line now loses, while one on the first line
 * still wins. It fails toward silence — a spurious higher version clears every
 * floor — so it costs a missed warning, never a wrong one.
 */
export function versionTokenFrom(stdout: string): string | undefined {
  const [firstLine = ''] = stdout.split('\n');
  for (const token of [...firstLine.trim().split(/\s+/), ...stdout.split(/\s+/)]) {
    const candidate = token.replace(LEADING_WRAP, '').replace(TRAILING_WRAP, '');
    if (isSemver(candidate)) return candidate;
  }
  return undefined;
}

export function hostCliVersion(bin: CliPluginBin): string | undefined {
  const { ok, stdout } = runCapture(bin, ['--version'], 5_000);
  return ok ? versionTokenFrom(stdout) : undefined;
}

// One command's argv, minus the binary. A step list rather than a single argv
// because Codex's marketplace prep is two commands.
type Step = readonly string[];

interface HostVerbs {
  install: (ref: string) => Step[];
  // The scope is the one the plugin is ALREADY INSTALLED AT, read from the
  // host's own ledger — not a preference. A host whose update verb takes no
  // scope ignores it.
  update: (ref: string, scope?: string) => Step[];
  // Registering the marketplace. REQUIRED before the op — without it the op
  // fails on an unknown marketplace — so a failure here genuinely should stop
  // whatever follows.
  register: (source: string) => Step[];
  // Refreshing an already-registered snapshot. Both managed hosts keep one, so
  // both carry a verb here; the empty return stays legal for a host that keeps
  // none. A failure here is survivable: the cached snapshot stays in place and
  // the op can still run against it.
  //
  // It is not optional in EFFECT, which is why the empty return was a defect
  // rather than a shortcut: `marketplace add` on an already-registered source
  // reports success without touching the snapshot (measured — Claude Code
  // answers "already on disk"), so prep that only registers leaves a months-old
  // manifest in place and the op resolves against that.
  refresh: (marketplace: string) => Step[];
}

const HOST_VERBS: Record<CliPluginBin, HostVerbs> = {
  claude: {
    install: (ref) => [['plugin', 'install', ref]],
    // `claude plugin update` defaults to `--scope user`, so a bare ref targets
    // the user scope whatever the read side looked at. `installedPluginVersions`
    // prefers a user record and FALLS BACK to the first one with a version, so
    // on a machine where an enterprise drop-in put the plugin at `managed` the
    // two halves talked about different installs: the comparison read the
    // managed record and reported an update, and the apply then failed with
    // `Plugin "ai-tc" is not installed at scope user`.
    //
    // Stated rather than defaulted, and stated whenever the ledger names one —
    // including `user`. An implicit agreement between the two halves is exactly
    // what broke, so the reading the comparison used is the one spelled here.
    // Whether a given scope may be updated at all is the host's call: `managed`
    // is an administrator's install, and a refusal from `claude` naming that is
    // a true answer, unlike the one this replaces.
    update: (ref, scope) => [['plugin', 'update', ref, ...(scope ? ['--scope', scope] : [])]],
    register: (source) => [['plugin', 'marketplace', 'add', source]],
    refresh: (marketplace) => [['plugin', 'marketplace', 'update', marketplace]],
  },
  codex: {
    install: (ref) => [['plugin', 'add', ref]],
    // No `update` verb — `add` is the whole operation. It resolves the plugin
    // from the marketplace manifest, and refreshing the git snapshot is about
    // the MANIFEST (a renamed package, a newly listed plugin), which is why it
    // is a separate, optional step.
    //
    // It takes no scope either: Codex keeps one plugin cache per home, so there
    // is nothing to target. The parameter is ignored here rather than absent,
    // so the two hosts share one signature and a caller cannot pass a scope to
    // only one of them.
    //
    // This used to add "which for this repo's entries names an npm package with
    // NO VERSION PIN, so `add` picks up a published bump on its own", and that
    // premise is false for Claude Code's marketplace: the resolved manifest's
    // `ai-tc` entry reads `{ source: 'npm', package: …, version: '0.9.10' }` on
    // a real install, on the default branch. An entry with no pin does exist —
    // a `github` or `git-subdir` source — so the shape varies per entry rather
    // than per repository.
    //
    // Whether it holds for the CODEX marketplace is UNVERIFIED: Codex keeps no
    // marketplaces directory to read a resolved manifest from, so nothing here
    // has seen one. It is stated as unknown rather than corrected to a second
    // guess, because what rests on it is this host's whole update path.
    update: (ref) => [['plugin', 'add', ref]],
    register: (source) => [['plugin', 'marketplace', 'add', source]],
    refresh: (marketplace) => [['plugin', 'marketplace', 'upgrade', marketplace]],
  },
};

export interface CliPluginManager {
  available: () => boolean;
  // The commands an install/update runs, in order. Exposed as STEPS rather than
  // run here, because the caller owns the output mode: apply.ts streams to a
  // terminal or captures for the dashboard, and marketplace prep is best-effort
  // where the op is fatal. One table feeds both those runs and the hint copy
  // that tells a user what to type — hint copy naming a verb the host rejects
  // is exactly how this bug reached a user's terminal.
  //
  // `marketplaceSteps` is prep: register the source, then refresh the snapshot
  // if a marketplace name is known. A re-add of an existing marketplace is a
  // no-op that reports success on both hosts (measured on each, not inferred
  // from one), and a refresh that fails leaves the cached snapshot in place,
  // which the plugin op can still install from — so every one of these steps is
  // survivable and apply.ts discards their results.
  marketplaceSteps: (source: string, marketplace?: string) => Step[];
  installSteps: (ref: string) => Step[];
  updateSteps: (ref: string) => Step[];
  // The MANUAL EQUIVALENT: what a user runs by hand to reach the same state —
  // register the marketplace, then the op. Shown where the automated path can't
  // run or may be interrupted, so every caller joins it with `&&`.
  //
  // Which means it must carry ONLY steps whose failure should stop the chain.
  // The snapshot refresh is deliberately absent: it is the one step this module
  // treats as survivable, and `&&` cannot express that — a git-fetch error on
  // `marketplace upgrade` would short-circuit the `plugin add` that is the whole
  // point. Leaving it in was a real defect: it made best-effort prep fatal in
  // exactly the line a user retypes, while the code path went on treating the
  // same failure as harmless.
  //
  // The trade that buys is worth naming rather than glossing. On a machine that
  // has never registered the marketplace — the case this copy is mostly written
  // for — `marketplace add` clones the snapshot fresh and there is nothing to
  // refresh. On one that registered it long ago, the re-add reports success
  // without reconciling, so the retyped line runs against whatever manifest is
  // cached. That is the deliberate choice: a stale manifest resolves the plugin
  // it already knows about, where a fatal refresh resolves nothing at all.
  installRecipe: (ref: string, source?: string) => string[];
  updateRecipe: (ref: string, source?: string) => string[];
  // Everything the AUTOMATED path spawns, in order: prep (both steps) then the
  // op. This is the disclosure render — a confirm dialog saying "this runs the
  // following on your machine" is a promise, and naming one of three spawns
  // breaks it in a product whose whole pitch is that you can see what runs.
  //
  // NOT interchangeable with a recipe, and never to be joined with `&&`: it
  // deliberately includes the survivable refresh, whose failure the automated
  // path ignores and `&&` would not. Join with a newline and show it as a list.
  installSpawnPlan: (ref: string, source?: string, marketplace?: string) => string[];
  updateSpawnPlan: (ref: string, source?: string, marketplace?: string) => string[];
  install: (ref: string) => boolean;
  update: (ref: string) => boolean;
}

/**
 * A manager for one host CLI, optionally bound to the scope a plugin is
 * already installed at.
 *
 * The scope is supplied HERE rather than at each update entry point, and that
 * is structural rather than tidy: there are four ways to reach the update verb
 * (`updateSteps`, `updateRecipe`, `updateSpawnPlan`, `update`), and a
 * per-call parameter is one a caller can thread into the spawn and forget in
 * the hint — which would print a command that does not do what the spawn did.
 * Bound here, every one of them agrees by construction.
 *
 * Absent means "whatever the host defaults to", which is what every caller got
 * before a scope could be read at all.
 */
export function createCliPluginManager(
  bin: CliPluginBin,
  installedScope?: string,
): CliPluginManager {
  const verbs = HOST_VERBS[bin];
  const update = (ref: string): Step[] => verbs.update(ref, installedScope);
  const runAll = (steps: Step[]): boolean => steps.every((args) => runInherit(bin, [...args]));
  const render = (steps: Step[]): string[] => steps.map((args) => `${bin} ${args.join(' ')}`);
  const marketplaceSteps = (source: string, marketplace?: string): Step[] => [
    ...verbs.register(source),
    ...(marketplace ? verbs.refresh(marketplace) : []),
  ];
  // Register-then-op only. See `installRecipe` on why the refresh stays out.
  const recipe = (steps: Step[], source: string | undefined): string[] =>
    render([...(source ? verbs.register(source) : []), ...steps]);
  // Prep-then-op, refresh included — what `apply.ts` really spawns.
  const spawnPlan = (
    steps: Step[],
    source: string | undefined,
    marketplace: string | undefined,
  ): string[] => render([...(source ? marketplaceSteps(source, marketplace) : []), ...steps]);

  return {
    available: () => binExists(bin),
    marketplaceSteps,
    installSteps: (ref) => verbs.install(ref),
    updateSteps: (ref) => update(ref),
    installRecipe: (ref, source) => recipe(verbs.install(ref), source),
    updateRecipe: (ref, source) => recipe(update(ref), source),
    installSpawnPlan: (ref, source, marketplace) =>
      spawnPlan(verbs.install(ref), source, marketplace),
    updateSpawnPlan: (ref, source, marketplace) => spawnPlan(update(ref), source, marketplace),
    install: (ref) => runAll(verbs.install(ref)),
    update: (ref) => runAll(update(ref)),
  };
}
