import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The shared coverage block every package's vitest config spreads in, plus the
 * per-package floors it enforces.
 *
 * It lives at the repo root for the reason test/setup/no-network.ts does: every
 * package needs the SAME block, a package wall blocks the import, and N private
 * copies of a threshold table drift apart — which for a floor means drifting
 * DOWNWARDS silently, since a floor nobody re-reads is met by whatever the code
 * happens to do. turbo.json's globalDependencies hashes this directory, so
 * editing a floor busts every package's `test` task rather than leaving them
 * replaying a cached green taken under the old one.
 */

/**
 * Coverage is ALWAYS ON, not behind a `--coverage` flag, and that is the
 * load-bearing choice in this file.
 *
 * turbo.json declares `outputs: ["coverage/**"]` for the `test` task. An output
 * a task produces only sometimes is worse than one it never produces: a cache
 * hit taken from a run WITHOUT coverage restores no report, and the gate that
 * reads it then measures a directory that belongs to some other commit — or to
 * no commit at all. Making it unconditional is what makes that declaration
 * true, and it is what makes the floors below hold locally rather than only on
 * the one machine that remembered the flag.
 *
 * It is also what makes a floor a floor. A threshold that runs only in CI is
 * discovered after review rather than before it.
 */

/**
 * Per-package LINE floors, set at or just below each package's measured level
 * so nothing ratchets backwards.
 *
 * **These are measurements, not aspirations.** The number beside each package
 * is what its own suite reported at the commit this landed on; the floor is one
 * percentage point below it — enough that an honest refactor does not redden
 * the tree, little enough that a real regression does. A floor above today's
 * level is a red tree on day one, and a floor far below it is a silent licence
 * to regress; both are ways of not having a floor.
 *
 * The measurement is LINE coverage over statement-bearing lines, which is not
 * the same denominator as a raw LOC count: a module that is mostly one exported
 * object literal has few statements, so a small `lines` total there is the
 * instrument working rather than files going missing.
 *
 * **Taken on macOS / Node 24.** Platform-gated code is covered on the platform
 * that runs it and not on the others — the macOS keychain custody backend is
 * the clearest case — so a Linux or Windows leg can legitimately read lower
 * than the figure beside a package here. Where one does, the fix is to re-take
 * that package's number on the platform that reports lowest and set the floor
 * from that, not to widen every floor until the noisiest one fits.
 *
 * These replace an earlier per-package table of ESTIMATES derived from reading
 * tests. The estimates were reasonable and four of them were wrong by enough to
 * matter — in both directions: `scanner` read ~75% and measures 96.8%, while
 * `dashboard-ui`, `web-ui`, `audit-gate` and the Claude Code plugin all measure
 * BELOW the floor those estimates suggested. Adopting the estimated numbers
 * would have failed CI on the first run, which is the concrete reason a floor
 * has to come from a measurement.
 *
 * There is deliberately **no global/aggregate threshold anywhere in this
 * repository**. One would be satisfied by covering `dashboard-ui`'s SVG icon
 * sheet while a mutating Server Action sat at zero: the number rises, the risk
 * is untouched. Per-package floors cannot be paid off that way, because the
 * package holding the risk has to clear its own bar. `coverage-gate` enforces
 * the other half — that NEW code is tested — and it too is per-diff rather than
 * per-repo.
 *
 * Raising a floor after real work is the intended direction of travel. Lowering
 * one is a decision that needs saying out loud in the PR that does it.
 */
export const COVERAGE_FLOORS: Readonly<Record<string, number>> = Object.freeze({
  //                                       floor   measured
  '@akasecurity/eslint-config': 99, //             100.00
  '@akasecurity/detections': 98, //                 99.14
  '@akasecurity/scanner': 95, //                    96.80
  '@akasecurity/extract': 95, //                    96.61
  '@akasecurity/persistence': 94, //                95.97
  // Everything but the CLI entry, which is I/O wiring and decides nothing —
  // every decision sits in lib.ts, where the suite drives it.
  '@akasecurity/coverage-gate': 93, //              94.80
  '@akasecurity/plugin-sdk': 91, //                 92.37
  '@akasecurity/setup-wizard': 89, //               90.38
  '@akasecurity/schema': 84, //                     85.59
  '@akasecurity/portability-gate': 84, //           85.58
  '@akasecurity/plugin-runtime': 76, //             77.25
  '@akasecurity/ai-tc-claude-code': 71, //          72.84
  '@akasecurity/local-ops': 65, //                  66.75
  '@akasecurity/audit-gate': 61, //                 62.88
  '@akasecurity/ai-tc-antigravity': 59, //          60.96
  '@akasecurity/ai-tc-codex': 58, //                59.78
  '@akasecurity/plugin-browser-extension': 57, //   58.02
  '@akasecurity/cli': 51, //                        52.66
  '@akasecurity/dashboard-ui': 23, //               24.56
  '@akasecurity/web-ui': 23, //                     24.04
  '@akasecurity/ui-kit': 1, //                       2.13
  // No instrumentable source, which is why this reads 0 rather than a measured
  // percentage. What this package ships is install.sh and install.ps1, which v8
  // cannot see, and everything else under it is test/**, which SHARED_EXCLUDES
  // drops — so the denominator is genuinely empty (0/0, reported as "Unknown%")
  // and a floor has nothing to describe. It is listed because the table is
  // pinned as an EXACT set against the packages that run tests, and this one
  // does. Give it a real measured floor the moment it grows a src/: an empty
  // denominator is the one case where 0 is not a surrendered floor, and that
  // stops being true as soon as there is something to count.
  '@akasecurity/installer': 0, //                     0/0
});

/**
 * Paths excluded from every package's coverage denominator.
 *
 * The rule applied here is narrow on purpose: exclude what is **not shipped
 * source** (tests, benchmarks, build output, config) and what is **generated**,
 * and exclude nothing else. Excluding a file because it is inconvenient to test
 * is how a floor stops meaning anything — the excluded file keeps shipping, and
 * the percentage stops describing it.
 */
const SHARED_EXCLUDES = Object.freeze([
  '**/node_modules/**',
  '**/dist/**',
  '**/dist-sea/**',
  '**/sea-dist/**',
  '**/.next/**',
  '**/coverage/**',
  '**/test/**',
  '**/bench/**',
  '**/scripts/**',
  '**/native-host/**',
  '**/*.config.*',
  '**/*.test.*',
  '**/*.bench.*',
  '**/*.d.ts',
  // Generated: 101 JSON rule packs inlined into one module by a build step. It
  // is data with a `.ts` extension, and counting it would let a package buy
  // several points of coverage by importing a constant.
  '**/*.generated.*',
]);

/** The file extensions counted as shipped source. */
const SOURCE_GLOB = '**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}';

/** The `package.json` sitting next to a vitest config. */
const manifestBesideConfig = (configUrl: string): { dir: string; name: string } => {
  const dir = dirname(fileURLToPath(configUrl));
  const raw = readFileSync(join(dir, 'package.json'), 'utf8');
  const name: unknown = (JSON.parse(raw) as { name?: unknown }).name;
  if (typeof name !== 'string') {
    throw new Error(`coverage: ${join(dir, 'package.json')} has no "name"`);
  }
  return { dir, name };
};

/**
 * The `coverage` block for the package whose vitest config is at `configUrl`.
 *
 * Call it as `coverageOptions(import.meta.url)` — the package is identified
 * from the manifest beside the config rather than passed as a string, so a
 * config copied from a neighbour cannot silently inherit that neighbour's
 * floor. A package with no entry in COVERAGE_FLOORS throws rather than
 * defaulting to zero: an unlisted package is one nobody chose a floor for, and
 * defaulting it to 0 would hide exactly that.
 */
export function coverageOptions(configUrl: string) {
  const { dir, name } = manifestBesideConfig(configUrl);
  const floor = COVERAGE_FLOORS[name];
  if (floor === undefined) {
    throw new Error(
      `coverage: no floor for "${name}". Add one to COVERAGE_FLOORS in test/vitest/coverage.ts ` +
        `(measure it first — a floor above today's level reddens the tree, and one far below it ` +
        `is not a floor).`,
    );
  }

  // Relative to the repo root, so every package's report keys agree and
  // coverage-gate can intersect them with `git diff` paths without guessing.
  const reportsDirectory = join(dir, 'coverage');

  return {
    enabled: true,
    provider: 'v8' as const,
    // `json` is what coverage-gate reads; `text-summary` is what a developer
    // reads in the terminal; `lcov` is what the CI artifact carries for anyone
    // wanting a browsable report. No reporter here uploads anything.
    reporter: ['text-summary', 'json', 'lcov'],
    reportsDirectory,
    // Count EVERY shipped source file, not only the ones a test happened to
    // import. Without this a package with one test on one file reports 100%,
    // which is how `ui-kit`'s zero stayed invisible: nothing imported it, so
    // nothing counted it.
    include: [SOURCE_GLOB],
    exclude: [...SHARED_EXCLUDES],
    // Per-package, and lines only. Statements/functions/branches move for
    // reasons that have little to do with whether a behaviour is exercised,
    // and four numbers to argue about is how a floor gets lowered.
    thresholds: { lines: floor },
    // A red floor must not also destroy the report that explains it.
    reportOnFailure: true,
  };
}
