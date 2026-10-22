## Adding a new workspace package

1. Create `packages/<name>/package.json` with `"name": "@akasecurity/<name>"`
2. Extend `../../tsconfig.base.json`
3. Add an `eslint.config.mjs` extending `@akasecurity/eslint-config`, and spread
   `...rootConfigFiles` **after** the block that turns `projectService` on. Root config
   files sit outside the tsconfig `include`, so the type-aware parser rejects them
   outright (`was not found by the project service`) and reports nothing else about
   them; that block drops the type-aware rules for `*.config.*` at the package root so
   they lint. Every network ban is syntactic and still fires.
4. Export from `src/index.ts`
5. Add `"lint"` and `"typecheck"` scripts — the `lint` script must run `eslint` over
   **every directory the package ships code in and every lintable file at its root**,
   whatever they are named (a bare `.` counts; naming individual files counts only for
   those files, not for the directory they sit in). Turbo silently skips a package with
   no `lint` script, so a config nothing points ESLint at enforces nothing. `*.config.*`
   is the standing target for the build and tooling config; name any other root file
   explicitly (see `web-ui`'s `middleware.ts`). A `scripts/` dir of **hand-written
   (git-tracked)** scripts needs its own `eslint.scripts.config.mjs` plus a second pass
   (`eslint --no-config-lookup -c eslint.scripts.config.mjs scripts`) — a generated
   `scripts/` dir (the plugin's bundled hooks) is build output and is exempt.

   **Naming a target is not enough if the same invocation hands it back.** An
   `--ignore-pattern` cancels a target it matches, so `*.config.*` plus an ignore of
   `vitest.config.ts` reads as covering that file and lints it not at all. Anything an
   ignore flag excludes therefore counts as uncovered however the targets read, and the
   fix is to drop the flag rather than the directory. `--ignore-path` counts as excluding
   its whole invocation: flat-config ESLint rejects the flag outright, so that `eslint`
   call lints nothing. No `lint` script carries either flag today, and
   `packages/eslint-config/test/effective-config.test.js` is what would catch one that
   took coverage back. It bounds the damage rather than banning the flag: an ignore
   matching nothing the package ships stays green, which is what stops the guard
   over-reporting.

   **That holds at FILE granularity, not just directory granularity, and the
   difference is the whole exposure.** A directory target is checked as a directory,
   so an ignore is reduced to its literal prefix to answer whether the directory
   survives — and `--ignore-pattern test/probe.test.ts` reduces to a base that
   neither equals `test` nor prefixes it. Read at that level alone the directory
   goes on reading as covered while ESLint skips the file, which is worse than an
   unguarded path rather than equal to it: the reviewer who checks coverage finds a
   green guard. So the tracked files inside each covered directory are enumerated
   and checked individually, and one an ignore takes back out is named. The two
   buckets partition the failure — where the whole directory is excluded, the
   directory bucket names the package and the file bucket stays quiet, so one
   mistake prints one actionable line rather than that line plus every file
   beneath it.

   A `lint` script is a shell string, so **two ESLint calls are chained with `&&`
   and nothing else**. Behind a `||` the second runs only once the first has
   failed, so no green run ever lints what it targets; `|| true` is the mirror
   image, running the call and discarding its exit code. The same guard drops a
   segment carrying any operator but `&&` — reporting the package as covering
   nothing, rather than crediting a call a green run skips.

   That covers files a **package** owns. Files **outside every package** — at the
   repo root or under a directory no package claims — are a separate case with its
   own pass: `pnpm lint:root` / `pnpm typecheck:root`. Both run outside Turbo
   (`turbo run …` drives per-package scripts, each with its package as the working
   directory, and no package's `lint` script targets anything outside its own
   tree), and CI runs them as their own steps beside `format:check`. `pnpm lint`
   and `pnpm typecheck` additionally **chain** them with `&&`, so the pre-push
   hook, the two release workflows and a contributor running them locally all
   cover the repo root rather than reading green while a file there is unlinted or
   unchecked — those callers run only the workspace-wide scripts and never the CI
   steps. The chain has to be unconditional: behind a `||` the root pass runs only
   once the workspace pass has already failed, which is every green run skipping
   the repo root. `lint:root` is a single invocation: `eslint.root.config.mjs` runs
   the full ruleset over `test/setup/**`, `test/fixtures/**`, `test/helpers/**`,
   `test/vitest/**`, `tools/ci/**`, and the repo-root `*.config.*`.
   `typecheck:root` runs `tsc -p tsconfig.root.json` over the same set.

   It used to carry a second, network-only invocation over the plain-JS
   enforcement suites in `packages/eslint-config/test/**`, because that package's
   `lint` was a deliberate no-op and a root pass was the only thing that could
   reach them. It lints itself now — `eslint src *.config.*` then
   `eslint --no-config-lookup -c eslint.guard.config.mjs test`, the same
   full-ruleset + network-only split every other two-pass package makes — so those
   suites are covered by the ordinary per-package check and nothing about them is
   special any more.

   **Naming a target is not enough here either.** The rule the package paragraph
   above draws applies to `lint:root` unchanged: an `--ignore-pattern` cancels a
   target it matches, and an `--ignore-path` cancels the whole invocation, so the
   script reads as covering a repo-root file that ESLint then skips. Either way the
   file counts as **uncovered** and the failure names it, and the fix is to drop the
   flag rather than the target. This is enforced rather than remembered — the
   derived check below reads each invocation's ignore flags next to its own targets,
   so an ignore that takes a root file back out fails exactly as a missing target
   does.

   Anything new outside every package belongs in those passes — and a **file** at
   the root is named explicitly, not folded into a directory glob (the same rule
   step 5 draws inside a package). `*.config.*` is the standing lint target for root
   config and catches the root ESLint config and commitlint's; any other root
   file is named by hand — including one whose `.config.` segment is capitalized,
   since a shell glob is case-sensitive on every platform and `*.config.*` reaches
   `aka.config.mjs` but not `aka.Config.mjs`. A root file carrying `// @ts-check`
   (as `eslint.root.config.mjs` does) is also named in `tsconfig.root.json`'s
   `include`, or the directive is
   decorative — nothing runs `tsc` over it and a real type error surfaces nowhere.
   Miss the pass and esbuild strips its types unchecked and nothing lints it.

   **Forgetting is caught rather than remembered.** `effective-config.test.js`
   derives the set of git-tracked lintable files belonging to no workspace package
   (`git ls-files` minus the `pnpm-workspace.yaml` globs — never a hardcoded list,
   or a file added tomorrow would not be in it), and fails naming each one that no
   eslint invocation lints. The coverage side is derived too, and from what is
   actually **run**: the invocations are walked out of the root `package.json`
   starting at `lint` and following the scripts it **unconditionally** chains, so
   a pass sitting in a script no gate invokes — a `lint:fix`, say — covers
   nothing, and neither does one the chain reaches only on failure. That rule
   applies to the eslint calls inside a script as well as to the scripts it
   chains: `eslint <a> || eslint <b>` reads as two passes and runs the second only
   once the first has already failed, so a green run never lints `<b>`. A
   fault-injection case then plants network code at each real path and requires
   all four network
   rules to fire with no fatal parse error, because a file outside every tsconfig
   `include` reports a parse error and NO rule violations — structurally wired,
   behaviorally correct, enforcing nothing. Adding such a file means adding a lint
   target for it and listing it in `EXPECTED_NON_PACKAGE_FILES`.

   It also means keeping the repo-root glob in `@akasecurity/eslint-config#test`'s
   `turbo.json` `inputs`: the per-package input globs all require a directory
   segment, so without it a new root-level file leaves that task's hash untouched
   and turbo replays a cached green in which the check never ran. Those globs spell
   their extensions by hand, so the same suite drives that list against the one it
   enumerates by — a file whose extension it counts as lintable and the glob omits
   is the same cached-green hole one extension wide.

   Those checks read `turbo.json` as TEXT and match its globs with
   `path.matchesGlob`, which is a MODEL of turbo's hashing rather than turbo's
   hashing. One case asks turbo instead: it plants a lintable file at the repo
   root, runs `--dry=json`, and asserts the hash really moves — the only reading
   that decides whether this suite RUNS. Two things in it are load-bearing. It
   selects the task by `taskId`, because `tasks[0]` is `#build`, whose inputs are
   package-local and which no repo-root file ever moves. And it carries a
   POSITIVE CONTROL that plants under a different input (`tools/ci/**`) first, so
   a broken measurement is reported as a broken measurement rather than as a
   missing glob — without it, "the hash did not move" reads the same whether the
   glob went or the selection did.

6. Add the package name to `EXPECTED_WORKSPACE_PACKAGE_NAMES` in
   `packages/eslint-config/test/effective-config.test.js`. That pinned list only
   forces a human to notice the new package — what actually stops it shipping
   unguarded are the assertions next to it (a missing config, a config that never
   extends the shared one, a `lint` script that misses a directory or a root file, a
   root file the linter cannot parse). A package under `tools/` also takes a
   `WALL_EXEMPT_PACKAGES` entry in `package-walls.test.js`, and moves the lint-script
   count `required-checks.test.js` pins.

7. If it has a `test` script, run those tests through **vitest** and wire the
   no-network guard into its `vitest.config.ts`, then add its name to
   `EXPECTED_VITEST_PACKAGES` in
   `packages/eslint-config/test/no-network-runtime.test.js`. Copy the block from a
   neighbour at the same depth — the relative path is `../../` from
   `packages/<name>/`, `plugins/<name>/` or `tools/<name>/`, and `../` from a
   repo-root package (`cli`, `web-ui`):

   ```ts
   const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));
   // …
   test: { setupFiles: [noNetworkGuard], … }
   ```

   A package whose dependency closure can load `@akasecurity/persistence` wires a
   SECOND setup file beside it, `test/setup/no-managed-settings.ts` — the
   administrative overlay is read from absolute system paths a temp home cannot
   redirect, so without it the package's suite reads whichever administrator the
   developer's own machine is enrolled with. That set is DERIVED rather than
   listed, by `packages/eslint-config/test/no-managed-settings-guard.test.js`, so a
   new package that takes such a dependency is told to wire it rather than
   discovering it as twenty-eight unrelated-looking failures later. See "The
   no-managed-settings guard" under Testing.

   A package that also declares `testTimeout`/`hookTimeout` in that config must add
   itself to `TIMEOUTS` in `packages/eslint-config/test/hook-timeout-ratchet.test.js`,
   which pins every package's ceilings as an EXACT map. The ratchet holds in BOTH
   directions on purpose. Raising a timeout is the change that must not pass unnoticed:
   the per-test SQLite migration above was 'fixed' once by moving this number from
   vitest's 10s default to 20s, which bought a green run and let the same failure spread
   from one package to four. Lowering it is a good change — setup is a file copy now, so
   there is headroom to give back — but a deliberate one. Raising it through the `test`
   script's CLI flags instead is refused by the same suite, since the pin reads config
   literals and a flag would bypass it silently.

   The runner is not incidental: the guard is a vitest `setupFiles` entry, so a
   package testing through anything else (`node --test`, say) runs with no runtime
   network guard at all. That suite enumerates every package with a `test` script
   and fails on any that is not vitest, so such a package has to be argued into
   `EXPECTED_NON_VITEST_TEST_PACKAGES` — a list that is empty and should stay that
   way, since every entry is a hole in the guarantee.

8. If any file the package ships or lints imports a `node:` builtin or reads
   `import.meta.dirname`, declare `@types/node` in its OWN `devDependencies`, at
   the single range every other manifest carries. Omitting it typechecks here and
   fails nowhere in this repo: TypeScript walks up to the repo root's
   `node_modules/@types` and finds the copy the root's devDependencies installed,
   so the manifest reads as complete while the package is only ever built from
   this workspace. It breaks the moment the package is consumed from one that does
   not install this root — TS2307 on the `node:` specifier, TS2339 on
   `import.meta.dirname`. Undeclared, it also lets pnpm resolve vitest's optional
   `@types/node` peer for that importer independently of what the compiler
   resolves from the root, putting two majors in play for one package. Three
   packages carried this at once, which is why it is derived rather than
   remembered: `packages/eslint-config/test/effective-config.test.js` reads each
   package's own tracked source against its own manifest, so a package that skips
   this reds CI instead of being caught in review.

**All three of those guards enumerate the tree at RUN time, which is what makes adding a
package the action most exposed to a stale base.** A `pull_request` check runs against a
merge commit GitHub built when the branch was last pushed and never rebuilds as `main`
moves, so a package added on one branch and a file it would judge added on another are
each green against a tree the other has already changed. Neither diff contains the
mismatch and the first run to see both is the post-merge run on `main` — which is how a
new package's unlinted root config file reddened `main` from a PR whose own diff was
innocent. Deriving is still right; a pinned list stays green through exactly the drift
these exist to catch. What closes it is a repository setting rather than anything in this
tree, and CONTRIBUTING.md's "Branch freshness" section records which one is in use and
what it obliges `.github/workflows/` to carry. Read it before assuming a green PR check
saw your package.
