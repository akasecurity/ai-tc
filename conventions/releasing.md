## Releasing (CLI / plugin versioning)

All five shippable artifacts are **self-contained bundles of the workspace** — their `tsup.config.ts`
sets `noExternal: [/^@akasecurity\//]`, so every `@akasecurity/*` package they use is inlined into
the published output (the user's machine has no `node_modules`). So a change to a _bundled_ package
changes the shipped artifact **even when the app's own `src/` is untouched**:

- **`plugins/claude-code`**, **`plugins/codex`**, **`plugins/antigravity`** and
  **`plugins/copilot`** each bundle `@akasecurity/plugin-runtime` + `plugin-sdk` and
  everything they pull in — `@akasecurity/schema`, `persistence`, `detections`. A change to
  any of those changes ALL FOUR plugins' `scripts/*.js`.
- **`cli`** bundles the same `@akasecurity/*` packages **and** ships the OSS web-ui
  (`web-ui` is `external` to the CLI JS but copied in by `prepack`'s `bundle:web-ui` and
  spawned as a separate Next server). So a web-ui change — or any bundled-package change — changes the CLI.
- **`plugins/copilot` is the fifth published artifact.** It publishes to npm from
  `release-plugin-copilot.yml` on a `plugin-copilot-v*` tag, and its `test/identity-consistency.test.ts`
  fails when `plugins/copilot/package.json` or `plugins/copilot/plugin.json` differs from the
  CLI's version. It has no marketplace: a user unpacks the npm package and installs it with
  `copilot plugin install ./package`, a local-path install the Copilot CLI warns is
  deprecated, and Windows has not been confirmed against a real Copilot CLI install. Its
  Windows CI coverage comes from the derived "every package npm publishes" check in
  `required-checks.test.js`, so the `ci.yml` filter line that names it is required rather than
  pinned by hand.

When a change touches the web-ui or any bundled package and the user wants to publish:

1. **Bump every affected artifact**:
   - web-ui / `local-ops` / `dashboard-ui` / `ui-kit` change → `cli` (bundled into the CLI JS
     and/or the web-ui it ships; the plugins bundle none of these).
   - `schema` / `persistence` / `plugin-runtime` / `plugin-sdk` / `detections`
     change → **all five** of `cli`, `plugins/claude-code`, `plugins/codex`,
     `plugins/antigravity` **and** `plugins/copilot` (all bundle them).
   - `setup-wizard` change → `plugins/claude-code`, `plugins/codex` **and**
     `plugins/antigravity` (all three bundle it; the CLI does not). `plugins/copilot` bundles
     none of its code but its build copies `setup-wizard`'s `assets/triage-rubric.md` into
     `scripts/`, so a change to that asset moves `plugins/copilot` too.
   - The CLI and all four plugins normally move together on one shared version line.
   - **Any `cli` bump → `plugins/browser-extension` too, to the SAME version.** The extension
     ships inside the CLI tarball, its `package.json` is the one place its version lives
     (`scripts/build.mjs` stamps it into `dist/manifest.json`, and the native host records it as
     `meta.pluginBuild` on every session), and `cli/scripts/bundle-extension.mjs` REFUSES to
     bundle a built manifest whose version is not the CLI's. That script runs from the CLI's
     `prepack`, which `ci.yml`'s `packaged-artifact` job runs — so a CLI-only bump reddens
     every pull request, not one release run. The committed `manifest.json` carries `0.0.0`,
     which Chrome rejects, so an artifact nobody stamped is detectable rather than shippable.
     A STORE archive (`package:zip`) is built from a bare version only, and only from a `dist/`
     that agrees with `package.json` on both halves (`storeArchiveRefusal`): every pre-release of
     one core collapses onto the same Chrome `version` and the same archive name, so at most one
     could ever be uploaded, and a stale `dist/` would otherwise ship under the old number.
     Chrome's `version` takes one to four integers and **no suffix**, so a pre-release package
     version is built as its numeric core in `version` plus the whole string in `version_name`
     (`builtManifest` in `src/packaging/store-zip.ts`); the pack-time check reads both halves.
2. Keep `plugins/claude-code/.claude-plugin/plugin.json` in sync with
   `plugins/claude-code/package.json`, `plugins/codex/.codex-plugin/plugin.json` in sync
   with `plugins/codex/package.json`, and `plugins/antigravity/plugin.json` (Antigravity reads
   its manifest from the plugin ROOT, not a dotted dir) in sync with
   `plugins/antigravity/package.json`, and `plugins/copilot/plugin.json` (also at the plugin
   root) in sync with `plugins/copilot/package.json` (identical version within each pair)
   whenever that plugin is bumped. `release-identity.test.js`'s `HOST_MANIFESTS` names all four
   pairs.

**The bump is not a decision to surface during feature work, because it is not made there.**
Pre-1.0.0 the version numbers are chosen **ad hoc**, at the **scheduled release** (twice a week)
— not per change. So do not ask which release type to use, and do not raise "this touches a
bundled package, so it needs a version bump" as an open question, a follow-up, or a caveat in a
summary or PR description. The steps above are what a **release** does: which artifacts move is
derivable from the bundling rules, and how far they move is settled at release time by whoever
cuts it.

Versions are bumped by hand in a `chore(release):` commit (no changesets). A stable release is
a bare `X.Y.Z` on the one shared version line; a pre-release carries a suffix and is routed by
it (below). The CLI and all four plugins currently share the `0.9.x` line.

### Release channels — the suffix decides the dist-tag

Every npm publish step in `release-cli.yml` and the four `release-plugin-*.yml` routes on the
version it is publishing, with one shell `case`: a `-beta.*` version goes to the `beta` dist-tag,
`-nightly.*` to `nightly`, any other suffixed version to `rc`, and a bare `X.Y.Z` to `latest`.
**On npm, only a bare version moves `latest`** — and only a bare `cli-v*` tag moves the
`cli-latest` alias — so a published pre-release stays reachable by its dist-tag and reaches no
machine that did not ask for it. The binary channel gives the same guarantee by a DIFFERENT
mechanism, and the difference is load-bearing: see "Binary (SEA) channel" below. There is no separate
tag prefix for a pre-release: `cli-v0.10.0-beta.1` rides the existing prefix, which is what keeps
each workflow's tag-to-manifest equality check in force. Nothing here notifies the marketplace
that pins the Claude Code plugin: its importer reads what it needs from npm and accepts only an
exact `x.y.z`, so declining a suffixed version is a rule that lives on that side, in one place.

`packages/eslint-config/test/release-channels.test.js` holds that by EXECUTING each publish
step's extracted `case` block under bash against sample versions, rather than by reading the
arms — arm ORDER is the defect that matters (`*-*` ahead of `*-beta.*` sends every beta to `rc`),
and only running it shows that. It reaches the workflows through one shared reader,
`test/helpers/release-workflows.js`, which `release-identity.test.js` uses too: two readers of
one shell string are free to disagree about what a workflow publishes.

**A pre-release moves the whole shared line.** `release-identity.test.js` puts the five
published artifacts on one version and each plugin's identity suite pins it to the CLI's; the
extension is private, so it is outside that audit's set and is pinned to `cli/package.json` by
its own `test/manifest.test.ts`. So `0.10.0-beta.1` is a `chore(release):` commit
moving all five published manifests, the four host manifests and the extension together. Cut
that commit on a release branch: on `main` it would sit in front of the next stable cut until the
matching stable shipped.

**A machine's channel is DERIVED, never stored.** `channelOfVersion` (`@akasecurity/local-ops`,
`src/release-channel.ts` — pure, no I/O) reads it off the first pre-release identifier of the
version a component is RUNNING, per component, every time the update report is built. There is
no settings field, and adding one would be wrong rather than merely bigger: a stored channel can
disagree with the bytes on disk, and it would be a third `settings.json`-class writer (§6). The
update surfaces ask `npm view <pkg> dist-tags --json` and offer the newer of the channel's own tag
and `latest` — that max is the whole graduation mechanism, since `beta` goes on pointing at
`0.10.0-beta.3` after `0.10.0` ships. A stable machine reads `latest` and nothing else.

**What is offered is what is installed.** The install spec is `<package>@<the resolved VERSION>`,
never `@<dist-tag>`, on all three paths — `aka update`, `aka update --channel`, and the
dashboard's apply — because all three build it through one function (`cliInstallSpec` in
`install-channel.ts`). Installing the tag instead is what made a graduated beta machine re-install
its own pre-release and be offered the same update for ever. That version is REGISTRY-SUPPLIED
text headed for argv, so it crosses `isExactSemver` first — not `isSemver`, which trims, so
`' 1.0.0 '` and `'1.0.0\n'` pass it. Anything the strict check refuses is treated as unresolved,
and only then does the spec fall back to the dist-tag from the closed `DIST_TAG` table. Where the
offered version came from is a typed answer (`RELEASE_TAG_SOURCE`: channel, graduated,
unpublished, unknown) rather than something folded into `latest`.

The vocabulary is two const-object registries joined by member name (§2's rule, for the same
reason): `RELEASE_CHANNEL` is what a user types (`stable`), `DIST_TAG` — annotated
`Record<ReleaseChannel, string>` — is what the registry serves (`latest`). Collapsing them makes
the documented `--channel stable` unparseable. The switchable set is derived from `DIST_TAG`'s
keys, never re-listed.

`aka update --channel <stable|beta|nightly>` switches the **CLI only**, including with the `all`
target: a plugin's channel is its host's marketplace registration, which this process cannot
change, so the flag is refused outright for a plugin target. The token is parsed against the
closed union BEFORE any spawn, because the Windows shell path concatenates argv unescaped (§7).
An explicitly requested channel is refused before the report is rendered, before any
confirmation and before any spawn, in either of two registry states — rendering first would
print the stable version beside the requested channel's name, which is the sentence a user acts
on in both. `Unpublished` is a channel that serves NO tag at all. `Graduated` is the other:
the channel HAD a tag, but the stable release has since overtaken it, so `resolveChannel`
answers the request with the stable version rather than one the requested line ever published —
`resolveChannel({latest:'0.12.0',beta:'0.11.0-beta.4'},'beta')` answers `{version:'0.12.0',
source:'graduated'}`, and unrefused that renders as `aka CLI: 0.9.11 → 0.12.0 (beta)`, a stable
release captioned with a channel name it never carried. The derived path keeps its fallback to
`latest` on BOTH states, which is intended: a beta machine whose tag has been retired, or that
has already graduated onto stable, must still be offered the stable rather than refused for a
request nobody made. The binary and Homebrew installs cannot express a channel and say so.
A standalone binary's plan names WHO manages it: `SEA_OWNER` (Homebrew / Scoop / Standalone,
`install-channel.ts`) is derived from the running executable's real path — a brew-prefix-anchored
`Cellar/aka/` keg is Homebrew (`brew upgrade aka`); an `apps/aka/<version or current>/` run is
Scoop (`scoop update aka`) only when a sibling `shims` directory exists at that root, because
`install.ps1 --dir <…>\apps\aka` lays down a byte-identical path on a machine with no Scoop;
anything else is Standalone (re-run the installer one-liner), and only Standalone carries an
`installRoot`. The advice table is annotated `Record<SeaOwner, …>` and `describeSea` has no
default, so a fourth owner fails to compile at both. The npm-under-brew case (`kind: 'homebrew'`,
an npm global inside brew's `node` keg) still prints `brew upgrade aka`, which now names the
tap's formula: it fails on a machine that has not tapped it, and on one carrying both it upgrades
the standalone copy rather than this npm one. Changing that advice is deferred on purpose —
`brew install akasecurity/tap/aka` collides at link with the npm `aka` already in that prefix.
`aka update` only moves forward: switching to a channel whose newest release is behind the
running copy installs nothing and says so. A marketplace `version`
pin is honoured only when it is an EXACT semver — a range used to be returned verbatim, which
froze `updateAvailable` at false for ever.

What is NOT built: nothing publishes a `nightly`, and no beta marketplace entry exists. A Claude
Code marketplace entry pins an exact version or a range, never a dist-tag, while a Codex entry
may name a dist-tag; and Claude Code installs from a different marketplace REPOSITORY
(`akasecurity/marketplace`, as `ai-tc@akasecurity`) than Codex (this one, as `aka-codex@ai-tc`),
so the two entries live in different manifests. A beta door for plugin users is therefore a
per-host decision, and it has not been made. `rc` is a dist-tag the workflows publish and NOT a
channel: `--channel rc` is refused and a machine running an `rc` build reads as stable, so an
`rc` is installed by exact version or `@rc`.

### Release branches

`ci.yml` triggers for `main` AND every `release/**` branch on both `push` and `pull_request`, so
a pull request based on a release branch runs the same jobs and reports the same check NAMES as
one based on `main`. There is deliberately **no lighter gate** for a promotion: the jobs have no
`needs:` edges and run in parallel, so dropping legs saves no wall clock; and "this code already
passed on `main`" is true of each commit but not of the merged tree, which no run has seen.

Two things are outside the tree and stay human steps. Branch protection for release branches is
a repository setting — until it names the same required checks, a release-base pull request
REPORTS them and can still be merged red. A classic protection pattern uses the same `fnmatch`
rules as a workflow filter — `*` stops at a `/` — so `release/*` covers `release/stable` and not
`release/0.9/stable`; the protection-side spelling that matches what `ci.yml`'s `release/**`
matches is `release/**/*`. A branch named bare `release` matches neither list and gets no CI at
all, so release branches are named `release/<something>`. On the push side, the dependency audit,
CodeQL and the internal-path guard still run post-merge for `main` only.

**Where a stable Claude Code plugin tag goes.** A bare `plugin-claude-v<X.Y.Z>` is cut only after
its release pull request merges, on the commit that merge put on `main` (the merge commit, or the
squash or rebase commit when the pull request used one), never on the release branch before the
merge. The commit a stable version's npm provenance names is then one `main` holds, which is what
verifying a release against reviewed code needs; a tag cut before a squash or rebase merge would
name a commit `main` never holds. A pre-release is the exception above: it is cut on its release
branch. `release-plugin-claude.yml` publishes only on the tag push: its manual dispatch has no
publish input and is always a dry run, its npm publish sits behind the tag-to-manifest check, and
its GitHub Packages job waits for that check's job. `release-plugin-claude-gates.test.js` (in
`packages/eslint-config/test/`) pins those gates, and that the workflow reads no secret but its own
`GITHUB_TOKEN`. The release job also refuses a stable tag whose commit `main` does not contain,
before anything publishes; the same suite executes that check against a scratch repository. It is
an early catch for a mistake, not a control: whoever pushes a tag also chooses what that file says
at the tagged commit.

### Binary (SEA) channel — `bin-v*`

The `aka` CLI also ships as a self-contained **Standalone Executable Application (SEA)** — a native
binary that embeds the Node runtime, so end users need neither Node nor npm. This is a **separate
release channel** from the `cli-v*` npm publish:

- **Bare versions only — there is no pre-release lane.** A pushed tag that is not exactly
  `bin-v<X.Y.Z>` is REFUSED by a first `verify-tag` job the build fan-out `needs:`, so it costs
  one runner rather than four and reaches neither the Release nor the `bin-latest` move (which is
  additionally wrapped in a bare-version `case`). That refusal is the ONLY thing standing between
  a pre-release binary and every default install: both installers take the NEWEST `bin-v*`
  release and deliberately ignore GitHub's prerelease flag, and they are themselves fetched from
  `bin-latest`. A real lane would need an opt-in channel selector in both installers, a default
  ref narrowed to bare tags, and a second tag to serve the installers from — none of which
  exists. The guard EXECUTES the refusal block under bash, and separately pins that the block is
  reached at all: falsifying the step's own `if:`, `continue-on-error` on the job, and a
  job-level `if: always()` on the fan-out each left every executing case green.
- **Trigger:** push a tag `bin-v<version>`. It must equal `cli/package.json`'s version —
  `release-binaries.yml` gates on it and fails the release on a mismatch. `workflow_dispatch` runs a
  build-only dry run (no Release).
- **Build:** `release-binaries.yml` builds the SEA on native runners per platform (no cross-compile)
  — `darwin-arm64`, `linux-x64`, `linux-arm64`, `win32-x64` — via `build:sea` → `bundle:web-ui` →
  `package:sea` → `archive:sea`.
- **Assets:** `aka-<version>-<triple>.tar.gz` (`.zip` on Windows) plus an aggregated `SHA256SUMS`,
  and three files the release job RENDERS from that sums file with
  `tools/package-manifests/src/render-manifests.ts` (run under Node 24 type stripping, no pnpm
  install — the release job sets up Node 24 for it): `aka.rb` (the Homebrew formula), `aka.json`
  (the Scoop manifest) and `VERSION`. Both release steps set `fail_on_unmatched_files: true`, so
  a missing asset fails the run instead of publishing a partial release. The
  renderer takes `--version`, `--repo` (required, no default — a fork's dispatch run must not
  render `akasecurity` URLs), `--sums` and `--out`, renders everything in memory and writes
  nothing on any refusal. The formula and manifest point at the IMMUTABLE versioned asset URLs,
  never at `bin-latest`. The `tools/installer/` one-liners verify the download against
  `SHA256SUMS`, fail-closed.
- **`bin-latest`:** on success the workflow force-moves `bin-latest` to the release commit; the
  installer one-liners (`install.sh`/`install.ps1`) are fetched from `bin-latest`, not `main`.
  It then updates a ROLLING GitHub Release on that tag (`Publish the rolling bin-latest release`,
  gated on a push AND on the staging step having seen a bare `bin-vX.Y.Z`, so a dispatch dry run
  cannot touch it) carrying VERSION-LESS alias copies of the four archives
  (`aka-darwin-arm64.tar.gz`, `aka-linux-x64.tar.gz`, `aka-linux-arm64.tar.gz`,
  `aka-win32-x64.zip`), a `SHA256SUMS` naming those aliases, and the three rendered files. That
  is what makes `https://github.com/akasecurity/ai-tc/releases/download/bin-latest/<alias>` a
  stable one-click URL: GitHub's own `/releases/latest` is unusable here — every release is
  flagged pre-release, and seven tag prefixes share one Releases list, so its election could land
  on a plugin release. The aliases are staged in `dist-latest/`, never in `dist/`, because the
  versioned release's `dist/aka-*` globs would otherwise sweep them in under names it never
  promised. The rolling release stays `prerelease: true` and `make_latest: false`.
- **`bin-latest` only moves FORWARD.** The workflow's concurrency group is per tag, so nothing
  else orders two releases: a re-run of an older tag's failed release, or two tags pushed out of
  order, would otherwise move it back. `Decide whether bin-latest moves forward` reads the
  version the tag names on origin and lets through only one at least as new — the SAME version
  included, because re-running is how a half-finished rolling upload is repaired — and the move
  pushes `--force-with-lease` against the value it read, so a release of another version that
  moved the tag in between fails the push instead of being overwritten. A read that fails for
  any reason but "no such tag" refuses rather than moving blind. There is no fixed concurrency
  group: GitHub cancels a pending run when a newer one joins, which drops a whole release, and
  the `queue: max` key that avoids that is rejected by the actionlint version CI pins. What the
  lease does not cover is two releases whose rolling UPLOADS overlap after both moved the tag in
  turn; the tag cannot go backward, the assets can end up mixed, and re-running the newer
  release's job makes them whole. A failure after the tag moved is named in the log by
  `Explain a bin-latest left half-published`. The CAS loser is the other half of the same race:
  by the time its lease is rejected, its OWN versioned Release has already published (the
  `Create GitHub Release` step runs before the move), so it ends with a real Release on a version
  that `bin-latest`, the rolling release and both package managers do not yet serve.
  `Explain a bin-latest move that lost a race` names that case in the log with no retry loop —
  the repair is re-running this tag's whole workflow, which re-reads the tag from scratch and
  only ever moves forward, so a newer winner makes the re-run a no-op.
- **Package managers.** Two jobs after `release`, `publish-homebrew-tap` and `publish-scoop-bucket`,
  push the rendered `Formula/aka.rb` to `akasecurity/homebrew-tap` and `bucket/aka.json` to
  `akasecurity/scoop-bucket` through the contents API, authenticating as a GitHub App rather than a
  person: each job mints its own token with `actions/create-github-app-token` (pinned by commit
  SHA), and the token is revoked when the job ends. The app is configured by one repository
  VARIABLE, `AKA_RELEASE_APP_CLIENT_ID` (it names the app and grants nothing), and one secret,
  `AKA_RELEASE_APP_PRIVATE_KEY`. The mint step is the only step handed the key, and the token it
  returns is handed to the push step alone, as `GH_TOKEN` in its `env:`; the job's gates read a
  boolean (`${{ vars.X != '' && secrets.Y != '' }}`) that tests only that the variable and the
  secret are set, because a job-level mapping of the key would put it in every step's environment,
  the artifact download included. The token's REACH is the mint step's inputs, and the guard pins
  that whole mapping: `owner` AND `repositories` are both named, because given `owner` alone the
  action scopes the token to EVERY repository the app is installed on; `permission-contents: write`
  is named, because a token otherwise inherits all of the installation's permissions; and
  `skip-token-revoke` stays unset. The mint step takes no `env:` and the job's own `env:` holds only
  that boolean, because the action also reads its `permission-*` inputs from `INPUT_PERMISSION-*`
  environment variables, which have no default; no `INPUT_` name appears anywhere in the file. Every
  action in the two publish jobs is pinned by commit SHA, and the two mint steps carry one revision,
  because every step in a job runs as the same user and an unpinned one runs before the key is
  handed out. The key is looked for in every expression in the file rather than in the two publish
  jobs, because the `release` job holds `id-token` and attestation write scopes and a step added
  there reads the same secret by the same name. The workflow is read as a PARSED YAML document
  (`yaml`, YAML 1.2 — a dev dependency of `@akasecurity/eslint-config`, in
  `test/helpers/workflow-yaml.js`), so every check runs on decoded structure: jobs, then steps, then
  each step's keys, `with:`, `env:` and `run:`. A key written quoted, in flow style, behind an
  escape (`"\x24{{ … }}"` spells the dollar of an expression) or through an alias reads the same as
  its plain spelling, and a line that only looks like a key inside another key's block scalar is not
  one. The expressions are read from the DECODED strings, keys and values, since a `#` line inside a
  `run: |` block is script text GitHub still substitutes and a YAML comment is not evaluated by
  anything; string literals are respected, since a `}}` inside one does not end the expression; the
  match is case-insensitive, `toJSON(` is refused outright because it serializes a whole context
  without naming a key, and no job may carry a `secrets:` key at any depth, because a call to a
  reusable workflow hands the key over with `secrets: inherit` without writing an expression. The
  top level and each publish job are built from a fixed set of keys, as are a publish job's steps,
  so a `shell:` template, a `defaults:` block, a `continue-on-error`, a `container:` or a
  workflow-level `env:` is a failure in whatever spelling it is written rather than something no
  case reads; a permission is `write` however its value is quoted; the download step's whole `with:`
  mapping is pinned, because `repository`, `run-id` and `github-token` would make it fetch another
  repository's run; and the fail-closed, notice and explanation scripts are RUN and their exit
  status and output read, since a pattern cannot tell `exit 0 # exit 1` from `exit 1`. The reader
  refuses what it cannot decode faithfully rather than guess: a parse error or warning, a duplicate
  key, more than one document, a `%YAML` directive, a `%TAG` directive that names a handle other
  than `!!`, a key that is not a string, an alias with no anchor before it, an alias that points at
  a node it sits inside, a document
  that decodes to 20,000 nodes or more (the alias-chain backstop, `MAX_NODES` in
  `helpers/workflow-yaml.js`; the largest workflow here decodes to under 300, so raise it only if a
  real workflow approaches it), and a `<<` merge key — GitHub's parser follows YAML 1.2, where that
  is an ordinary key, so a reader that expanded it would report a mapping the runner may never
  build. Anchors and aliases are decoded. The version a pinned
  `uses:` names in its trailing `# v1.2.3` comment is a comment, which the reader keeps beside the
  value it trails. These are an early catch for a mistake, not a control — whoever can change the
  workflow can change its guard. The installation is the ceiling on all of this and nothing in this
  tree can observe it: the app must be installed only on the tap and the bucket, with Contents (read
  and write) as its only chosen repository permission, and Metadata: read is mandatory for every
  app. CONTRIBUTING.md's setup steps are what establish that. Both targets are HARDCODED rather than
  repository variables, so the READMEs can be held to the same spelling. Each job holds
  `contents: read` here and no write scope. On the canonical repository an unconfigured app FAILS
  the job with an `::error::` naming both halves — the Release and the `bin-latest` move have
  already happened, so the red run is the signal to configure the app and re-run, which a content
  compare makes a no-op. A mint that fails once the app is configured (not installed on the
  repository, a wrong client id, a key rotated incorrectly) is explained by a step gated on that
  step's own outcome, since the action's own error says nothing about what already shipped. A re-run
  executes the workflow as it was at the tagged commit, so configuring the app and re-running
  repairs a release whose tag already carries the app steps; one tagged before them is not repaired
  that way. A fork with no app configured skips. Each push only moves forward as well: the version
  already there is read off its versioned download URL, which both formats carry, and a file serving
  a newer one is left in place — so re-running an older release, or this job alone, cannot downgrade
  the tap or the bucket. A non-empty existing file that names no such URL at all — hand-edited, or
  written by something other than this renderer — has nothing in it to compare against, so the push
  `::warning::`s and still writes rather than either silently keeping it or silently overwriting it.
  And the write itself is wrapped: a PUT the contents API refuses (two releases racing the same
  file, say) ends the step with an `::error::` naming the repair — re-run this job, which re-reads
  the file and leaves a newer one alone — instead of the script's own success line. The formula
  installs the whole archive directory into `libexec` and symlinks `bin/aka` (Node resolves
  `process.execPath` through the symlink, which is how `boot.cjs` still finds its sidecars);
  `brew install ./aka.rb` from the attached copy is refused by current Homebrew, so the attached
  `aka.rb` is an audit copy and the tap is the only Homebrew door. `scoop install <url>` of the
  attached `aka.json` IS an install path. There is no darwin-x64 build, so the formula refuses Intel
  macOS (`depends_on arch: :arm64`).
- `cli-v*` (npm) and `bin-v*` (binary) are **independent** — a binary release needs no npm publish
  and vice versa, though they normally share one version line.
- **Signing state, stated exactly.** The macOS binary is AD-HOC signed (`codesign --sign -`), which
  is mandatory rather than decorative: injecting the blob invalidates Node's own signature, and an
  unsigned arm64 Mach-O is killed at exec. It is NOT Developer ID signed and NOT notarized. The
  Windows binary carries no VALID signature. `package-sea.mjs` strips `node.exe`'s own
  Authenticode signature before the inject, but best-effort: it ships unsigned when the strip
  lands, and carrying `node.exe`'s now-invalid signature — which Windows reports as tampered
  rather than as unsigned — on any of the three other outcomes the step reports: no SDK
  `signtool` found, the SDK lookup failing, or the strip itself failing. None of them fails the
  build, and the build log says which.
  The order is load-bearing on both platforms (remove signature → inject → sign on
  macOS; remove → inject on Windows) and is pinned over a COMMENT-STRIPPED read of the script,
  since commenting a call out kept a plain text match green.
- **Provenance.** Every asset the two releases publish — each archive, `SHA256SUMS`, the three
  rendered files, and the rolling release's alias set — carries a build-provenance attestation,
  made in the `release` job by `actions/attest` pinned to a commit SHA and gated on `push`, so
  the `workflow_dispatch` dry run attests nothing. The alias ARCHIVES are byte-identical renames,
  and `gh attestation verify` identifies an artifact by its digest, so they verify against the
  same attestation under their new names; the alias `SHA256SUMS` is new bytes and is attested in
  its own right. Only that job holds `id-token: write` and `attestations: write`; the build
  fan-out and the two publish jobs hold neither, and the workflow's top-level block grants no
  write scope for any of them to inherit.
  `packages/eslint-config/test/release-binaries-integrity.test.js` holds all of that, slicing the
  attest STEP rather than the job (the release-creation steps name the same globs, so a job-wide
  match is inert) and requiring the attest subjects to EQUAL the union of every softprops step's
  `files:` in both directions — which is why the aliases must be staged before the attest step
  and why a rolling asset can never ship unattested. **The installers do not verify the attestation and never require `gh`** — they
  verify the checksum and stop. That checksum arrives from the same release as the archive, so it
  catches a corrupt download and not a replaced release; `gh attestation verify <asset> -R
<owner>/<repo>` is the manual check that does. `install.sh`/`install.ps1` themselves come from
  the movable `bin-latest` tag and are covered by neither.
