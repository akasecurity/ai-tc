### 7. A command spawned by BARE NAME goes through the planner

`planBareCommand` (`packages/plugin-sdk/src/bare-command.ts`, the `./bare-command` subpath)
is how every bare-name spawn in the plugins is built. Three facts have to hold together, and
handling any one of them alone makes things worse rather than better:

- **libuv does no PATHEXT.** Its own executable search tries `.com` and `.exe` and stops, so a
  shell-free `execFileSync('claude', …)` never sees the `claude.cmd` an npm global install put
  on PATH. It fails **ENOENT** — the same code a genuinely-absent CLI produces, which is why
  this read as "not installed" rather than as a batch-file problem for as long as it did.
  Reaching the shim needs a shell, exactly as `packages/local-ops/src/exec.ts` says.
- **Windows searches the working directory BEFORE PATH.** So the moment a shell is involved, a
  `claude.cmd` in a cloned repo runs instead of the real CLI. Every Windows spawn is anchored at
  `homedir()`; nothing spawned this way depends on the caller's cwd. POSIX never consults the
  cwd, and no anchor is added there.
- **A shell RE-PARSES the argv.** Node joins `[file, ...args]` with a space and hands the result
  to `cmd.exe` verbatim — it says so itself, in DEP0190: "the arguments are not escaped, only
  concatenated". So `shell: true` on its own is not a fix, it is a command-injection surface
  wherever an argument carries content this repo did not choose.

The planner's answers to the third are what must not be softened. It quotes each argument
itself and passes the joined line as the FILE with an empty args array, so Node has nothing left
to concatenate; it **refuses** — `BareCommandUnsupportedError`, never a best-effort escape — an
argument carrying `"`, `%`, `!`, a line break or a NUL, or a line over cmd.exe's 8,191
characters; and its refusal `reason` names an argv INDEX and a character class, never a value,
because the one caller that reaches it in practice is refusing a raw-bearing prompt. It also
skips the shell entirely when the bare name resolves (via `where.exe`) to a real executable,
which removes the re-parse, the 8 KiB ceiling and the extra `cmd.exe` process at once — the
binary channel's `aka.exe` takes that path.

**Two measurements inside that are easy to get subtly wrong, and both fail SILENTLY.** What
counts as "a real executable" is an **allowlist** — `.exe` and `.com`, what `CreateProcessW`
loads as an image — never a `.cmd`/`.bat` denylist. An npm global install writes an
EXTENSIONLESS launcher (a Bourne script, for Git Bash) beside the shim, and `where` prints that
line FIRST: `…\npm\aka` before `…\npm\aka.cmd`. A denylist therefore takes the direct path and
hands a shell script to `CreateProcessW`, which fails **ENOEXEC** — a different code from the
ENOENT every caller here tests for, so the CLI reads as installed and the spawn then does
nothing at all. And the 8,191 ceiling is charged against the line **cmd.exe is handed**, which
is Node's `<COMSPEC> /d /s /c "<line>"` and not `<line>`; measuring the inner line alone admits
one that is then truncated rather than refused, which is the whole failure the refusal exists to
prevent. `where.exe` also runs under its own timeout, because a PATH entry on an unreachable
network share blocks that search for as long as the OS takes to give up — and it runs in front
of a launcher meant to return at once, and before the judge's own spawn timeout, which cannot
bound something that has not spawned yet.

**Antigravity's judge used to be the case that could not be made to work through `cmd.exe`, and
what closed it is worth keeping.** Its prompt rode ARGV, so it was multi-line, several KiB, and
built from scanned transcript text — three independent reasons a Windows command line cannot
carry it — and the planner refused that plan outright rather than escaping it hopefully. The
repair was to stop needing the command line: the prompt now rides stdin (§4), so the argv is
fixed flags, it crosses `cmd.exe` intact, and an `agy.cmd` shim is reachable like any other
host's. That retired `judge-argv-unsupported.ts`, the gate that had kept that plugin's
wizard-journey suite off the Windows leg because its stub can only ever be a `.cmd`. The
property is pinned behaviourally in `plugins/antigravity/test/triage/judge.test.ts` — against
the real planner and the real argv `runJudge` builds, with a positive control that the prompt is
still large, multi-line and raw-bearing — so putting anything raw-bearing back on argv goes red
there rather than only on Windows. **A refusal is still the right answer where an argv genuinely
cannot cross**; what changed is that this argv no longer has to.

**A probe in front of such a spawn reads the plan rather than re-deriving it.** A shell-free
probe ahead of a shelled spawn reports a false miss and the reverse a false pass, and the PATH
shims fail OPEN (see [Testing](#testing)), so a false pass reaches the developer's real
installed CLI. The journey harnesses pass `plan.viaShell` and `plan.options.cwd` straight
through to `assertShimResolves` for that reason.

`packages/plugin-sdk/test/bare-command.test.ts` drives every branch from any host — the planner
takes `platform` and a resolution seam the way `judgeEnv`/`writeCommandShim` take a platform.
**Three** sites deliberately do NOT go through it, and they are unsafe to different degrees:

- `cli/src/lib/external-dispatch.ts` is POSIX-only by design, so none of the three facts apply.
- `plugins/claude-code/src/provenance.ts` shells out to `npm` with its own `USE_SHELL` because
  `npm audit signatures` reads the caller's project — it therefore carries the shell half
  **without** the cwd anchor. On Windows that is the cwd-before-PATH hazard this section opens
  with, reached from a repository the user merely opened. It is NOT exploitable today for a
  reason outside this module: the function has no shipped caller and is tree-shaken out of every
  built script (see §4). So it is a gap in the SOURCE rather than in the artifact — and wiring
  the check back without anchoring or resolving the spawn first is what would make it live.
- `packages/local-ops/src/exec.ts` carries `USE_SHELL` **and** the `homedir()` anchor, so it has
  both halves of the cwd defence — but no quoting and no refusal, so on the shell path Node
  concatenates its argv unescaped exactly as DEP0190 describes. It is not exploitable today, and
  the reasons now differ per argument. The CLI update's npm argv is no longer built entirely from
  the `CLI_PACKAGE` constant: it also carries a REGISTRY-SUPPLIED version — an update report's
  resolved answer for a channel, which `npm view` supplied. That version crosses only through
  `isExactSemver` inside `cliInstallSpec`, which is TOTAL (a non-string is refused rather than
  thrown on), refuses anything over npm's own 256-character limit, and admits no whitespace and no
  shell metacharacter — so nothing that reaches this argv can break out of the unescaped
  concatenation, and anything the check refuses falls back to a dist-tag from the closed
  `DIST_TAG` table instead. Plugin arguments are still refs resolved from the static
  `AGENT_PLUGINS` registry after validating the caller-supplied id against it — that half remains
  a **hand-maintained invariant in a comment**, the precise class this module converts into a
  structural one everywhere else — and `local-ops` already depends on `@akasecurity/plugin-sdk`,
  so routing it through `planBareCommand` is available rather than blocked by a package wall.
  Migrating it is tracked separately.
