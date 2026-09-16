---
card: cd_mu3ykpbj1io
title: GitHub Copilot — cover the CLI + VS Code agent mode
stage: spec
created: 2026-09-16
---

## Summary

AKA Traffic Control ships hook adapters for Claude Code, Codex CLI and Antigravity. GitHub
Copilot is the largest uncovered harness and it is not one harness — it is seven surfaces
(Copilot CLI, VS Code agent mode, the cloud coding agent, JetBrains, Visual Studio, Xcode,
and a Claude agent hosted inside Copilot Chat) that disagree about event names, payload
casing, which fields may be rewritten, and — the dangerous one — **what silence from a hook
means**. This card builds `plugins/copilot`, a single workspace package covering the Copilot
CLI and the VS Code Local harness in one adapter with two payload dialects, plus a
repo-committed hook manifest for the cloud coding agent, and closes with a decision gate for
the three IDE surfaces.

Three things are already true in the tree and shape everything below.

**Phase A is partly landed.** `plugins/copilot` exists as a registered workspace package
carrying `src/identity.ts` (a placeholder constant), eight recorded CLI hook payloads under
`test/fixtures/cli/`, a fixture README that is the most complete description of this host
anywhere in the repo, and `test/cli-fixture-shapes.test.ts` pinning them. Copilot CLI 1.0.83
has been driven live under an isolated `$COPILOT_HOME`; a `preToolUse` deny, a `modifiedArgs`
rewrite, and `ask`-resolves-to-deny are all confirmed by effect.

**The wire vocabulary already exists.** `SOURCE_TOOL.Copilot` (`'github-copilot'`),
`HARNESS.Copilot` (`'copilot'`) and their `TOOL_TO_HARNESS` row are in
`packages/schema/src/zod/harness-map.ts` today; `Provider` and `FindingProvider` both carry
Copilot, and `SCAN_COVERAGE` carries a `{ coverage: 0, supported: false }` row. What is
missing is the read side's harness-card vocabulary (`HarnessId`, `HARNESS_LABELS`,
`TITLE_NEEDLES`, `resolveHarnessId`) and any `AGENT_PLUGINS` entry at all.

**Two probes that decide the wrapper's shape are blocked**, by an account-side context-budget
error rather than by anything a hooks file did. Per operator decision, this card does not
wait on them: the adapter takes the shape that is correct whichever way they resolve.

## User problem

A developer or a security team running AKA today gets prompt capture, secret detection,
redaction and blocking across Claude Code, Codex and Antigravity — and **nothing at all** in
GitHub Copilot. The dashboard's scan-coverage row for Copilot reads 0 and unsupported, which
is honest and useless: a Copilot user's prompts, shell commands and file writes leave the
machine with no inspection, no audit row and no policy, while the same machine's Claude Code
traffic is fully governed. Coverage that stops at one vendor is not a control plane; it is a
gap with a dashboard in front of it.

The Copilot case is harder than the three already covered, in a way that produces its own
distinct failure:

- **Silence is not one convention.** On Copilot CLI, a `preToolUse` hook that crashes or
  exits non-zero is documented to **deny** the tool call, while a hook that times out allows
  it. On VS Code it depends on which harness the "Local" session target runs, and that is
  unknown. An adapter written with this repo's default assumption — exit 0, print nothing,
  mean "no opinion" — would, on the CLI, turn every AKA crash into a blocked tool call and
  wedge the user's session. That is the exact inversion §1 of `CLAUDE.md` already documents
  for Antigravity, arriving at a second host with a second set of rules.
- **One session store, many producers.** `~/.copilot/session-state/<uuid>/events.jsonl` is
  written by the CLI, by VS Code's Copilot Chat, and by other surfaces. A backfill that reads
  it without attributing by producer will double-count against whichever adapter also
  captured the session live.
- **The event name does not reach the hook.** Seven of the eight recorded payloads carry no
  `hookName` at all (`permissionRequest` is the exception). A dispatcher keyed on the payload
  cannot tell `preToolUse` from `postToolUse`.

## Desired behavior

`plugins/copilot` is one npm-published, self-contained plugin bundle — the fourth alongside
Claude Code, Codex and Antigravity — that:

1. **Captures** prompts, shell commands, file writes and tool results from Copilot CLI and
   VS Code agent mode into the same local `~/.aka/data/aka.db` every other adapter writes to,
   stamped `sourceTool: 'github-copilot'` and carrying a `harnessInterface` of `cli`,
   `vscode` or `cloud`.
2. **Enforces** the workspace policy at the same four levels the other adapters do — block,
   redact, warn, monitor — using each surface's own rewrite channel where one exists
   (`modifiedArgs` on the CLI, `hookSpecificOutput.updatedInput` on VS Code) and the
   configured `redactFallback` where none does.
3. **Never breaks a session**, under a rule that is correct on a fail-open host and a
   fail-closed one simultaneously: every `preToolUse` exit path prints exactly one JSON
   object, and when no opinion was reached that object is an explicit allow.
4. **Reports** what it can and cannot do per surface, in `skills/setup/SKILL.md`'s Known
   limitations, matching a capability matrix derived from fixtures rather than from prose.

### The fail convention, stated once

This is the load-bearing design decision and it is the same on both dialects, which is worth
saying plainly because it looks like it should not be.

| Host reading of "exit 0, empty stdout" | Explicit allow is | Silence is       |
| -------------------------------------- | ----------------- | ---------------- |
| allow (fail-open, Claude-Code-like)    | correct           | correct          |
| deny (fail-closed, Antigravity-like)   | correct           | a wedged session |

Printing an explicit `{"permissionDecision":"allow"}` is correct under **both** readings.
Silence is correct under only one. Since the CLI's reading is unmeasured and VS Code's
depends on an unidentified harness, the adapter prints. This resolves the blocked probes from
a gate into an optimization: confirming that CLI silence means allow would _permit_ the
silent shape, and nothing in this card depends on it.

The corollary is that `plugins/copilot`'s `src/hooks/shared.ts` follows **Antigravity's**
`runHookFailOpen` template — the watchdog race, the seeded `failOpen` payload, the awaited
single-object emit, `process.exit(0)` — for `preToolUse`, and Claude Code's silent shape for
every other event, where both hosts agree that nothing printed is no opinion.

`runHookFailOpen`'s documented limit transfers unchanged and must be restated rather than
softened: the guarantee covers everything that **yields** (a throw, an undecided body, a body
that outruns the watchdog) and cannot preempt a body that blocks the thread. The blocking
stretches are the same two — synchronous `node:sqlite` whose `PRAGMA busy_timeout = 2000` is
charged per contended statement, and §5's in-process `scan()` on a ruleset with no pulled or
custom regex rule. Copilot's host timeout is 30 s rather than Antigravity's 10 s, which gives
more headroom, not a different property.

### Two dialects, one package

Detected from the stdin envelope, not from argv:

|                       | Copilot CLI / cloud                                         | VS Code Local                                         |
| --------------------- | ----------------------------------------------------------- | ----------------------------------------------------- |
| Session key           | `sessionId`                                                 | `session_id` (only when known)                        |
| Event name in payload | absent (except `permissionRequest.hookName`)                | `hook_event_name`, always                             |
| Casing                | camelCase (one exception: top-level `stop_hook_active`)     | snake_case envelope, camelCase `tool_input`           |
| Tool name key         | `toolName`                                                  | `tool_name`                                           |
| Tool args key         | `toolArgs`                                                  | `tool_input`                                          |
| Workspace             | `cwd`                                                       | `cwd`, only when the hook entry declares one          |
| Deny shape            | top-level `permissionDecision` + `permissionDecisionReason` | `hookSpecificOutput.permissionDecision`               |
| Input rewrite         | `modifiedArgs`                                              | `hookSpecificOutput.updatedInput` (last hook wins)    |
| Output rewrite        | `modifiedResult`                                            | none — `decision: 'block'` + `additionalContext` only |

The presence of `hook_event_name` is the primary discriminator and is the one field VS Code
is documented to send on every event. `sessionId` versus `session_id` is the secondary one,
used when `hook_event_name` is absent.

**Per operator decision, the VS Code dialect is built from Microsoft's published contract
rather than from live recordings.** This is a deliberate, named exception to the card's own
"fixtures captured live, never written from docs" rule, and it carries three obligations that
are functional requirements below, not caveats: doc-derived fixtures live in a separate
directory that cannot be mistaken for recordings, every doc-derived capability row is marked
unverified in the matrix and in `SKILL.md`, and the VS Code half ships with its enforcement
claims stated as unverified until a live pass replaces them.

### The event name reaches the hook on argv

Seven of eight recorded CLI payloads carry no event name. The installed hook manifest
therefore registers one command per event with the event name as a literal argv token —
`<node> <script> preToolUse` — exactly as the recording script that produced the fixtures
did. The adapter must never infer its own event from payload shape.

## User flows

**Flow 1 — a developer installs coverage for the Copilot CLI.** They run
`aka plugins install copilot`. AKA writes `~/.copilot/hooks/aka.json` with absolute paths to
the bundled hook scripts and an absolute path to the Node binary, merging into any existing
file rather than replacing it. The next `copilot` session's first tool call is scanned. If the
Copilot plugin channel is available and the marketplace ref resolves, AKA offers that route
instead; the file-drop remains the floor.

**Flow 2 — a secret reaches a shell command.** The developer asks Copilot to deploy with a
live token. `preToolUse` fires for the `bash` tool; `toolArgs.command` is scanned;
`secrets/*` matches at `block`. The hook prints
`{"permissionDecision":"deny","permissionDecisionReason":"…"}` with exit 0; the CLI's
transcript reads `Denied by preToolUse hook` and the command does not run. An audit row and a
`blocked_detections` row land with the value masked.

**Flow 3 — the same secret under a `redact` policy.** On the CLI, `modifiedArgs` rewrites
`command` in place and the masked form runs. On VS Code, `updatedInput` carries the full
camelCase object for the exact tool id. In both cases, a redact on an **executable** field is
not rewritten — the runtime declares the field unrewritable, resolves the configured
`redactFallback` (`monitor | warn | block`, shipped `warn`), and reports what it became via
`redactDegradedTo`, which the decision module reads rather than re-deriving.

**Flow 4 — the hook crashes.** `openLocalDatabase` throws on a corrupt store. The
`preToolUse` body rejects, `runHookFailOpen`'s catch leaves `output` at its seeded
`{"permissionDecision":"allow"}`, one object is written and awaited, and the process exits 0.
The tool call proceeds. Nothing is captured for that call and the session is not broken.

**Flow 5 — a cloud coding agent run.** The repo carries `.github/hooks/aka.json` on the
default branch. `copilot-setup-steps.yml` installs Node 24, `@akasecurity/cli` and the plugin,
and attaches the runner to the organization's control plane from an Agents-type secret. Hooks
capture through the run; `sessionEnd` drains in runner mode. If the setup step failed, `~/.aka`
is absent and every `preToolUse` still prints an explicit allow.

**Flow 6 — a user runs `/aka-setup`.** The wizard scans `~/.copilot/session-state/*/events.jsonl`
for historical secrets, attributing by producer so sessions belonging to another adapter's
surface are skipped. With explicit consent it runs a judge subprocess under a throwaway
`COPILOT_HOME` pre-seeded with `{ "remoteExport": false, "autoUpdate": false }`, which is
deleted in a `finally`.

## Functional requirements

### Package and structure

- The package MUST remain `plugins/copilot`, name `@akasecurity/ai-tc-copilot`, and MUST
  follow every step of `CLAUDE.md`'s "Adding a new workspace package" checklist. Steps 1–7 are
  already satisfied by the landed skeleton; step 8 (`@types/node` in its own
  `devDependencies`) is satisfied and MUST stay so.
- It MUST lose `"private": true` and gain a `tsup.config.ts` with
  `noExternal: [/^@akasecurity\//]`, emitting `scripts/*.js` plus `scripts/scan-worker.js` as
  a sibling build entry (§5 — the worker is a build entry, not a file the loader finds).
- `src/identity.ts`'s placeholder comment MUST be removed once the package ships behaviour.

### Hook entries and the fail convention

- Every `preToolUse` entry MUST print exactly one JSON object on every exit path and MUST exit 0. When no opinion was reached that object MUST be `{"permissionDecision":"allow"}` (CLI
  dialect) or `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
  (VS Code dialect).
- Every other event's hook MUST fall back to **silence** — exit 0, empty stdout — since both
  hosts read that as no opinion on those events.
- A hook MUST NOT exit 2, ever, by any path. On VS Code exit 2 blocks and shows stderr to the
  model; AKA's blocks go through the decision field, never through an exit code.
- `emit` MUST take a narrowed union type (Claude Code's `HookOutput` pattern), not `unknown`,
  so a new output shape cannot reach stdout without being named. The write MUST be awaited.
- A `hook-output-shapes` test MUST pin both dialects' output shapes against that union, in
  both directions (a union variant not in the map, and a map entry whose variant is gone).
- The watchdog MUST sit under the host's 30 s timeout with margin. It MUST be a parameter so
  the timing property is drivable in milliseconds.
- The adapter MUST take its event name from argv. It MUST NOT infer the event from payload
  shape.

### Dialect detection and field tables

- Dialect detection MUST key on `hook_event_name` first and the `sessionId`/`session_id`
  spelling second. An envelope matching neither MUST be treated as no opinion (explicit allow
  on `preToolUse`, silence elsewhere).
- Two `SCANNABLE_FIELDS` tables MUST exist, one per dialect, each `Record<string, readonly
ScannableField[]>` with `{ field, executable }` entries, following the Codex and Antigravity
  template. They MUST NOT be merged into one table with aliases; the tool vocabularies do not
  overlap.
- The CLI table MUST cover at minimum `bash.command` (executable) and `apply_patch` (not
  executable). `bash.description` is model-authored text and SHOULD be scanned as a
  non-executable field.
- `preToolUse` MUST be the scan point for tool input, never `permissionRequest`:
  `permissionRequest.toolInput` is a strict subset of `preToolUse.toolArgs` (`command` only in
  the recording), so scanning it would silently skip `description`.
- The hook MUST exit before the store is opened when the tool name is not in the table. VS
  Code spawns the hook for every tool call — its matchers are parsed and ignored — so this
  fast path is the difference between a per-call store open and none.
- A vault-pointer in an **executable** field MUST deny before the secret scan and before the
  store is opened, following `decideInputPointerDeny`.

### Redaction

- On the CLI, a redact MUST be carried out through `modifiedArgs`. On VS Code it MUST be
  carried out through `hookSpecificOutput.updatedInput` carrying the **full** camelCase object
  for the exact tool id, not a partial patch.
- A redact on an executable field MUST read `result.redactDegradedTo` rather than re-deriving
  the escalation, so the emitted decision, `findings.actionTaken` and the ledger read one
  answer.
- VS Code's `updatedInput` is last-hook-wins. Where AKA's rewrite may be discarded by a
  later hook, the audit row MUST record what AKA decided and MUST NOT claim the rewrite
  reached the tool. `SKILL.md` MUST say so.

### Session, stop and provider

- `session-start.ts` MUST call `handleSessionStart({ tool: SOURCE_TOOL.Copilot, harnessVersion,
harnessInterface })` with `harnessInterface` ∈ `cli | vscode | cloud | jetbrains` as opaque
  strings. `harnessInterface` has no Zod schema and is validated only as a string; it lands in
  the attribute bag and is deliberately not part of the content-addressed identity key.
- `harnessVersion` MUST come from `copilotVersion` in the session store's `session.start` event
  (CLI) or the built-in extension's `package.json` (VS Code).
- The once-per-session pass MUST tolerate running **after** the session's first prompt. The
  recordings show `userPromptSubmitted` and `userPromptTransformed` stamped 20 ms _before_
  `sessionStart`. A pass that assumes it runs first will miss that prompt's inventory context.
- Provider resolution MUST record `unknown` with the model id taken from the event stream,
  until the provider seam is widened (D7).

### Capture correctness

- `postToolUse.toolResult.resultType` MUST NOT be read as the command's exit status. It
  reports tool-invocation success; the recorded command `false` produced `"success"`, with the
  exit code only as free text in `textResultForLlm`.
- `userPromptSubmitted.prompt` is not the whole of what reaches the model.
  `userPromptTransformed.transformedPrompt` wraps it in scaffolding the user did not write.
  The adapter MUST capture the prompt from `userPromptSubmitted` and SHOULD record the
  transformed form separately rather than conflating them.
- `preToolUse` and `permissionRequest` both fire for one tool call, in that order, even under
  `--allow-all`. The adapter MUST NOT record two tool-use events for one call.

### History and backfill

- `src/history/transcripts.ts` MUST read `~/.copilot/session-state/<uuid>/events.jsonl` keyed
  on `session.start.data.copilotVersion` and MUST be version-tolerant: this is not a stable
  API, and the one locally available sample was written by 1.0.15.
- The backfill MUST skip sessions whose `producer` / `context.hostType` belongs to another
  adapter's surface, so a machine running both the Claude Code plugin and Copilot does not
  double-count.
- `src/backfill.ts` MUST exclude the live session by `sessionId` from stdin plus a timestamp
  cutoff.
- Historical scanning MUST remain gated on the existing `historicalAccess` grant. That grant
  authorizes the READ only.

### Judge

- The judge MUST spawn under a throwaway `COPILOT_HOME` pre-seeded with
  `{ "remoteExport": false, "autoUpdate": false }` and a temp workspace carrying no
  `.github/hooks`, so neither user nor repo hooks re-enter AKA's own hooks. The throwaway home
  MUST be deleted in a `finally`.
- The prompt MUST ride **stdin**, not argv, and argv MUST be fixed flags only, routed through
  `planBareCommand` (§7). `copilot` is a `.cmd` shim under npm and a native `.exe` under
  winget, so both planner paths are live.
- It MUST send the same minimized `toJudgePayload` projection the other three judges send —
  `rawMatch`, the re-masked `context` window, the sequential `id`; never `filePath`,
  `valueFingerprint` or `keyVersion` — under the same distinct `modelJudgeConsent` opt-in and
  `MODEL_JUDGE_PAYLOAD_VERSION` re-check.
- Consent copy MUST state the model-API egress **and** that without the pre-written
  `remoteExport: false` a judge session would sync to the user's GitHub account. It MUST NOT
  describe the subprocess as isolated from the network.
- `CLAUDE.md` §3's opt-out table MUST gain an eleventh row and its count word MUST move; §4
  MUST gain a numbered egress item. The READMEs' `[^egress]` footnote counts are derived from
  `EGRESS_PATHS` in `plugins/claude-code/test/privacy-claims.test.ts` and MUST move with it.

### Registry and read-side vocabulary

- `AGENT_PLUGINS` MUST gain a `copilot` entry with `sourceTool: SOURCE_TOOL.Copilot` and a
  distinct `pluginName` (an identical ref across two entries makes either plugin's ledger
  entry satisfy the other's installed check).
- `HarnessId` MUST be extended with `'Copilot'`. That makes `HARNESS_LABELS` and
  `TITLE_NEEDLES` rows compile-mandatory. `resolveHarnessId`'s dispatch chain is **not** type
  enforced and MUST gain its line explicitly — this is the known silent gap.
- `SCAN_COVERAGE`'s Copilot row MUST move off `{ coverage: 0, supported: false }` to a
  justified number with the argument recorded (D5). The CLI is richer than Antigravity —
  prompt capture plus input and output rewrite; VS Code Local is poorer — no output rewrite.
  A single number over both surfaces SHOULD reflect the weaker one, or the row SHOULD be
  argued as covering the CLI with VS Code's gaps named in `SKILL.md`.

### Distribution

Per operator decision, both channels, with file-drop as the floor.

- `aka plugins install copilot` MUST write `~/.copilot/hooks/aka.json` with absolute script
  paths and an absolute Node path. `--project` MUST write `.github/hooks/aka.json`.
- **This is new machinery.** Nothing in `local-ops` writes a hook file into a host's config
  directory today — install is either delegated to the host CLI (Claude Code, Codex) or
  printed as an `installHint` (Antigravity). The writer MUST go through
  `writeOwnerOnlyFileSync` and MUST take a file lock if it ever performs a read-modify-write,
  per §6.
- Install and uninstall MUST be idempotent over a pre-existing `~/.copilot/hooks/` file
  carrying foreign entries: AKA's entries are merged in and removed again, and no foreign
  entry is disturbed.
- The plugin channel (`copilot plugin marketplace add` + `copilot plugin install`) MUST be
  added behind the file-drop once D4 settles, adding `CliPluginBin 'copilot'`, `HOST_VERBS`
  entries and an installed-version reader over `~/.copilot/installed-plugins/`. A registry
  entry carrying **both** `pluginRef` and `npmPackage` is counted by the passive update
  notice's `npm view` sweep, so that count MUST move in both READMEs' `[^egress]` footnotes
  and in `CLAUDE.md` §4 item 1 in the same change.
- The hook manifest MUST be one Copilot-CLI-format `hooks.json` that the CLI, the cloud agent,
  JetBrains and VS Code (which converts CLI-format files) all read. Per-surface differences
  MUST be handled in the scripts, not in the file.
- The installed command line MUST be valid PowerShell 5.1 on Windows, with quoted node and
  script paths — VS Code executes it through `powershell -ExecutionPolicy Bypass`, so §7's
  cmd.exe quoting rules do not apply there.

### Fixtures and the doc-derived exception

- CLI fixtures MUST remain live recordings under `test/fixtures/cli/`. New CLI recordings MUST
  be described in the existing README, which the shapes test holds to the file set.
- VS Code fixtures MUST live under a directory whose name marks them as doc-derived — e.g.
  `test/fixtures/vscode-provisional/` — with a README stating plainly that no live session
  produced them, naming the vendor pages they were written from, and listing every field whose
  presence, casing or type is unverified.
- A test MUST fail if a doc-derived fixture is moved into the recordings directory without a
  README entry describing its capture.
- The capability matrix MUST carry a verified/unverified column, and every VS Code row MUST
  read unverified until replaced by a recording.
- `SKILL.md`'s Known limitations MUST state that VS Code enforcement is built to the published
  contract and not confirmed against a live install.

### Guards and disclosure

- `CLAUDE.md`'s hook-contract bullets MUST gain: _Copilot CLI: `preToolUse` denies on crash,
  allows on timeout, other events fail open; VS Code Local: exit 2 blocks, everything else
  fails open, matchers ignored_ — with the CLI half marked as documentation until the two
  probes run.
- The package MUST wire `test/setup/no-network.ts` (already done) and, once it takes a
  `persistence` dependency, `test/setup/no-managed-settings.ts`. The derived guard will name
  it if it is missed.
- `release-plugin-copilot.yml` MUST be added on `plugin-copilot-v*`, alongside the three
  existing per-plugin release workflows. Its smoke test MUST feed junk to `preToolUse` and
  require an explicit allow, and junk to every other hook and require silence.
- Per-package coverage floor MUST be measured, not estimated, and added to `COVERAGE_FLOORS`.

## Edge cases

- **Silence versus explicit allow on a surface that changes its mind.** If a future CLI build
  starts reading an explicit allow as an override of a user's own deny rule, AKA's
  unconditional allow becomes a policy weakening rather than a safety net. The e2e enforcement
  rows are what would catch it; the fault rows would not.
- **`hookName` on `permissionRequest` only.** A dispatcher that reads it where it exists and
  falls back to argv elsewhere is two code paths for one fact. Read argv always.
- **Prompt events before `sessionStart`.** A session whose whole interaction is one prompt with
  no tool call produces a prompt capture whose session root does not yet exist when it lands.
- **`permissionRequest.permissionSuggestions` recorded empty.** The session ran under
  `--allow-all`, which is the likely cause. The populated shape is unobserved; nothing may
  depend on its contents.
- **Double capture with the Claude Code plugin.** With `chat.useClaudeHooks` on, VS Code reads
  `~/.claude/settings.json` hooks, so AKA's Claude Code adapter and AKA's Copilot adapter can
  both fire for one tool call. Shipped default is false, but this must be detected and
  deduplicated, not assumed away.
- **Cold-store cost against the 30 s timeout.** First `openLocalDatabase` plus a full migration
  on a fresh home is charged inside `preToolUse`'s budget. If it can approach 30 s on a
  contended machine, the hook allows by timeout and the call goes unscanned.
- **`~/.copilot` exists without the CLI.** VS Code's Copilot Chat writes that directory. The
  inventory collector MUST NOT infer "CLI installed" from its existence.
- **A 1 MB minified file through `apply_patch`.** §5's linear-in-file-length requirement for
  `extractFileEgress` applies to anything this adapter feeds it.
- **Repo hooks under `-p` / prompt mode** are gated by `GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS`
  and folder trust; user hooks are unstated. If user hooks fire under `-p`, the judge
  subprocess re-enters AKA's own hooks unless the throwaway home suppresses them.
- **Cloud agent on Windows x64 runners** honours only the `bash` field. Whether repo hooks fire
  there at all is unknown.
- **A cloud setup step that fails is skipped and the agent proceeds**, so `~/.aka` may be
  absent at hook time. On `preToolUse` that must be an explicit allow, never silence.
- **GitHub masks Agents secrets in its own session logs.** That masking must not be recorded as
  an AKA finding.
- **An oversized `toolArgs`** past the pipe buffer: `emit` sits outside the watchdog race, so a
  stalled pipe has no deadline and `process.exit(0)` is unreachable on that path.

## Out of scope

- **Cloud session-log backfill.** Session logs exist only in the GitHub UI and
  `gh agent-task view --log` (preview, no REST endpoint). Hooks are the capture.
- **The Claude agent hosted inside Copilot Chat.** Not a Copilot hook surface; VS Code's own
  hook files never reach it.
- **Implementing JetBrains, Visual Studio or Xcode adapters.** Phase D is a spike plus a
  decision gate per IDE — live hooks, backfill-only, MCP observation, or inventory-only with
  the reason recorded in Known limitations. No adapter code lands under this card.
- **Windows-specific work beyond the manifest being valid PowerShell.** The `.cmd`/`.exe`
  planner paths, `policy.d` at `C:\ProgramData\GitHub\Copilot\policy.d`, and cloud Windows
  runners are a separate follow-up issue.
- **Widening the provider seam (D7).** Provider stays `unknown` with a model id.
- **Retention or rollup work on the Copilot corpus.** It uses the existing store paths.
- **A version bump.** Pre-1.0.0 versions are chosen ad hoc at the scheduled release; which
  artifacts move is derivable from the bundling rules.

## Acceptance criteria

1. Every surface × event row in the card's table is either confirmed by a fixture or corrected
   in the fixture README, with doc-derived VS Code rows marked unverified and physically
   separated from the recordings.
2. A capability matrix (surface × event × field → block / rewrite / warn channel) exists, is
   derived from the fixtures rather than restated, and matches `SKILL.md`'s Known limitations
   — with a test that fails when they disagree.
3. `plugins/copilot/test/e2e/fail-open.e2e.test.ts` drives the **built** scripts and passes
   both halves: fault rows (empty, malformed, truncated, scalar, null, binary, oversized
   stdin, and an unopenable store) proving `preToolUse` emits exactly one explicit allow and
   every other hook emits nothing; enforcement rows proving block, redact, warn and monitor
   each produce the shape that cell is expected to emit.
4. `hook-output-shapes` pins both dialects' output shapes against the narrowed `emit` union,
   in both directions, and a new variant fails to compile until the map names it.
5. `aka plugins install copilot` and its uninstall are idempotent over a pre-existing
   `~/.copilot/hooks/aka.json` carrying foreign entries — proven by a test that seeds foreign
   entries, installs, uninstalls, and asserts the file is byte-identical to the seed.
6. Backfill and the setup wizard run against a captured `session-state` corpus, attribute by
   producer, and the judge leaves nothing in the real `~/.copilot` — proven by asserting the
   directory's contents before and after.
7. The inventory card for Copilot carries its own config assets; `SCAN_COVERAGE`'s row is
   above zero with its argument recorded.
8. Every guard in the epic's cross-cutting checklist is green on macOS and Linux: lint
   including the network and `process.env` bans, the derived non-package-file coverage check,
   the no-network runtime guard, `EXPECTED_VITEST_PACKAGES`, the coverage floor, the
   test-only-seam audit, and the `[^egress]` footnote count derived from `EGRESS_PATHS`.
9. A live block and a live redact-in-place are demonstrated on the Copilot CLI against a real
   session, recorded as fixtures.
10. `release-plugin-copilot.yml` exists and its smoke test asserts the explicit allow on
    `preToolUse` and silence elsewhere.

## Open questions

1. **The two blocked CLI probes** — `preToolUse` with exit 0 + empty stdout, and with a
   non-zero exit. The adapter is designed to be correct either way, so these are not blocking,
   but they remain unmeasured and the account-side context-budget error that stopped them is
   unresolved. Confirming them would permit the cheaper silent shape on non-`preToolUse`
   paths; nothing else depends on them.
2. **Which harness VS Code 1.135's "Local" session target runs** — extension-host
   `ChatHookService` (PascalCase, fail-open) or the agent-host Copilot-SDK harness (camelCase,
   `preToolUse` fail-closed). The adapter is safe under both, but the answer decides whether
   the VS Code dialect is a second dialect at all or a third spelling of the CLI's. Per
   operator decision, the doc-derived build proceeds without it; this is the single most
   valuable thing a live pass would settle.
3. **`SCAN_COVERAGE`'s number for Copilot (D5).** One number spans a rich surface (CLI:
   prompt capture, input and output rewrite) and a poorer one (VS Code Local: no output
   rewrite) and a third with no local store (cloud). The assumption in this document is that
   the number reflects the weakest live surface with the gaps named in `SKILL.md`; a product
   decision could instead argue it per surface, which would need a schema change.
4. **Whether the Copilot plugin channel's marketplace accepts this repo's npm-object
   `plugins[].source` (D4).** The file-drop floor makes this non-blocking, but the plugin
   channel's registry edits — `CliPluginBin`, `HOST_VERBS`, the `npm view` count in two
   READMEs and `CLAUDE.md` §4 — cannot be written until it is answered.
5. **Whether cloud hook processes sit inside the Bash-tool firewall.** Two vendor pages
   contradict each other. This decides whether an attached cloud runner can reach the
   organization's control plane from a hook at all, and therefore whether Phase C's runner
   mode is viable or push-scan (F5) is the only available mode there.
