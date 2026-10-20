# Copilot CLI hook payloads — recorded shapes

Each `<event>.json` here is the JSON one hook received on stdin from GitHub
Copilot CLI **1.0.83** (`npm view @github/copilot version` on 2026-09-05), in
one authenticated session run under an isolated `$COPILOT_HOME`. Auth was
`gh auth token | copilot login --with-token`, which the CLI accepts with no
browser step. The session was one turn — `run the shell command: false`,
executed through the `bash` tool under `--allow-all` — so the eight files
describe one prompt and the single tool call it produced. A second, smaller set
from Copilot CLI 1.0.98 and an installed plugin sits in `plugin-install-1.0.98/`;
its own section at the end says how it was made.

`test/cli-fixture-shapes.test.ts` in this package pins the exact set of files
and the field shapes this note calls out; where it pins something weaker than
the prose (a value's presence rather than its content) the note says so. Add a
recording and the file-set case fails until it is described here too.

## What was rewritten before commit

- **Every path under the capturing user's home** became the repository's
  `/Users/dev` placeholder — the checkout (`cwd`) and the isolated
  `$COPILOT_HOME` alike. That second rewrite also flattened the isolated home
  into a default-home layout: `agentStop.transcriptPath` reads
  `/Users/dev/.copilot/session-state/…`, which is not the directory the
  session ran under. Only its shape is the CLI's.
- **Nothing else was changed.** The session id, the epoch timestamps, the tool
  arguments and the tool result are as received. The `<current_datetime>` stamp
  inside `transformedPrompt` keeps its `+05:30` offset — it parses to exactly
  `userPromptTransformed.timestamp`, and it records a timezone and nothing more.

So a test pins a **sanitized** shape: a path in these files is never the one
the CLI sent, and everything else is.

## Not recorded here

Seven of the fifteen file-configurable events (below) have no recording,
each because it needs a setup this one-turn session did not have:
`postToolUseFailure` (a tool-level failure, not a non-zero exit — see
`postToolUse`), `preMcpToolCall` (a call through an MCP server; one was
configured, as the tool list below shows, but nothing in this turn called
through it), `subagentStart` and `subagentStop` (a task delegated through the
`task` tool), `preCompact` (a session long enough to compact), `notification`,
`errorOccurred`.

## The hook file that produced these

`$COPILOT_HOME/hooks/<name>.json`, one file, keyed by event name. The file used
here carried one entry per recorded event; two are shown for shape:

```json
{
  "hooks": {
    "preToolUse": [{ "hooks": [{ "type": "command", "command": "<script> preToolUse" }] }],
    "postToolUse": [{ "hooks": [{ "type": "command", "command": "<script> postToolUse" }] }]
  }
}
```

The capture script wrote its stdin to a file named by the event on its own
argv, which is what made the recordings possible at all: seven of the eight
payloads carry no event name (see `hookName` under field notes), so a
dispatcher keyed on the payload alone could not have told them apart.

## Accepted event names

A hooks file naming these fifteen was loaded without complaint: `sessionStart`,
`sessionEnd`, `userPromptSubmitted`, `userPromptTransformed`, `preToolUse`,
`postToolUse`, `postToolUseFailure`, `preMcpToolCall`, `agentStop`,
`subagentStart`, `subagentStop`, `errorOccurred`, `preCompact`,
`permissionRequest`, `notification`.

The CLI's own schema (`copilot-sdk/schemas/api.schema.json`, `HookType`)
lists seventeen. Wiring all seventeen into a hooks file and starting a
session logs the other two as unknown — quoted as emitted, but for the hooks
file's own path, which was the recorder's:

```
[DEBUG] [rust:hooks] Ignoring unknown hook event(s) in <hooks file>: postResult, prePRDescription
```

So `postResult` and `prePRDescription` are in the schema and are not
file-configurable in this build. Where else they are reachable was not
established here.

## Observed behaviours

Stated as recorded. The first three come from the CLI's transcript or debug
log in runs other than the one the fixtures are from, so **no file here backs
them**; the rest are in the fixtures.

- **A `preToolUse` deny is a JSON object on stdout with exit 0.** The hook
  printed `{"permissionDecision":"deny","permissionDecisionReason":"…"}` and
  exited 0; the CLI's transcript read `Denied by preToolUse hook: …` and
  `The command was blocked by the pre-tool-use hook.`, and the command did not
  run. Whether exit 2 also denies was not tested.
- **`modifiedArgs` rewrites the executed call.** A hook returning
  `{"modifiedArgs":{"command":"echo modified-by-hook"}}` for a call whose
  command was `echo MODIFYME-original` produced `modified-by-hook` in the
  transcript; the original string never ran. Confirmed by effect, not by the
  input being echoed back.
- **`permissionDecision: "ask"` resolves to a denial when nobody can be
  asked.** In non-interactive mode the call sat for ~25 s with no stdout and
  the debug log then recorded the mechanism:

  ```
  [DEBUG] [rust:copilot_runtime::session::session_helpers] respondToPermission: requestId=…, kind=denied-no-approval-rule-and-could-not-request-from-user
  ```

  A policy that maps to `ask` on this surface fails closed in automation by
  that route.

- **The prompt events are stamped BEFORE `sessionStart`.** By the payloads'
  own timestamps the recorded order is `userPromptSubmitted` (…858031),
  `userPromptTransformed` (…858041), `sessionStart` (…858051), `preToolUse`,
  `permissionRequest`, `postToolUse`, `agentStop`, `sessionEnd` — so the
  session's own start event lands 20 ms after the prompt it started with was
  submitted. A once-per-session pass hung off `sessionStart` therefore runs
  after that prompt has already been submitted and transformed.
- **`preToolUse` and `permissionRequest` both fire for one tool call, in that
  order, even under `--allow-all`** — 41 ms apart in the recordings
  (`preToolUse.json` at `1788547866483`, `permissionRequest.json` at
  `1788547866524`), with `postToolUse` 22 ms later again.
  `permissionRequest` carries `toolName` and a **strict subset** of
  `preToolUse.toolArgs`: its `toolInput` holds `command` only, while
  `toolArgs` also holds `description` (model-authored text), `mode` and
  `initial_wait`. `postToolUse` repeats `toolArgs` in full, so a hook that
  wants to scan `description` reaches it on `preToolUse` and `postToolUse` —
  never on `permissionRequest`.
- **`postToolUse.toolResult.resultType` reports whether the tool invocation
  succeeded, not whether the command exited zero.** The recorded command is
  `false`; `resultType` is `"success"` and the exit code appears only as free
  text in `textResultForLlm`, which is a newline followed by
  `<shellId: 0 completed with exit code 1>`. Whether `postToolUseFailure` is
  reserved for a tool-level error, or ever fires on a non-zero shell exit, was
  not observed.

## Field notes

- **The envelope every event carries** is `sessionId` (one UUID, identical
  across all eight), `timestamp` (epoch milliseconds) and `cwd` (the
  workspace, here the rewritten placeholder). Everything else is per event.
- `hookName` is present on `permissionRequest` only, and absent from each of
  the other seven recordings — both halves pinned. Whether any of the seven
  UNRECORDED events carries it was not observed. So for these payloads the
  event name reaches a hook on its argv or not at all.
- `agentStop.transcriptPath` names `$COPILOT_HOME/session-state/<sessionId>/events.jsonl`,
  the on-disk session record. No other recorded event carries it — not
  `sessionStart`, and not the six others.
- `permissionRequest.permissionSuggestions` was recorded as an **empty
  array**, and the session ran under `--allow-all`, which is the likely
  reason: with every permission pre-granted there was nothing to suggest.
  The populated shape was not observed, so a hook that wants it has to
  re-record without the flag.
- `sessionStart.source` was `"new"` and `sessionStart.initialPrompt` repeats
  the submitted prompt verbatim; `agentStop.stopReason` was `"end_turn"` and
  `agentStop.stop_hook_active` was `false`; `sessionEnd.reason` was
  `"complete"`. Each is the one value a single, uninterrupted turn produces;
  the other values each field can take were not observed.
- `stop_hook_active` is the one snake_case key at the TOP LEVEL of any
  payload; every other top-level key is camelCase. `initial_wait` inside
  `toolArgs` is snake_case too, but that is the `bash` tool's own argument
  name rather than the hook envelope's.
- `userPromptTransformed` re-carries the untransformed `prompt` alongside
  `transformedPrompt`, which wraps it in scaffolding the user did not write —
  a `<current_datetime>` stamp and a
  `<system_reminder><sql_tables>…</sql_tables></system_reminder>` block naming
  a `todos`/`todo_deps` schema. `userPromptSubmitted.prompt` is not the whole
  of what reaches the model. (The test pins that the wrapper contains the
  prompt and differs from it, not the scaffolding's content.)
- The shell tool is named `bash` (lowercase). Its `toolArgs` carry `command`,
  `description`, `mode` (`"sync"`) and `initial_wait` (`30`).

Not a payload field, and no recording backs it: tool names seen in the
session's own tool-selection log were `bash`, `read_bash`, `stop_bash`,
`list_bash`, `apply_patch`, `view`, `web_fetch`,
`fetch_copilot_cli_documentation`, `skill`, `sql`, `session_store_sql`,
`read_agent`, `list_agents`, `write_agent`, `rg`, `glob` and `task`, plus a
`github-mcp-server` MCP server wired in by default and contributing several
`github-mcp-server-*` tools.

## Settled by the vendor reference, not by a recording

These were listed here as unmeasured, and the listing was wrong: the Copilot
hooks reference answers them outright, in its "Exit codes for command hooks"
table and its `preToolUse` decision-control table. Nothing here observed them —
what changed is that a recording is no longer what would settle them.

- **Exit 0 with empty stdout.** "Empty output uses default behavior", i.e. the
  call goes to the host's own permission flow. It is **not** a deny, and not an
  allow either — which is why the adapter writes nothing when it has no verdict.
- **A non-zero exit other than 2.** "`preToolUse` is fail-closed—a non-zero exit
  (other than exit 2) denies the tool call."
- **Exit 2.** Denies, and "any `stdout` JSON is merged with the deny decision and
  the tool call is denied even if that JSON reports `permissionDecision:
\"allow\"`".
- **A timeout.** "Timeouts are fail-open for every event, including
  `preToolUse`."
- **`systemMessage`.** Not an output field on this event at all: the reference
  documents `permissionDecision`, `permissionDecisionReason` and `modifiedArgs`,
  and the string `systemMessage` appears nowhere in it. A notice on the CLI
  therefore goes to stderr.

A recording would still be worth having — the reference describes the contract
and these files describe one build's behaviour, and the two have already
disagreed once (see `hookName` under field notes). But no claim in this adapter
now rests on the gap.

## Not measured

Each of these decides something a hook written against this host depends on,
and none was observed:

- `postToolUse.modifiedResult` replacing what the model sees.
- `userPromptSubmitted.modifiedPrompt` from a command hook.
- The seven unrecorded events above.

Anyone re-recording should know that the account used here stopped accepting
any invocation partway through, before a prompt was sent, with
`Static system messages and tool definitions exceed the model's usable context
budget.` — unchanged by a fresh `$COPILOT_HOME`, a fresh login or
`--disable-builtin-mcps`, so it reads as a condition of the account or its
model tier rather than of anything a hooks file did.

## Plugin-install recordings — Copilot CLI 1.0.98

`plugin-install-1.0.98/` holds four more recordings, of a different kind from
the eight above: what Copilot CLI **1.0.98** handed to this package's own
**built** hooks after the packed plugin was installed with
`copilot plugin install`, so every hook ran through the manifest's commands as
shipped. They are `sessionStart`, `userPromptSubmitted`, `preToolUse` and
`postToolUse`, all from one session. `test/cli-fixture-shapes.test.ts` pins
them in a group of their own.

### How they were recorded

- **The CLI.** `npm install -g @github/copilot@1.0.98`, run from the home
  directory. Run inside this repository, the same install omitted the CLI's
  platform binary, because the repository's `.npmrc` was picked up; from `~` it
  installed whole.
- **Isolation.** `HOME` and `COPILOT_HOME` both pointed at throwaway
  directories, so AKA's store was a fresh `~/.aka` and the CLI's state was
  isolated too. `COPILOT_HOME` was honoured: the login and the installed plugin
  both landed under it.
- **Auth.** `copilot login`, through the browser OAuth flow. Under the
  redirected `HOME` the CLI reported `System keychain unavailable` and offered
  to store the token in **plaintext** under `COPILOT_HOME` instead; that was
  accepted. Anyone repeating this leaves a usable token on disk in that
  directory and should delete it afterwards.
- **The install.** `npm pack` of the built plugin (0.9.19), `tar -xzf`, then
  `copilot plugin install ./package`. The CLI printed
  `Plugin "aka-copilot" installed successfully. Installed 1 skill.` together
  with a warning that direct plugin installs (repositories, URLs, local paths)
  are deprecated and that only `plugin@marketplace` installs will be supported
  in a future release. The plugin landed under
  `$COPILOT_HOME/installed-plugins/_direct/package/`, and `copilot plugin list`
  showed `aka-copilot (v0.9.19)`.
- **The sessions.** `copilot -p … --allow-tool 'shell(cat)'`, in a git
  repository with no remote whose `.env` assigned `GH_TOKEN` the bundled
  `secrets/github-pat` rule's own example value. The prompt, recorded verbatim
  in `userPromptSubmitted`, asked for `cat .env` and a yes-or-no answer.
- **The capture.** Each installed hook command was temporarily prefixed with a
  `tee` into a file named for its event, so the hook still received the same
  bytes. The prefix was removed afterwards; the manifest in this package was
  never changed.

### What was rewritten before commit

The same rule as above: the recorder's temporary directory became the
`/Users/dev` placeholder, so `cwd` reads `/Users/dev/work`. Nothing else was
changed — the session id, the timestamps, the prompt, the tool arguments and
the tool result, including the rule example value in it, are as received. The
files were re-indented; their content was not.

### Recorded

- **`${PLUGIN_ROOT}` expands in hook commands.** All four built scripts ran
  from the installed directory, through the manifest's
  `node "${PLUGIN_ROOT}/scripts/…"` commands unchanged.
- **All four wired events fire from an installed plugin.** The throwaway store
  recorded a session root with `harness_interface` `cli`, prompt captures, a
  `tool_use` finding `command-risk/credential-file-read` (warn) on `cat .env`,
  `response` findings `secrets/github-pat` (warn), `secrets-infra/env-key-value`
  (log) and `secrets-infra/secret-config-value` (log) on the tool result, and a
  prompt finding `secrets/github-pat` from a session whose prompt carried the
  value. The project was recorded with no scope key, as expected for a
  repository with no remote. These store outcomes come from inspecting that
  throwaway `~/.aka` after the runs, so **no file here backs them**.
- **In `-p` mode, a successful hook's stderr was not shown by the CLI.** Every
  notice the hooks wrote appeared in none of the CLI's own output in `-p` mode. It appeared
  only in the debug log (`--log-level debug --log-dir <dir>`), one line per
  write, in this form:

  ```
  [DEBUG] [rust:hooks] [hook stderr] AKA flagged sensitive content in bash input (command-risk/credential-file-read).
  ```

  The other lines seen there were the session-start notice that AKA is active
  and monitoring prompts, `AKA flagged sensitive content in this prompt
(secrets/github-pat) — sent unchanged.`, and the tool-result notice naming
  the three response rules, ending `— the output reached the model unchanged.`
  So on this host a warn reaches the debug log and not the user, which
  `skills/setup/SKILL.md` states on the user-facing side.

- **The prompt is stamped BEFORE `sessionStart` again.** `userPromptSubmitted`
  is at `1792405102341` and `sessionStart` at `1792405102577`, 236 ms later —
  the same order the 1.0.83 recording showed.
- **`sessionStart` carries `source: "new"` and `initialPrompt`**, which repeats
  the submitted prompt verbatim, as on 1.0.83. No payload carries `hookName`.
- **`preToolUse.toolArgs` is an OBJECT**, `{ command, description }`. That is
  the encoding 1.0.83 sent too, and the one `readToolCall` in
  `src/hooks/dialect.ts` reads; the JSON-string encoding it declines to parse
  was not seen on either build. What differs is the key set: 1.0.83's `bash`
  arguments also carried `mode` and `initial_wait`, and this build's carry
  neither, so no reader can rely on those two across builds.
- **`postToolUse.toolResult` is `{ resultType, textResultForLlm }`**, the same
  two keys as on 1.0.83: `resultType` was `"success"`, and the text is the
  shell output followed by `<shellId: 0 completed with exit code 0>` on its own
  line. `postToolUse` repeats `toolArgs` exactly as `preToolUse` sent them.
- **Asked to `echo` the value directly, the model refused.** That was the
  model's own choice, not anything a hook did, which is why the recorded
  session reads the file with `cat` instead.

### Not measured by this install

- Whether the CLI shows a successful hook's stderr in an **interactive**
  session; only `-p` mode was observed.
- A `plugin@marketplace` install, the route the deprecation warning points at.
- Whether `${PLUGIN_ROOT}` expands anywhere other than a hook's `command`.
- `postToolUse.modifiedResult` and `userPromptSubmitted.modifiedPrompt`, as
  above: neither was exercised.

## Update, marketplace and auto-update — Copilot CLI 1.0.98

How Copilot CLI 1.0.98 updates and discovers this plugin, observed against the
same throwaway `HOME` and `COPILOT_HOME` as the install above. These are command
outcomes and file states, not hook payloads, so **no file here backs them**.

### Recorded

- **The install remembers its source path.** `config.json`'s `installedPlugins`
  entry for `aka-copilot` carries `marketplace: ""`,
  `source: { source: "local", path: "<the unpacked package folder>" }` and a
  `cache_path` of `$COPILOT_HOME/installed-plugins/_direct/package`.
- **Hooks run from the installed copy, not the source folder.** A stub
  `session-start.js` placed in the source folder never ran; the same stub
  placed in the installed copy ran, and reported the installed path. The debug
  log's `Plugins loaded:` line names the source folder all the same, so that
  line is not evidence of where hooks run from.
- **`copilot plugin update aka-copilot` re-copies the source folder.** With the
  source's `plugin.json` raised to `0.9.20` and a new file added, it printed
  `Plugin "aka-copilot" updated successfully (v0.9.19 → v0.9.20). Updated 1 skill.`
  and the installed copy took both changes. It REPLACES the installed copy
  rather than overlaying it: a file removed from the source was removed from
  the installed copy too, even when the version was unchanged
  (`v0.9.20, already at latest`). It follows the source in either direction —
  with the source back at `0.9.19` it reported `v0.9.20 → v0.9.19`.
  `copilot plugin update --all` behaves the same.
- **Update fails, and changes nothing, once the source folder is gone.** With
  the unpacked folder moved away, `copilot plugin update aka-copilot` exited 1
  with `Local plugin path does not exist: <path>`, and the installed copy was
  left as it was. Deleting the unpacked folder after installing therefore
  leaves AKA running and makes `copilot plugin update` unusable for it; a
  newer version is installed by unpacking it again and running
  `copilot plugin install ./package`.
- **`copilot plugin uninstall aka-copilot` removes the install, and it can be
  installed again.** It exited 0 and printed
  `Plugin "aka-copilot" uninstalled successfully.`; `copilot plugin list`
  afterwards no longer listed it, and `$COPILOT_HOME/installed-plugins/_direct`
  was gone. Installing again with `copilot plugin install ./package` worked.
- **`COPILOT_HOME` defaults to `$HOME/.copilot`**, as `copilot help environment`
  states. That is the help text only: every run here set `COPILOT_HOME`, so an
  install under the default location was not itself observed.
- **`copilot plugin marketplace add akasecurity/ai-tc` refuses this
  repository's marketplace.** It read `.claude-plugin/marketplace.json` and
  exited 1 with
  `Invalid marketplace.json: plugins.0.source: Invalid input, plugins.1.source: Invalid input`.
  Both entries use `{ source: "npm", package: … }`, which this build does not
  accept. The whole marketplace was rejected, not just those entries:
  `copilot plugin marketplace list` afterwards showed only the built-in
  `awesome-copilot`.
- **A session did not update the local-path plugin.** With the source folder
  newer than the installed copy, one `copilot -p` session ran and the installed
  copy was unchanged, still the older version without the new file. The debug
  log showed no plugin update or fetch activity.
- **The only auto-update setting is for the CLI itself.** `copilot help config`
  documents `autoUpdate` as "whether to automatically download updated CLI
  versions", and `--no-auto-update` likewise. Neither mentions plugins.

### Not measured

- Whether a plugin installed from a **marketplace** is updated at session start.
  Only the local-path install was observed.
- Whether a marketplace whose entries use a source this build accepts (a GitHub
  repository or a path inside one) would install this plugin.
- Interactive sessions. Only `-p` sessions were run.
