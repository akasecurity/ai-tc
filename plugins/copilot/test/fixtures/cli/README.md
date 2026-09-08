# Copilot CLI hook payloads — recorded shapes

Each `<event>.json` here is the JSON one hook received on stdin from GitHub
Copilot CLI **1.0.83** (`npm view @github/copilot version` on 2026-09-05), in
one authenticated session run under an isolated `$COPILOT_HOME`. Auth was
`gh auth token | copilot login --with-token`, which the CLI accepts with no
browser step. The session was one turn — `run the shell command: false`,
executed through the `bash` tool under `--allow-all` — so the eight files
describe one prompt and the single tool call it produced.

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

## Not measured

Each of these decides something a hook written against this host depends on,
and none was observed:

- `preToolUse` with **exit 0 and empty stdout** — allow or deny.
- `preToolUse` with a **non-zero exit** — allow or deny.
- `preToolUse` past its timeout; `preToolUse` with exit 2.
- `postToolUse.modifiedResult` replacing what the model sees.
- `userPromptSubmitted.modifiedPrompt` from a command hook.
- The seven unrecorded events above.

Anyone re-recording should know that the account used here stopped accepting
any invocation partway through, before a prompt was sent, with
`Static system messages and tool definitions exceed the model's usable context
budget.` — unchanged by a fresh `$COPILOT_HOME`, a fresh login or
`--disable-builtin-mcps`, so it reads as a condition of the account or its
model tier rather than of anything a hooks file did.
