# Copilot CLI hook payloads — recorded shapes

Each `<event>.json` here is the JSON one hook received on stdin from GitHub
Copilot CLI **1.0.83** (`npm view @github/copilot version` on 2026-09-05), in
one authenticated session run under an isolated `$COPILOT_HOME`. Auth was
`gh auth token | copilot login --with-token`, which the CLI accepts with no
browser step. The session was one turn — `run the shell command: false`,
executed through the `bash` tool under `--allow-all` — so the eight files
describe one tool call from `sessionStart` to `sessionEnd`.

`test/cli-fixture-shapes.test.ts` in this package pins the fields described
below and the exact set of files. Add a recording and it fails until the
recording is described there too.

## What was rewritten before commit

- **Every path under the capturing user's home** became the repository's
  `/Users/dev` placeholder — the checkout (`cwd`) and the isolated
  `$COPILOT_HOME` alike. `agentStop.transcriptPath` therefore reads as a
  default-home layout (`/Users/dev/.copilot/session-state/…`) and is not the
  directory the session ran under; only its shape is the CLI's.
- **Nothing else.** The session id, the epoch timestamps, the tool arguments
  and the tool result are as received. The `<current_datetime>` stamp inside
  `transformedPrompt` keeps its `+05:30` offset — it agrees with the epoch
  fields to the millisecond, and it records a timezone and nothing more.

So a test pins a **sanitized** shape: a path in these files is never the one
the CLI sent, and everything else is.

## Not recorded here

Seven of the fifteen file-configurable events (below) have no recording,
each because it needs a setup this one-turn session did not have:
`postToolUseFailure` (a tool-level failure, not a non-zero exit — see
`postToolUse`), `preMcpToolCall` (an MCP server), `subagentStart` and
`subagentStop` (a task delegated through the `task` tool), `preCompact` (a
session long enough to compact), `notification`, `errorOccurred`.

## The hook file that produced these

`$COPILOT_HOME/hooks/<name>.json`, one file, keyed by event name. This is the
shape that fired every event above:

```json
{
  "hooks": {
    "preToolUse": [{ "hooks": [{ "type": "command", "command": "<script> preToolUse" }] }],
    "postToolUse": [{ "hooks": [{ "type": "command", "command": "<script> postToolUse" }] }]
  }
}
```

The capture script wrote its stdin to a file named by the event on its own
argv. Nothing here shows whether a dispatcher keyed on the **payload** alone
would work — see `hookName` under field notes.

## Accepted event names

The loader accepted fifteen names from a hooks file: `sessionStart`,
`sessionEnd`, `userPromptSubmitted`, `userPromptTransformed`, `preToolUse`,
`postToolUse`, `postToolUseFailure`, `preMcpToolCall`, `agentStop`,
`subagentStart`, `subagentStop`, `errorOccurred`, `preCompact`,
`permissionRequest`, `notification`.

The CLI's own schema (`copilot-sdk/schemas/api.schema.json`, `HookType`)
lists seventeen. Wiring all seventeen into a hooks file and starting a
session logs the other two as unknown, verbatim:

```
[DEBUG] [rust:hooks] Ignoring unknown hook event(s) in .../aka-spike.json: postResult, prePRDescription
```

Those two are reachable from the SDK's callback surface only, not from a file.

## Observed behaviours

Stated as recorded. The first three come from the CLI's transcript or debug
log in runs other than the one the fixtures are from, so **no file here backs
them**; the last two are in the fixtures.

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

- **`preToolUse` and `permissionRequest` both fire for one tool call, in that
  order, even under `--allow-all`** — 41 ms apart in the recordings
  (`preToolUse.json` at `1788547866483`, `permissionRequest.json` at
  `1788547866524`). `permissionRequest.toolInput` is a **strict subset** of
  `preToolUse.toolArgs`: it carries `command` only, while `toolArgs` also
  carries `description` (model-authored text), `mode` and `initial_wait`. A
  hook that wants to scan `description` reaches it on `preToolUse` and
  nowhere else.
- **`postToolUse.toolResult.resultType` reports whether the tool invocation
  succeeded, not whether the command exited zero.** The recorded command is
  `false`; `resultType` is `"success"` and the exit code appears only as free
  text in `textResultForLlm` (`<shellId: 0 completed with exit code 1>`).
  Whether `postToolUseFailure` is reserved for a tool-level error, or ever
  fires on a non-zero shell exit, was not observed.

## Field notes

- `hookName` is present on `permissionRequest` only (`"hookName":
"permissionRequest"`). Whether the CLI sends it on other events was not
  tested, so nothing here says a payload can be dispatched without the event
  name on argv.
- `agentStop.transcriptPath` names `$COPILOT_HOME/session-state/<sessionId>/events.jsonl`,
  the on-disk session record. `sessionStart` carries no `transcriptPath`.
- `agentStop.stop_hook_active` is the one snake_case key observed; every
  other key is camelCase.
- `userPromptTransformed.transformedPrompt` wraps the submitted prompt in
  scaffolding the user did not write — a `<current_datetime>` stamp and a
  `<system_reminder><sql_tables>…</sql_tables></system_reminder>` block naming
  a `todos`/`todo_deps` schema. `userPromptSubmitted.prompt` is not the whole
  of what reaches the model.
- The shell tool is named `bash` (lowercase). Its `toolArgs` carry `command`,
  `description`, `mode` (`"sync"`) and `initial_wait` (`30`).
- Tool names seen in the session's own tool-selection log: `bash`,
  `read_bash`, `stop_bash`, `list_bash`, `apply_patch`, `view`, `web_fetch`,
  `fetch_copilot_cli_documentation`, `skill`, `sql`, `session_store_sql`,
  `read_agent`, `list_agents`, `write_agent`, `rg`, `glob`, `task`, plus a
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

The second recording pass ended before the first two could run: every
invocation on the capturing account then failed, before any prompt was sent,
with `Static system messages and tool definitions exceed the model's usable
context budget.` A fresh `$COPILOT_HOME`, a fresh login and
`--disable-builtin-mcps` did not change it, so it reads as a condition of the
account or its model tier rather than of anything a hooks file did.
