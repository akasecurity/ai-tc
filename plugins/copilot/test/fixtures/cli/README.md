# Copilot CLI — Phase A spike findings (partial)

Captured from a live, authenticated session against GitHub Copilot CLI
**1.0.83** (`npm view @github/copilot version` on 2026-09-05; the epic's
Surfaces table was written against 1.0.82). Auth: `gh auth token | copilot
login --with-token` — the CLI accepts an existing `gh` OAuth token directly,
with no browser step. Run under an isolated `$COPILOT_HOME` so nothing here
touched the machine's real Copilot config.

Covers the core enforcement path only: `sessionStart`, `userPromptSubmitted`,
`userPromptTransformed`, `preToolUse`, `permissionRequest`, `postToolUse`,
`agentStop`, `sessionEnd`. **Not captured**: `postToolUseFailure` (a tool-level
failure, not a nonzero exit — see below), `preMcpToolCall` (needs an MCP
server configured), `subagentStart`/`subagentStop` (needs a task that spawns
one), `preCompact` (needs a long enough session to compact), `notification`,
`errorOccurred`. Each needs its own elaborated setup; left for a follow-up
pass rather than forced here.

## Corrections to the epic's Surfaces table

1. **The file-hook loader accepts 15 event names, not 17 and not the epic's 14.** The live schema (`copilot-sdk/schemas/api.schema.json`'s `HookType`
   enum) lists 17, but wiring all 17 into `~/.copilot/hooks/*.json` and
   running a session logs, verbatim:

   ```
   [DEBUG] [rust:hooks] Ignoring unknown hook event(s) in .../aka-spike.json: postResult, prePRDescription
   ```

   Those two are schema-only (SDK-callback surface, not file-configurable) in
   this build. The epic's list of 14 was itself short two of the 15 real
   file-configurable ones — `preMcpToolCall` and `postToolUseFailure` weren't
   named, though both are legitimate hook-file events.

2. **`preToolUse` denies via a JSON object on stdout with exit 0, not exit 2.** Confirmed by driving a real deny: the hook command printed
   `{"permissionDecision":"deny","permissionDecisionReason":"..."}` to stdout
   and exited 0. The CLI's own transcript read:

   ```
   ✗ Run the requested echo command (shell)
     └ Denied by preToolUse hook: AKA spike test - verifying deny semantics
   The command was blocked by the pre-tool-use hook.
   ```

   This is the Claude-Code-style JSON-decision convention, not a raw
   exit-code convention. Worth re-verifying `permissionDecision: "ask"` and
   `modifiedArgs` the same way before Phase B relies on them; only `deny` was
   driven live here.

3. **`preToolUse` and `permissionRequest` both fire for the same tool call,
   in that order, under `--allow-all`.** `permissionRequest` is not gated
   behind "would otherwise prompt" — it fired even with every permission
   pre-granted. The two carry the SAME tool-call payload under DIFFERENT key
   names: `preToolUse.toolArgs` vs. `permissionRequest.toolInput`. A scanner
   reading one cannot assume the other's shape.

4. **`postToolUse.toolResult.resultType` reflects whether the _tool
   invocation_ succeeded, not whether the underlying command exited zero.**
   Ran `false` (exit 1) through the shell tool: `resultType` was still
   `"success"`, and the exit code appeared only as free text inside
   `textResultForLlm`: `"<shellId: 0 completed with exit code 1>"`. Detecting
   a failed command means parsing that string, not reading a status field —
   worth confirming whether `postToolUseFailure` is reserved for a
   tool-level error (bad args, crash) rather than ever firing on a nonzero
   shell exit; this spike didn't manage to trigger it.

## Working hook-file shape

`$COPILOT_HOME/hooks/<name>.json`, one combined file, keyed by event name —
confirmed live (this is what produced every fixture here):

```json
{
  "hooks": {
    "preToolUse": [{ "hooks": [{ "type": "command", "command": "<script> preToolUse" }] }],
    "postToolUse": [{ "hooks": [{ "type": "command", "command": "<script> postToolUse" }] }]
  }
}
```

## Other observations, not yet load-bearing for anything

- `agentStop.transcriptPath` points at `$COPILOT_HOME/session-state/<sessionId>/events.jsonl`
  — real on-disk transcript location, relevant to a future history-scan/backfill design.
  `sessionStart` carries no `transcriptPath`; only `agentStop` does.
- `agentStop` carries `stop_hook_active` in snake_case, the one field observed
  that breaks the otherwise-consistent camelCase convention.
- `userPromptTransformed.transformedPrompt` embeds internal scaffolding not
  present in the raw prompt — a `<current_datetime>` stamp and a
  `<system_reminder><sql_tables>...</sql_tables></system_reminder>` block
  naming a `todos`/`todo_deps` schema. Neither was asked for; this is the
  CLI's own prompt engineering, visible only post-transform. Worth knowing
  before assuming `userPromptSubmitted.prompt` is the whole of what reaches
  the model — it manifestly isn't.
- Tool name observed: `bash` (lowercase). `toolArgs` for it carries
  `command`, `description`, `mode: "sync"`, `initial_wait: 30` — the last two
  not mentioned anywhere in the epic's table.
