# VS Code agent mode hook payloads — PROVISIONAL, not recorded

**No live VS Code session produced any file in this directory.** Every one of
them was written from vendor documentation and from the Copilot Chat extension's
published behaviour, and is a statement of what the payload was _believed_ to
look like before anything was recorded. That is why this directory sits beside
`../cli/` and `../vscode/` rather than inside either: those are recordings, and
a doc-derived specimen filed among them would be read as one.

The recordings for this host are in `../vscode/plugin-load-1.141/`: seven
payloads from VS Code 1.141.0 with Copilot Chat 0.69.0, which loaded this
package's packed plugin from a local directory. The next section says which
claims below they confirm and which they contradict. Where the two disagree, the
recording is right and the specimen here is not.

`../../fixture-provenance.test.ts` is what keeps the kinds apart — a loose file
under `vscode/`, or a `cli/` file or `vscode/` session directory with no README
describing its capture, fails there.

## What the recordings settled

Confirmed by `../vscode/plugin-load-1.141/`:

- **The event names** `SessionStart`, `UserPromptSubmit`, `PreToolUse` and
  `PostToolUse`. The other four (`PreCompact`, `SubagentStart`, `SubagentStop`,
  `Stop`) were not registered, so nothing was recorded for them.
- **The common envelope.** `hook_event_name`, `session_id`, `transcript_path`,
  `timestamp` and `cwd` arrived on every event. `session_id` was sent on
  every event, `SessionStart` included.
- **`transcript_path`'s layout**,
  `workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/<session id>.jsonl`.
- **The tool ids.** `run_in_terminal` and `create_file` reach the hook as
  `tool_name` under exactly those names. VS Code did not substitute a Claude
  spelling the way the CLI's PascalCase payloads do.
- **The `tool_input` keys** `command` and `explanation` for `run_in_terminal`,
  and `filePath` and `content` for `create_file`, in camelCase.
- **`tool_response` is a string.** It was the terminal's text for
  `run_in_terminal` and `""` for `create_file`.

Contradicted by the same recordings:

- **`timestamp` is an ISO-8601 string** such as `2026-10-19T10:42:00.538Z`,
  not the epoch-millisecond number every file here carries.
- **`SessionStart` fired first**, 151 ms before `UserPromptSubmit`. The
  timestamps here put the prompt first, copied from the CLI's order.
- **`source` was `"new"`**, not the `"startup"` placeholder in
  `SessionStart.json`. `SessionStart` also carried `model` (`"auto"`), which no
  file here has.
- **`run_in_terminal` sent no `isBackground`.** Its input was
  `{ command, explanation, goal, mode }`, with `mode` set to `"sync"`.
- **Both tool events carry `tool_use_id`**, which no file here has.
- **`cwd` was sent although no hook entry declared one,** and the hook's
  working directory was the workspace folder, not the home directory. The
  `cwd` entry below describes the documented behaviour, which this build did
  not show.
- **No VS Code-specific hooks file was needed.** VS Code read the plugin's own
  CLI-format `hooks.json` and dispatched its camelCase keys as the PascalCase
  events above, with the snake_case payloads.

Still unmeasured: the `replace_string_in_file`, `insert_edit_into_file` and
`apply_patch` ids, an object-shaped `tool_response`, whether `updatedInput` or
a deny is honoured, the `UserPromptSubmit` block channels, and whether matchers
are ignored.

## What these are for

They are the shape the VS Code half of this adapter was first written against:
the dialect sniff (`src/hooks/dialect.ts`) and the VS Code `SCANNABLE_FIELDS`
table (`src/hooks/pre-tool-use-decision.ts`) were both built **from these
files**, not the other way round. Writing the fixtures to match a table already
in the tree would prove nothing at all.

A VS Code row in `src/capabilities.ts` is `verified: true` only where the
recordings in `../vscode/` back it, and every other row stays `verified: false`.
The unit suites still drive these files where they need an event the
recordings do not cover.

## Sources

- VS Code's chat-hooks documentation (`code.visualstudio.com`, "Agent mode
  hooks"), which supplies the eight PascalCase event names, the common envelope
  (`hook_event_name`, `timestamp`, `session_id`, `transcript_path`, `cwd`), the
  `hookSpecificOutput.permissionDecision` verdict, `updatedInput`, exit 2 as the
  block channel, and the 30 s timeout with SIGTERM then SIGKILL after 5 s.
- The Copilot Chat extension's own tool ids as they appear in VS Code's
  language-model tool registry: `run_in_terminal`, `create_file`,
  `replace_string_in_file`, `insert_edit_into_file`,
  `multi_replace_string_in_file`, `apply_patch`, `edit_notebook_file`,
  `read_file`, `fetch_webpage`, and the `mcp_*` prefix.

## Every field whose presence, casing or type is unverified

Read this list as the scope of what a live recording would settle. Nothing here
is asserted by the adapter beyond "if it is present and a string, scan it".

- **`session_id`** — documented as sent _only when known_, so its absence is
  expected on some events and is not an error. `detectDialect` places a payload
  without it on `hook_event_name` alone for this reason.
- **`cwd`** — documented as sent _only when the hook entry declares one_. The
  spawn's own working directory defaults to the **home directory**, so the
  adapter deliberately does not fall back to `process.cwd()` on this host.
- **`transcript_path`** — documented as unstable, pointing under
  `workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/<id>.jsonl`. The hash
  and the layout in these files are placeholders.
- **`tool_input` key names, per tool.** The keys in `PreToolUse.json` and
  `PostToolUse.json` (`command`, `explanation`, `isBackground`) are the
  `run_in_terminal` tool's published input schema. Whether the hook receives
  them under exactly those names — and camelCase, which the docs state but no
  recording confirms — is unverified. Whether `updatedInput` is honoured per
  tool, and whether a user's or repo's own hook returning one silently discards
  this adapter's (documented: **last hook wins**), is unverified too.
- **`tool_response`** — documented as a **string**, not an object. The value here
  is the CLI recording's own `textResultForLlm`, reused so the two surfaces'
  fixtures describe the same command; VS Code's real wording is unknown. An
  object- or array-shaped `tool_response` is not recorded either; the adapter
  scans its string leaves through a bounded walk (`src/hooks/tool-response.ts`)
  rather than dropping it, and reports any leaf the bounds leave out as unscanned.
- **`source` on `SessionStart`** — the set of values it can take was not observed.
  `startup` here is a placeholder.
- **`SubagentStart` / `SubagentStop` / `PreCompact`** carry nothing beyond the
  common envelope in these files. Whether they carry more is unverified; they are
  present so the event vocabulary has a file per member rather than a gap that
  reads as "this event does not exist".
- **`UserPromptSubmit`'s block and rewrite channels.** Whether `continue: false`,
  a `stopReason`, or an updated-prompt field are honoured here is unknown, so the
  adapter records this event and does not act on it.
- **No `matcher` is honoured.** VS Code parses matchers and ignores them, so the
  hook is spawned for **every** tool call. That is why the unknown-tool exit in
  `src/hooks/pre-tool-use-run.ts` runs before the config load and before the store
  opens: on this host it is the common path, not the rare one.

## What is NOT a fixture question

The failure convention. VS Code fails **open** — exit 2 blocks, and any other
non-zero exit, invalid JSON or a timeout is a non-blocking warning — while the
Copilot CLI's `preToolUse` denies on a non-zero exit. Both are satisfied by the
same rule, which is why no recording is owed for it: the adapter always exits 0,
and writes a payload only where it reached a verdict. See `src/hooks/shared.ts`.

## Where each tool id came from

The ids in `VSCODE_SCANNABLE_FIELDS` are the part of this directory a wrong
guess costs the most: an id that does not match what the host sends is not an
error, it is a **silent unscanned allow** — the hook finds no field table, exits
early and writes nothing. "Written from the fixtures" does not settle that,
because the fixtures were written from the same reading. So each id is cited
individually here, and a recording is what replaces the citation.

| Tool id                  | Fields scanned           | Source                                                                                                            |
| ------------------------ | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `run_in_terminal`        | `command`, `explanation` | VS Code docs, "Copilot Chat tools" / `#runInTerminal`; the input schema published for the built-in terminal tool. |
| `create_file`            | `content`                | Same tool list, `#createFile`; `filePath` + `content` are its published inputs.                                   |
| `replace_string_in_file` | `newString`              | Same tool list; the string-replacement editing tool, whose inputs are `filePath`, `oldString`, `newString`.       |
| `insert_edit_into_file`  | `code`                   | Same tool list; the older insert-edit tool, whose input carries the edit as `code` plus an `explanation`.         |
| `apply_patch`            | `input`                  | Shared with the Copilot CLI's own `apply_patch`, where the argument name is likewise unverified.                  |

The `run_in_terminal` and `create_file` rows are now confirmed by
`../vscode/plugin-load-1.141/`: both ids arrived as `tool_name`, and every field
those two rows scan was present under that name. The recorded `run_in_terminal`
input also carried a `goal` field of model-authored prose that this table does
not scan. The other three rows are still citations only.

Two caveats applied to every row before the recordings, and still apply to the
three that have none:

- **The id is the tool-registry name, not necessarily the hook's `tool_name`.**
  The CLI's own reference notes that its PascalCase payloads report `tool_name`
  as the **Claude** spelling (`Bash`, not `bash`), which is direct evidence that
  a host may not put its registry id on the wire. Whether VS Code's agent mode
  does the same substitution is exactly what a recording would settle.
- **The key names are the tool's published input schema, not an observed
  payload.** Whether the hook receives them under those names, and in camelCase,
  is unverified — see the `tool_input` entry above.

For an id with no recording, a missed id fails **safe for the session and unsafe for
the finding**: nothing is blocked that should not be, and nothing is scanned
either.
