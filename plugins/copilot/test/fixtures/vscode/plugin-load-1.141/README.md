# VS Code agent mode hook payloads — recorded, plugin-load route

Each `.json` file here is the JSON one hook received on stdin from **VS Code
1.141.0** with its built-in **GitHub Copilot Chat 0.69.0** extension, in one
agent-mode session on macOS. VS Code loaded this package's packed plugin from a
local directory and ran its built hooks. These are the first VS Code recordings
in this package. The doc-derived specimens in `../../vscode-provisional/` are
still there, and that directory's README says which of their claims these files
confirm and which they contradict.

`test/vscode-fixture-shapes.test.ts` in this package pins the exact set of files
and the field values this note calls out. `test/fixture-provenance.test.ts`
requires every file here to be named in this README.

## How they were recorded

- **The host.** VS Code 1.141.0, launched as
  `HOME=<throwaway home> code --user-data-dir <dir> --extensions-dir <dir>`.
  AKA's store was therefore a fresh `~/.aka` under the throwaway home, and VS
  Code's own state was isolated too. The user signed in to GitHub inside that
  window.
- **The plugin.** The npm-packed plugin at 0.9.19, unpacked to a local
  directory. VS Code loaded it through three user settings:

  ```json
  {
    "chat.plugins.enabled": true,
    "chat.useHooks": true,
    "chat.pluginLocations": { "<absolute path to the plugin directory>": true }
  }
  ```

  Nothing was registered anywhere else. In particular, no VS Code-specific
  hooks file was written. VS Code read the plugin's own `hooks.json`, which is
  the CLI-format file this package ships.

- **The capture.** Each hook command in the unpacked `hooks.json` was prefixed
  with a `tee` into a file named for its event and the shell's pid. The hook
  still received the same bytes. The manifest in this package was never
  changed.
- **The session.** Agent mode was driven by hand with two prompts, both recorded
  verbatim below. The workspace was a git repository with no remote. Its `.env`
  started with an unrelated `APP_MODE=` line, and a later line assigned
  `GH_TOKEN` the bundled `secrets/github-pat` rule's own example value.
- **What VS Code logged.** The "GitHub Copilot Chat Hooks" output channel
  showed, for every hook, a `Running` line, an `Input` line carrying the same
  payload, then `Completed (Success)` and, where the hook wrote to stdout, an
  `Output` line.

## What was rewritten before commit

- **The throwaway workspace** became `/Users/dev/work`, in `cwd`, in
  `create_file`'s `filePath`, and wherever else it appeared.
- **The isolated `--user-data-dir`** became VS Code's default macOS location
  under the placeholder home, `/Users/dev/Library/Application Support/Code`, so
  `transcript_path` reads `/Users/dev/Library/Application Support/Code/User/…`.
  That is not the directory the session ran under. Only the part after
  `User/` is VS Code's own layout.
- **The capturing user's name in the shell prompt** that `run_in_terminal`
  echoes into its result became the placeholder user `dev`, so the prompt reads
  `dev@Mac work %`. The host part, `Mac`, is as received. The replacement is
  shorter than the original, so the line wraps in that result no longer fall
  at the terminal's real width; they are where the terminal put them.
- **Nothing else was changed.** The session id, the ISO timestamps, the tool
  ids, the tool arguments, the `tool_use_id`s and the rest of the tool results
  are as received. The files were re-indented; their content was not.

## The files

All seven come from one session, `fcbfebce-dbe0-4aa1-b640-4b6590f9a3a3`. In the
order they fired:

| File                                    | `hook_event_name`  | `timestamp`                |
| --------------------------------------- | ------------------ | -------------------------- |
| `sessionStart.json`                     | `SessionStart`     | `2026-10-19T10:42:00.538Z` |
| `userPromptSubmitted-cat-env.json`      | `UserPromptSubmit` | `2026-10-19T10:42:00.689Z` |
| `preToolUse-run_in_terminal.json`       | `PreToolUse`       | `2026-10-19T10:42:13.834Z` |
| `postToolUse-run_in_terminal.json`      | `PostToolUse`      | `2026-10-19T10:42:16.964Z` |
| `userPromptSubmitted-create-notes.json` | `UserPromptSubmit` | `2026-10-19T10:42:24.441Z` |
| `preToolUse-create_file.json`           | `PreToolUse`       | `2026-10-19T10:42:36.220Z` |
| `postToolUse-create_file.json`          | `PostToolUse`      | `2026-10-19T10:42:36.346Z` |

Each file is named by the camelCase event token its hook command passed on
argv, which is also the `hooks.json` key that produced it, followed by what the
call was.

## Recorded

- **VS Code loads the CLI-format `hooks.json` from a plugin directory and runs
  all four events.** The file's keys are the camelCase `sessionStart`,
  `userPromptSubmitted`, `preToolUse` and `postToolUse`. VS Code dispatched
  them as the PascalCase events `SessionStart`, `UserPromptSubmit`,
  `PreToolUse` and `PostToolUse`.
- **The payloads are the VS Code snake_case dialect,** not the CLI's camelCase
  one, even though they came from camelCase keys. Every payload carries
  `timestamp`, `hook_event_name`, `session_id`, `transcript_path` and `cwd`.
  The tool events add `tool_name`, `tool_input` and `tool_use_id`, and
  `PostToolUse` adds `tool_response`. `detectDialect` reads all seven as
  `vscode`.
- **The argv token is still the camelCase one.** Each hook command passed
  `sessionStart`, `userPromptSubmitted`, `preToolUse` or `postToolUse` as
  written in `hooks.json`, and every entry accepted it.
- **`${PLUGIN_ROOT}` expands in hook commands.** The `Running` line showed each
  command with the absolute plugin directory in place of `${PLUGIN_ROOT}`. The
  same line showed `PLUGIN_ROOT` set in the hook's environment, the hook's
  working directory as the workspace folder, and `timeoutSec: 30` carried as
  `timeout: 30`.
- **`timestamp` is an ISO-8601 string** with millisecond precision and a `Z`
  suffix, not the epoch-millisecond number the CLI sends.
- **`cwd` is sent on every event,** although no hook entry declared one. It is
  the workspace folder.
- **`transcript_path` is present on every event** and points under
  `User/workspaceStorage/<hash>/GitHub.copilot-chat/transcripts/<session id>.jsonl`.
- **`SessionStart` carries `source: "new"` and `model: "auto"`.** It carries no
  prompt.
- **`SessionStart` fired first.** `UserPromptSubmit` followed 151 ms later. That
  is the opposite of the CLI, where the prompt hook fires before the session
  hook.
- **`run_in_terminal`'s `tool_input` is `{ command, explanation, goal, mode }`.**
  `mode` was `"sync"`. The model ran
  `cat .env | awk …` rather than a bare `cat .env`, so the awk program printed
  only whether the first line starts with `GH_TOKEN`. The first line is
  `APP_MODE=`, so it printed `does not start with GH_TOKEN`, and the token never
  reached the tool result.
- **`create_file`'s `tool_input` is `{ filePath, content }`,** with an absolute
  `filePath`.
- **`tool_response` is a string on both tool calls.** For `run_in_terminal` it
  is the terminal's text: the echoed prompt and command, wrapped at the
  terminal's width, then the output. For `create_file` it is the empty string.
- **`PostToolUse` repeats `tool_input` and `tool_use_id`** exactly as
  `PreToolUse` sent them.
- **What the throwaway store recorded:**
  - one session root, with `harness_interface` `vscode`, keyed by the
    payload's `session_id`;
  - two `prompt` captures, one per prompt;
  - one `tool_use` for the `run_in_terminal` call, with the finding
    `command-risk/credential-file-read` and action `warn`;
  - one `code_change` for `create_file`, whose content is `hello`;
  - no `response` row. Neither tool result was flagged, and responses are
    persisted only with findings.
- **Hook stdout reached VS Code.** The first `UserPromptSubmit` hook wrote the
  first-run notice, and the `run_in_terminal` `PreToolUse` hook wrote the warn:

  ```
  {"systemMessage":"AKA is active and monitoring your prompts (log-only by default — nothing is blocked or redacted yet). Run the aka-setup skill to choose your installation type and set enforcement (warn/redact/block) per detection."}
  {"systemMessage":"AKA flagged sensitive content in run_in_terminal input (command-risk/credential-file-read)."}
  ```

  VS Code logged both as `Output` and
  reported every hook as `Completed (Success)`. Every other hook wrote nothing,
  and VS Code logged `no output` for each.

- **A `systemMessage` is not shown in the chat UI.** The user was watching the
  Copilot Chat panel throughout and saw nothing from AKA there: neither the
  first-run notice nor the warn. Both appeared only in the "GitHub Copilot Chat
  Hooks" output channel. So on this build a `warn`, including a redact that
  resolved to the `warn` fallback, is invisible to the user, as it already is on
  the Copilot CLI. This was observed on one run, in agent mode.

## Settled for the adapter

`test/vscode-fixture-shapes.test.ts` drives the adapter's own readers over
these files:

- `detectDialect` reads every payload as `vscode`, and `readSessionStartFacts`
  opens the root as the `vscode` interface with the recorded session id and
  `cwd`.
- Each prompt is read under the camelCase argv token its hook command passed.
- Every field the VS Code table scans for `run_in_terminal` (`command`,
  `explanation`, `goal`) and `create_file` (`content`) is present under that
  name.
- The string `tool_response` is read as one field, and the empty one as none.

Where the recordings and the adapter do not line up:

- **`timestamp`, `transcript_path`, `tool_use_id` and `SessionStart.model`** are
  read by nothing. That costs nothing today: the store stamps each capture
  with the hook's own clock, and there is no backfill to read a transcript.
- **`run_in_terminal.mode`** is the one recorded `tool_input` field the adapter
  does not scan. It is the tool's own execution dial and carries no user text,
  so there is nothing in it to find.

## Unmeasured

Nothing in this session reached any of these, so none of them is measured:

- a `PreToolUse` deny, through `hookSpecificOutput.permissionDecision` or
  through exit 2;
- an `updatedInput` rewrite of a file-write tool's content, including whether
  the `permissionDecision: 'allow'` it rides with is honoured. `run_in_terminal`
  is not rewritten at all: a redact on its `explanation` or `goal` takes the
  workspace `redactFallback`, because the allow would approve its `command`;
- the large-input refusal;
- an object-shaped or array-shaped `tool_response`;
- a flagged tool result;
- `PreCompact`, `SubagentStart`, `SubagentStop` and `Stop`, which this
  package's `hooks.json` does not register.
