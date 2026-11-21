# Recording a live VS Code session

The VS Code rows in `src/capabilities.ts` marked `verified: false` describe what
VS Code documents, not what was seen. This runbook drives each of them against
a real VS Code install, records what the hooks received and answered, and turns
the result into a fixture directory under `vscode/` so a row can be marked
verified.

Use a throwaway account and throwaway values throughout. A recording holds
each payload exactly as VS Code sent it, prompts and tool output included.

## 1. Set up an isolated VS Code

Use a home, a VS Code user-data directory and an extensions directory that
belong to this session alone, so neither AKA's store nor VS Code's own state is
your everyday one:

```sh
export REC=$(mktemp -d)
mkdir -p "$REC/home" "$REC/user-data" "$REC/extensions" "$REC/work"
cd "$REC/work" && git init -q
```

Build and pack the plugin from this checkout, then unpack it:

```sh
pnpm --filter @akasecurity/ai-tc-copilot build
(cd plugins/copilot && npm pack --pack-destination "$REC")
mkdir -p "$REC/plugin" && tar -xzf "$REC"/akasecurity-ai-tc-copilot-*.tgz -C "$REC/plugin"
```

Register it in the isolated user-data directory's settings, and set up AKA's
store under the throwaway home:

```sh
node "$REC/plugin/package/scripts/vscode-install.js" --settings "$REC/user-data/User/settings.json"
HOME="$REC/home" aka init
```

## 2. Turn recording on

The hooks record only while `~/.aka/data/hook-recordings/` exists. Under the
throwaway home:

```sh
mkdir -p "$REC/home/.aka/data/hook-recordings"
```

Each hook run that reaches an answer writes one JSON file there, holding the
event token, the payload (`stdin`), what the hook answered (`verdict`) and the
exit code it ended in (`exitCode`). Remove the directory to turn recording off.

## 3. Launch VS Code and drive the scenarios

```sh
HOME="$REC/home" code --user-data-dir "$REC/user-data" --extensions-dir "$REC/extensions" "$REC/work"
```

Sign in to GitHub in that window and open the chat in agent mode. Set policies
on the dashboard (`HOME="$REC/home" aka dashboard`). For every scenario, write
down what the chat showed and what the "GitHub Copilot Chat Hooks" output
channel logged; a recording shows what the hook said, not what VS Code did
with it.

Use a value the bundled rules detect that is not a rule's documented example,
since the scanner caps documented examples at warn. Each row names the
capability-matrix row it settles.

| #   | Row                        | Set up                                                                              | Drive                                                      | Expect, if VS Code honours it                                                |
| --- | -------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 1   | PreToolUse command (block) | Secrets pack on Block                                                               | Ask the agent to run `echo <value>` in the terminal        | Recording: `hookSpecificOutput.permissionDecision: "deny"`. Command not run. |
| 2   | PreToolUse file write      | Secrets pack on Redact                                                              | Ask the agent to create `notes.md` containing the value    | Recording: `updatedInput` with the value masked. File on disk is masked.     |
| 3   | PreToolUse large input     | Delete `scan-worker.js` from `$REC/plugin/package/scripts/`, then reload the window | Ask the agent to run a command over 32,768 characters long | Recording: a deny naming the size limit. Command not run.                    |
| 4   | UserPromptSubmit (block)   | Secrets pack on Block                                                               | Send a prompt containing the value                         | Recording: `exitCode: 2`, `verdict.promptBlock`. The prompt is not sent.     |
| 5   | UserPromptSubmit large     | As row 3                                                                            | Send a prompt over 32,768 characters long                  | Recording: `exitCode: 2`. The prompt is not sent.                            |
| 6   | PostToolUse flagged result | Secrets pack on Warn; put the value in a file in the workspace                      | Ask the agent to `cat` that file                           | Recording: `systemMessage` naming the rule. Output reaches the model.        |

Restore `scan-worker.js` (re-unpack the tarball) after rows 3 and 5.

## 4. Turn the recordings into fixtures

1. Create `vscode/<what-it-shows>-<VS Code version>/`, for example
   `vscode/enforcement-1.143/`.
2. For each recording, save its `stdin` value as one `.json` file named for the
   event and the scenario, for example `preToolUse-deny-run_in_terminal.json`.
   The fixture is the payload alone; what the hook answered goes in the README.
3. Rewrite before commit, and say so in the README: the throwaway workspace
   path, the user-data directory, any user or host name a tool result echoes,
   and the secret value itself, replaced by the same rule's documented example
   so the fixture is still detected.
4. Write the directory's README the way `vscode/plugin-load-1.141/README.md`
   is written: the VS Code and Copilot Chat versions, how it was launched, each
   file by name with its event, what the hook answered and its exit code, and
   what the chat and the hooks output channel showed.
5. Add the directory to the pinned session list in
   `test/fixture-provenance.test.ts`, mark each row the recordings back
   `verified: true` in `src/capabilities.ts` with a note citing the directory,
   and update the table in `skills/setup/SKILL.md` to match.

A row where VS Code did not honour the answer stays unverified, and its note
says what was seen instead.
