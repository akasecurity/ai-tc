# @akasecurity/ai-tc-claude-code — the `aka` plugin for Claude Code

[![npm](https://img.shields.io/npm/v/@akasecurity/ai-tc-claude-code?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/ai-tc-claude-code)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

**AKA Security — We secure agent harnesses at the source.**

The Claude Code plugin for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`). It hooks into a Claude Code session and inspects its traffic — prompts, tool calls, tool results, file reads — scanning each event against your rule packs and applying inline **warn / redact / block** policies. Every event is recorded to a local SQLite store at `~/.aka/data/aka.db`.

Detection runs entirely on your machine. Standalone by default — no account and no backend, and nothing is sent anywhere to be scanned.[^egress]

[^egress]: Live detection and enforcement run locally, on every install and whatever else is configured. Two things can send anything off the machine, and both are opt-in. The first is the **opt-in** `/aka:setup` calibration below: to rate what an initial history scan finds, its judge step sends those findings to the model API through the `claude` CLI — the same provider your Claude session already uses, reached with your own credentials. For each finding that means the raw (unmasked) value including any secret, roughly 120 characters of the surrounding transcript text on either side (re-scanned before it goes, so every secret the rules detect in that window is masked, including the finding's own value where it appears there), the finding's rule, category, severity, masked value and confidence, and a sequential counter the model echoes back so its verdict can be matched to the finding. The source file's path is not sent. It takes **two** separate opt-ins — one to read your history at all, and a second, distinct grant to send what was found — and without the second the judge does not run. It keeps those values out of your local Claude transcript, but a copy of them does leave the machine. Withdrawing either grant stops future scans; it cannot recall what was already sent. The second is attaching this machine to an AKA deployment your organization runs (`aka attach`), after which the plugin forwards the activity that deployment is entitled to see and enforces the policy it sets — which can raise enforcement beyond your own settings but never lower it. On a machine attached in scoped mode, for a personal device, activity only from the repositories enrolled with `aka enroll` and from Claude Code sessions signed in to a recognised work subscription or to an account enrolled by hand with `aka enroll --account` is forwarded, as are, from the browser extension, the replies in a claude.ai account enrolled that way; everything else stays on the machine, and the models that policy prohibits are refused only in those repositories and in any folder of such a Claude Code session. A Claude Code session counts as a work subscription when it is signed in through claude.ai to a Team or Enterprise plan under the same email as the AKA account that attached the device. Such a session sends everything it records from its first reply on, from any folder, with that folder's project and branch names, and your organization's prohibited models are refused in any folder of it. To tell whether a session is one, the device reads Claude Code's login file, the session's own log, and Claude Code's settings files (the project's own included) and environment variables that choose the account or provider, and compares the signed-in email with the account that attached the device. The check sends none of what it reads, though the token usage and tool calls read from that same log are forwarded with the rest of the activity of a recognised session or of one signed in to an account enrolled by hand. The first prompt of a new session, a personal plan, another email, an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule; `aka enroll --account` enrolls by hand an account the device cannot recognise, and the Claude Code sessions of an account enrolled that way then forward from their first reply on whatever the plan or email, though not under an API key or another provider. An organization recognised this way never records or forwards a claude.ai chat. A personal device that attached before its plugin could recognise work subscriptions starts recognising them when the plugin updates, with no new prompt, so update `aka` first. `aka unenroll --work-subscriptions` turns recognition off on this device and `aka enroll --work-subscriptions` turns it back on; it turns off only the automatic recognition, so while it is off, enrolled repositories and accounts enrolled by hand still forward (`aka unenroll --account` stops an account), and your organization's model restrictions apply only to them. A machine whose connection an administrator manages attaches machine-wide only, so it has no personal-device mode and no such opt-out. Attached either way, the machine still sends more than activity, and no repository limits it. Whenever a session starts anywhere on this machine, in a repository or not (a browser chat included), the machine pulls the deployment's policy (at most every 15 minutes) and its sighting key (when none is stored or the stored one is a day old) and sends it a device report (at most hourly): a device identifier, host name, versions, detection packs, policy counts, finding counts and dates for everything recorded on the machine, and, when the machine is attached as a personal device, the fact that it is one. Where a scan is available (the coding-agent plugins, not a browser chat), the same session start also checks it for device commands. On a personal device, the background sync also asks the deployment which account its key belongs to, and asks again at later syncs until the device has an answer; syncs that overlap can each send one. On a machine attached machine-wide, a Claude Code session start also sends the Claude Code configuration that session's scan found: each skill, hook, MCP server and configuration file, with its name, scope, file path and the plugin or marketplace it came from; a skill's description, version and modification time; a hook's event, matcher, command and timeout, and an MCP server's transport and command or URL, each description, command and URL with any secret the bundled detection rules find masked, and an MCP server's URL also stripped of its credentials and query values; the names of an MCP server's environment variables, never their values; a configuration file's kind, modification time and a summary of its shape (key names, line and entry counts), never its contents; and the repository's remote URL with any credentials and query removed, or the working directory where it has none, that the project's own items belong to. A machine attached with `--scoped` keeps this configuration on the machine. Where the host shows a session-start message, a new session on an attached machine opens with a line saying where that session's own records go, and a local-only line says that work in an enrolled repository is still forwarded. On a personal device, a Claude Code session outside an enrolled repository opens with one of two lines: one saying it forwards to the deployment from its first reply, once the account is confirmed, which a recognised work subscription and an account enrolled by hand get (an API key or another provider keeps the session local-only), or the local-only line. A session that forwards sends everything it records from its first reply on, token usage and tool calls included; the first prompt of a new session and a reply written before the device has confirmed the account follow the repository rule. The line is a convenience, not the record: a resumed or compacted session shows none, and neither does a session whose start stopped before it recorded the session, so its absence never means nothing is forwarded, and `aka status` is the authoritative answer. The line names the deployment, by its label or by its address with no credential, so a transcript that keeps session-start messages carries that name. Nothing is forwarded until both an endpoint and an access key are on disk; `aka status` says what a machine is attached to and `aka detach` ends it.

The local store keeps your prompts and tool calls verbatim apart from the spans a rule masks, and file permissions — not encryption — are all that protect it. See [Data at rest](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-at-rest) for which files it spans and what holds on Windows.

## Install

This package is distributed through the **Claude Code plugin marketplace**, not `npm install`. Add the marketplace and install the plugin from inside Claude Code:

```text
/plugin marketplace add akasecurity/marketplace
/plugin install ai-tc@akasecurity
```

Or let the `aka` CLI install the plugin for you:

```bash
npm install -g @akasecurity/cli
aka plugins install claude-code
```

Either way, finish onboarding by running `/aka:setup` from inside Claude Code:

```text
/aka:setup
```

If you installed via the CLI, `aka init` scaffolds the local store and `aka dashboard` views findings.

## What it registers

The plugin installs Claude Code hooks that run locally with no `node_modules`, and fail open (a hook error never breaks your session). The one exception is a prompt, tool input or tool output field too large to scan within the hook's time limit, which is blocked, or withheld from the model, rather than passed unscanned. The hooks:

- **SessionStart** — snapshot the session context.
- **UserPromptSubmit** — scan prompts before they reach the model.
- **PreToolUse** — scan tool inputs (Bash, Edit, Write, MultiEdit, WebFetch, WebSearch, Agent /
  Task, and any `mcp__*` tool) before they run, and check the path of a Read or Grep that names a
  credential file (`.env`, a private key, `.netrc`, `credentials*`, `*auth.json`, shell rc files).
  Sensitive content in text a tool merely stores is masked in
  place; in text a tool acts on — a shell command, a URL, a search query, an MCP argument —
  masking would change what runs, so the call is blocked instead.
- **PostToolUse** — scan tool outputs and file reads (Bash, Read, WebFetch, Grep, WebSearch
  summaries and links, the report of a subagent run in the foreground, and the text blocks of any
  `mcp__*` tool's result) after they return. A subagent run in the background reports outside any
  tool result, so its report is not scanned.
- **Stop** — reconcile token usage and finalize the session record.

It also adds slash commands for reports and setup (`/aka:health`, `/aka:findings`, `/aka:dashboard`, and more).

The plugin works standalone, and governs what a session carries: rule packs, findings, policy, and an audit trail. To harden the harness itself — safe-default permissions, structural command guards, and credential deny rules — pair it with [claude-tools](https://github.com/akasecurity/claude-tools). They compose: claude-tools hardens the harness, `ai-tc` governs the traffic.

## Docs

Full documentation and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
