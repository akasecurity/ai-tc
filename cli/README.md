# @akasecurity/cli — `aka`

[![npm](https://img.shields.io/npm/v/@akasecurity/cli?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/cli)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

**AKA Security — We secure agent harnesses at the source.**

The `aka` command-line tool for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`) — an open-source, local-first control plane for coding agents. It inspects and governs the traffic of an agent session (prompts, tool calls, responses, file reads), scans each event against your rule packs, and records everything to a local SQLite store at `~/.aka/data/aka.db`.

Detection, enforcement, and your store run on your machine. There's no account and no backend unless you attach to one, and nothing leaves your computer to be scanned. Four narrow paths do reach the network. Two of them carry none of your data: the version check that runs after a command, and the registry lookups and installs that `aka plugins`, `aka update` and `aka check-updates` drive. The third is `aka attach`, which is off until you run it and then forwards activity on purpose. The fourth is `aka scan` on an attached machine, which forwards the Data Shares register it just recorded.[^egress]

If your organization runs its own AKA deployment, `aka attach --url <https-url>` registers this machine against it — after which activity that deployment is entitled to see is forwarded, and the policy it sets is enforced (it can raise enforcement beyond your own settings, never lower it; on a machine attached with `--scoped`, the models it prohibits are refused only in the repositories you enroll and in any folder of a session signed in to a recognised work subscription or to an account you enroll by hand). That is opt-in and off until you run it: `aka status` says what a machine is attached to and in which mode, and `aka detach` ends it. On a personal device, `aka attach --url <https-url> --scoped` forwards only activity from the repositories you enroll with `aka enroll` (`aka enroll --list` shows them, `aka unenroll` takes one out), from Claude Code sessions signed in to a recognised work subscription or to an account you enroll by hand with `aka enroll --account` and, from the browser extension, only the replies in a claude.ai account you enroll with `aka enroll --account`, with their tool calls and token usage (a prompt typed into a web chat is not recorded there at all); everything else stays on this machine; it also sends more than activity, and no repository limits that. A Claude Code session counts as a work subscription when it is signed in through claude.ai to a Team or Enterprise plan under the same email as the AKA account that attached the device. Such a session sends everything it records from its first reply on, from any folder, with that folder's project and branch names, and your organization's prohibited models are refused in any folder of it. To tell whether a session is one, the device reads Claude Code's login file, the session's own log, and Claude Code's settings files (the project's own included) and environment variables that choose the account or provider, and compares the signed-in email with the account that attached the device. The check sends none of what it reads, though the token usage and tool calls read from that same log are forwarded with the rest of the activity of a recognised session or of one signed in to an account enrolled by hand. The first prompt of a new session, a personal plan, another email, an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule; `aka enroll --account` enrolls by hand an account the device cannot recognise, and the Claude Code sessions of an account enrolled that way then forward from their first reply on whatever the plan or email, though not under an API key or another provider. An organization recognised this way never records or forwards a claude.ai chat. A personal device that attached before its plugin could recognise work subscriptions starts recognising them when the plugin updates, with no new prompt, so update `aka` first. `aka unenroll --work-subscriptions` turns recognition off on this device and `aka enroll --work-subscriptions` turns it back on; it turns off only the automatic recognition, so while it is off, enrolled repositories and accounts enrolled by hand still forward (`aka unenroll --account` stops an account), and your organization's model restrictions apply only to them. A machine whose connection an administrator manages attaches machine-wide only, so it has no personal-device mode and no such opt-out. Whenever a session starts anywhere on this machine, in a repository or not (a browser chat included), the machine pulls the deployment's policy (at most every 15 minutes) and its sighting key (when none is stored or the stored one is a day old) and sends it a device report (at most hourly): a device identifier, host name, versions, detection packs, policy counts, finding counts and dates for everything recorded on the machine, and, when the machine is attached as a personal device, the fact that it is one. Where a scan is available (the coding-agent plugins, not a browser chat), the same session start also checks it for device commands. On a personal device, the background sync also asks the deployment once which account its key belongs to, when the device does not know it yet.

[^egress]: Scanning, enforcement and your store are local — there's no AKA server, and no account unless you attach to one. Four narrow paths reach the network. **Two are child processes** and carry none of the content of your prompts, tool calls or findings. The **update notice** runs after a command when stdout is a terminal; when its cache is stale it refreshes in the background with three `npm view` lookups — this package (`@akasecurity/cli`), plus the two marketplace plugin packages `@akasecurity/ai-tc-claude-code` and `@akasecurity/ai-tc-codex`, which are looked up whether or not you have them installed. So what the registry — and whatever proxy your npm configuration points at — learns is which packages this machine asked about, not which it runs. The notice is on by default, and `--no-update-check` skips it for a single invocation. Second, the commands that look up or install software — `aka plugins install`, `aka update` and `aka check-updates` — shell out to `npm`, `claude` or `codex`, which reaches the network the way those tools normally do. `aka check-updates` only reads: it issues the same `npm view` lookups and installs nothing. `aka detections` is not one of them: it lists packs and applies pack updates from your local store, and opens no connection of its own. **The third and fourth are neither**, and are the two paths where this CLI's own source opens a connection — through `@akasecurity/remote`, the one package permitted a socket. `aka attach` is the one that carries your activity, which is the point of attaching: it is opt-in, does nothing until both an endpoint and an access key are on disk and name the same host, and `aka detach` ends it. Attached with `--scoped`, it forwards activity, and the scan register below, only for the repositories enrolled with `aka enroll`, plus the activity of Claude Code sessions signed in to a recognised work subscription or to an account enrolled by hand with `aka enroll --account` and, from the browser extension, the replies in a claude.ai account enrolled with `aka enroll --account`, with their tool calls and token usage; everything else stays on this machine, and a prompt typed into a web chat is not recorded there at all. A Claude Code session counts as a work subscription when it is signed in through claude.ai to a Team or Enterprise plan under the same email as the AKA account that attached the device. Such a session sends everything it records from its first reply on, from any folder, with that folder's project and branch names, and your organization's prohibited models are refused in any folder of it. To tell whether a session is one, the device reads Claude Code's login file, the session's own log, and Claude Code's settings files (the project's own included) and environment variables that choose the account or provider, and compares the signed-in email with the account that attached the device. The check sends none of what it reads, though the token usage and tool calls read from that same log are forwarded with the rest of the activity of a recognised session or of one signed in to an account enrolled by hand. The first prompt of a new session, a personal plan, another email, an API key or another provider, a reply written before the device has confirmed the account, and the rest of a session whose organization changes follow the repository rule; `aka enroll --account` enrolls by hand an account the device cannot recognise, and the Claude Code sessions of an account enrolled that way then forward from their first reply on whatever the plan or email, though not under an API key or another provider. An organization recognised this way never records or forwards a claude.ai chat. A personal device that attached before its plugin could recognise work subscriptions starts recognising them when the plugin updates, with no new prompt, so update `aka` first. `aka unenroll --work-subscriptions` turns recognition off on this device and `aka enroll --work-subscriptions` turns it back on; it turns off only the automatic recognition, so while it is off, enrolled repositories and accounts enrolled by hand still forward (`aka unenroll --account` stops an account), and your organization's model restrictions apply only to them. A machine whose connection an administrator manages attaches machine-wide only, so it has no personal-device mode and no such opt-out. In either mode the machine also sends more than activity, and no repository limits it. Whenever a session starts anywhere on this machine, in a repository or not (a browser chat included), the machine pulls the deployment's policy (at most every 15 minutes) and its sighting key (when none is stored or the stored one is a day old) and sends it a device report (at most hourly): a device identifier, host name, versions, detection packs, policy counts, finding counts and dates for everything recorded on the machine, and, when the machine is attached as a personal device, the fact that it is one. Where a scan is available (the coding-agent plugins, not a browser chat), the same session start also checks it for device commands. On a personal device, the background sync also asks the deployment once which account its key belongs to, when the device does not know it yet. On macOS, attaching also installs a per-user LaunchAgent that re-invokes the drain on its own schedule, so what gets sent does not depend on a session ever reopening. And `aka scan` on an attached machine forwards the Data Shares register it just recorded — destination hosts, endpoints and file/line call sites, with no source text and the project key replaced by a digest, and, while this machine shares credential sightings, the credentials each call site uses: an environment variable it reads, by name, or a secret written in it, as a keyed fingerprint, never the value — to the same deployment; `--no-forward` skips it for one invocation, and an unattached machine sends nothing. While this machine shares credential sightings, `aka scan` also sends, in a request of its own, each secret the scan found, `.env` files included, as a sighting token (a keyed hash under the key the deployment issues) with its rule, the variable it is assigned to, its location class (a project file or a home dotfile), whether git tracks the file, and the project's digest and display name — never the value or a path; `--no-forward` skips that send too. Separately, and not one of the four: `aka <name>` dispatches git-style to an `aka-<name>` program from your own `PATH` (POSIX only; a built-in always wins). That program is yours, not ours — `ai-tc` does not bundle, pin or verify it — so whether it reaches the network is its business, not something this project can describe. The one path that sends your data to a MODEL belongs to the Claude Code plugin rather than to this CLI: its **opt-in** `/aka:setup` calibration sends what an initial history scan finds to the model API to be rated, behind two separate opt-ins, and the [plugin README](https://github.com/akasecurity/ai-tc/blob/main/plugins/claude-code/README.md) states that payload field by field.

The local store keeps your prompts and tool calls verbatim apart from the spans a rule masks, and file permissions — not encryption — are all that protect it. See [Data at rest](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-at-rest) for which files it spans and what holds on Windows.

## Install

```bash
npm install -g @akasecurity/cli
```

Requires **Node.js 24+** (the CLI uses the built-in `node:sqlite`).

Or install the self-contained binary, which needs no Node.js:

macOS / Linux, with [Homebrew](https://brew.sh):

```bash
brew install akasecurity/tap/aka
```

Windows, with [Scoop](https://scoop.sh):

```powershell
scoop bucket add akasecurity https://github.com/akasecurity/scoop-bucket
scoop install aka
# or, without adding the bucket:
scoop install https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka.json
```

Or the bootstrap installer, which downloads the same archive:

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex
```

Or download an archive directly — these four links always serve the newest binary release. The binary is ad-hoc signed and not notarized, so a browser download is quarantined and Gatekeeper refuses to run it, while `brew`, `curl` and command-line `tar` don't quarantine what they fetch.

| Platform              | Download                                                                                                             |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| macOS (Apple silicon) | [aka-darwin-arm64.tar.gz](https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka-darwin-arm64.tar.gz) |
| Linux x64             | [aka-linux-x64.tar.gz](https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka-linux-x64.tar.gz)       |
| Linux arm64           | [aka-linux-arm64.tar.gz](https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka-linux-arm64.tar.gz)   |
| Windows x64           | [aka-win32-x64.zip](https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka-win32-x64.zip)             |

Intel macOS (`darwin-x64`) has no binary build — install this package from npm instead (above), which needs Node.js 24+.

Each archive extracts to its own `aka-<platform>-<arch>/` directory; the binary has to stay inside it to find the files it loads at startup. Then run `aka init`.

Check a download against [SHA256SUMS](https://github.com/akasecurity/ai-tc/releases/download/bin-latest/SHA256SUMS) and its build provenance with `gh attestation verify` — [tools/installer/README.md](https://github.com/akasecurity/ai-tc/blob/main/tools/installer/README.md) sets out the trust chain and what each check does and does not establish. The Homebrew tap and Scoop bucket entries above are published by each binary release.

Upgrade the way you installed: `brew upgrade aka`, `scoop update aka`, `npm install -g @akasecurity/cli@latest`, or re-run the one-liner.

## Quick start

```bash
aka init         # scaffold the local store at ~/.aka
aka dashboard    # open the local web dashboard over your store
```

## What it does

| Command          | What it does                                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `aka init`       | Create the local store and settings under `~/.aka`.                                                                        |
| `aka dashboard`  | Launch the local web dashboard (findings, policies, exceptions).                                                           |
| `aka scan`       | Scan source files for security flaws; forwards the Data Shares register when attached and in scope.                        |
| `aka attach`     | Attach this machine to your organization's deployment; `--scoped` for a personal device.                                   |
| `aka status`     | Show what this machine is attached to, in which mode, and what is enrolled.                                                |
| `aka enroll`     | On a scoped attachment, choose which repositories and Claude accounts (Claude Code sessions and claude.ai chats) are sent. |
| `aka unenroll`   | Stop sending a repository or a Claude account from a scoped attachment.                                                    |
| `aka detections` | List installed detection packs and available updates.                                                                      |
| `aka exception`  | Manage exact-value exceptions that let a specific match through.                                                           |
| `aka stats`      | Show detection activity and token/cost summaries from the store.                                                           |
| `aka plugins`    | Optional hub to install agent plugins (e.g. Claude Code).                                                                  |
| `aka extension`  | Install the browser-extension bridge (`install` / `status` / `account`).                                                   |

Run `aka --help` for the full command list.

### External subcommands

Any other command dispatches, git-style, to an executable named `aka-<command>` on your PATH (POSIX only; built-ins always win). For example, with [aka-claude-tools](https://github.com/akasecurity/claude-tools) installed, `aka claude` launches the hardened Claude Code profile via its `aka-claude` launcher.

## The Claude Code plugin

The CLI gives you the dashboard, store, and scanning. To actually **intercept** a Claude Code session you also need the AKA plugin, which installs from the Claude Code plugin marketplace (not npm). With the CLI installed:

```bash
aka plugins install claude-code
```

This drives Claude Code to add the plugin for you (or prints the `/plugin` commands to run). See the [installation guide](https://akasecurity.github.io/ai-tc-docs/getting-started/installation/) for both components.

## The browser extension (ChatGPT + Claude.ai web chat)

The CLI also ships a Chrome extension that scans messages in ChatGPT and
Claude.ai web chat before they are sent, recording into the same local store
over Chrome's native messaging (no server, no open port). Set it up with:

```bash
aka extension install   # registers the native-messaging host with Chrome
aka extension status    # verify the wiring
```

Then load the extension in Chrome: open `chrome://extensions`, enable
Developer mode, click "Load unpacked", and select the directory the install
command prints. The standalone binary runs the native host itself; the npm
package runs it under the same Node.js runtime as the CLI.

On a machine attached as a personal device (`aka attach --scoped`), the
extension still checks each message before it is sent and blocks or masks it
as your policy says, and records a chat only in a claude.ai account you enroll
with `aka enroll --account`: each reply, with its tool calls and token usage,
under a record of the session that names the account and nothing about this
machine. That also needs web-chat capture turned on under Settings in `aka
dashboard`. Nothing else from a chat is recorded: not the prompt you type, and
nothing in any other account or on ChatGPT, so none of it can be sent, then or
by a later attachment. The popup names the account a claude.ai tab is in, and
`aka extension account --on` records each account it sees (its organization
id and when it was seen, nothing from the chat) so that `aka enroll
--list-detected` can list them; `--off` stops that and deletes the record. The
one exception is a value it blocks or masks, which leaves a masked entry, kept
for a day, so that `aka exception` can approve it. Opening a chat still counts as a session start,
so the machine still pulls the organization's policy and its sighting key and sends its device
report. A machine holding a
control-plane credential AKA cannot read records nothing from a chat either,
since what it was attached as is unknown. The extension's popup, `aka
extension status` and the dashboard's Settings page say when either is the
case, and the popup also names a site whose messages are not being checked.

The registration names `aka` through the link your package manager keeps
pointed at the current version (Homebrew's `opt/aka`, the installers' and
Scoop's `current`), so upgrading keeps it working. A copy of `aka` placed by
hand is registered where it sits: after moving or replacing it, run
`aka extension install` again. `aka extension status` reports a registration
whose launcher names something that is gone, a versioned path an upgrade will
remove, or a version other than the one your package manager now points at.

## Docs

Full documentation, architecture, and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
