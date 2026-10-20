# @akasecurity/ai-tc-copilot — the `aka` plugin for GitHub Copilot

[![npm](https://img.shields.io/npm/v/@akasecurity/ai-tc-copilot?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/ai-tc-copilot)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

**AKA Security — We secure agent harnesses at the source.**

The GitHub Copilot plugin for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`). It hooks into a Copilot session and records its session start, prompts, tool calls and tool results to a local SQLite store at `~/.aka/data/aka.db`, scanning each one against your rule packs. On the Copilot CLI it can also block a shell command before it runs.

Detection runs entirely on your machine. Standalone by default — no account and no backend, and nothing is sent anywhere to be scanned.[^egress]

[^egress]: Live detection and enforcement run locally, on every install and whatever else is configured. This plugin has no setup calibration and no judge step, so it sends nothing to a model API, and it runs no package-manager lookups of its own. One narrow path can send anything off the machine, and it is opt-in: attaching this machine to an AKA deployment your organization runs (`aka attach`). Attached, the plugin forwards the activity that deployment is entitled to see, through `@akasecurity/remote`, the one package permitted to open a socket, and enforces the policy it sets, which can raise enforcement beyond your own settings but never lower it. Each captured event is sent as the local store holds it, so a value a detection flags under monitor or warn reaches that deployment unmasked. On a machine attached as a personal device, a Copilot session forwards activity only from the repositories enrolled with `aka enroll`; Copilot sign-ins are not recognised as work subscriptions, and everything else stays on the machine. Attached either way, the machine still sends more than activity, and no repository limits it. Whenever a session starts anywhere on this machine, in a repository or not (a browser chat included), the machine pulls the deployment's policy (at most every 15 minutes) and its sighting key (when none is stored or the stored one is a day old) and sends it a device report (at most hourly): a device identifier, host name, versions, detection packs, policy counts, finding counts and dates for everything recorded on the machine, and, when the machine is attached as a personal device, the fact that it is one. Where a scan is available (the coding-agent plugins, not a browser chat), the same session start also checks it for device commands. On a personal device, the background sync also asks the deployment which account its key belongs to, and asks again at later syncs until the device has an answer; syncs that overlap can each send one. A capture that could not be delivered at the time is kept and sent later in the background, and the separate `aka sync-history` grant sends what was recorded before the attachment. What has been sent cannot be recalled. Nothing is forwarded until both an endpoint and an access key are on disk; `aka status` says what a machine is attached to and `aka detach` ends it. [SECURITY.md](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-in-transit) has the full picture.

The local store keeps your prompts and tool calls verbatim apart from the spans a rule masks, and file permissions — not encryption — are all that protect it. See [Data at rest](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-at-rest) for which files it spans and what holds on Windows.

## Supported surfaces

| Surface            | Status                                                                                    |
| ------------------ | ----------------------------------------------------------------------------------------- |
| Copilot CLI        | Supported. Windows is unconfirmed.                                                        |
| VS Code agent mode | Beta. Capture was observed; enforcement is unverified.                                    |
| Cloud coding agent | Not covered by a plugin install. It reads only a repository's own `.github/hooks/*.json`. |

## Install

The plugin is installed from an unpacked copy of its npm package. There is no marketplace entry for it yet. The [setup skill](https://github.com/akasecurity/ai-tc/blob/main/plugins/copilot/skills/setup/SKILL.md) is the authority on these steps, and `aka plugins install copilot` prints them.

### Copilot CLI

```sh
mkdir -p aka-copilot && cd aka-copilot
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
copilot plugin install ./package
copilot plugin list
aka init
```

`copilot plugin list` shows `aka-copilot` once the install has landed. To remove it, run `copilot plugin uninstall aka-copilot`. The Copilot CLI warns that installing from a local path is deprecated in favour of marketplace installs.

Keep the `aka-copilot` folder; the first line is safe to run again and reuses it. To update, from inside that same folder:

```sh
rm -rf package
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
copilot plugin update aka-copilot
```

`copilot plugin update` re-copies the `package` folder into the installed plugin. It does not fetch a newer version itself; the newer version is the one `npm pack` just unpacked there.

### VS Code agent mode (beta)

If you have already installed into the Copilot CLI, reuse that `aka-copilot` folder and skip this step, so VS Code loads the same folder the update steps refresh. Otherwise pack and unpack the package the same way:

```sh
mkdir -p aka-copilot && cd aka-copilot
tar -xzf "$(npm pack @akasecurity/ai-tc-copilot --silent)"
```

Then point VS Code at the unpacked folder in your user settings:

```json
{
  "chat.plugins.enabled": true,
  "chat.useHooks": true,
  "chat.pluginLocations": { "<absolute path to the unpacked package folder>": true }
}
```

`npm pack` unpacks into a folder named `package`; use its absolute path.

## Known limitations

The setup skill's [Known limitations](https://github.com/akasecurity/ai-tc/blob/main/plugins/copilot/skills/setup/SKILL.md#known-limitations) section is the authority on what AKA can do on each surface. In brief:

- **Only a tool call can be stopped.** Prompts and tool results are captured, scanned and recorded, so a secret in either shows up as a finding, but neither is ever blocked or rewritten.
- **AKA's notices are not shown to you.** On the Copilot CLI in `-p` mode they appeared only in the debug log; in VS Code, only in the "GitHub Copilot Chat Hooks" output channel.
- **No setup wizard and no history backfill yet.** Use the `aka` CLI directly (`aka init`, `aka detections`, `aka scan`), and nothing reads the sessions that happened before the plugin was installed.

## Where your data lives

Everything is under `~/.aka`: settings in `~/.aka/settings`, the store at `~/.aka/data/aka.db`. Run `aka dashboard` to browse findings in the local web dashboard.

## Docs

Full documentation and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
