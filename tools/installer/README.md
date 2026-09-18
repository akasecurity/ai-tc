# AKA installer

Installs the self-contained `aka` binary. **No Node.js required** — the binary embeds
its own runtime.

## Usage

```bash
# macOS (Apple Silicon) / Linux (x64, arm64)
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh
```

```powershell
# Windows (x64, PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex
```

```sh
# From a checkout
sh tools/installer/install.sh
```

## What it does

1. Detects your OS + architecture and picks the matching release asset
   (`darwin-arm64`, `linux-x64`, `linux-arm64`, `win32-x64`).
2. Downloads the archive **and `SHA256SUMS`** from the latest `bin-v*` GitHub Release,
   and verifies the archive against the checksum — **fail closed** on any mismatch.
3. Extracts to `~/.local/share/aka/<version>` (macOS/Linux) or `%LOCALAPPDATA%\aka`
   (Windows) and links `aka` onto your `PATH` (`~/.local/bin` / a user-PATH entry).
4. Runs `aka --version` to confirm. Then run `aka init`.

## Supported targets

`darwin-arm64` (Apple Silicon), `linux-x64`, `linux-arm64`, `win32-x64`. Intel macOS
(`darwin-x64`) is not built. Plugins install through the CLI once it is on your PATH
(`aka plugins install <agent>`) or, for Claude Code, the plugin marketplace.

## Homebrew and Scoop

`brew install akasecurity/tap/aka` reads `Formula/aka.rb` from the
[akasecurity/homebrew-tap](https://github.com/akasecurity/homebrew-tap) repository, and
`scoop install aka` (after `scoop bucket add akasecurity
https://github.com/akasecurity/scoop-bucket`) reads `bucket/aka.json` from the
[akasecurity/scoop-bucket](https://github.com/akasecurity/scoop-bucket) repository. The
release workflow renders both files from that release's own `SHA256SUMS` and pushes them
there. Each names the release's **versioned** archive URL and its checksum, so the package
manager checks the archive it downloads against the sums that release published — which,
like the installers' check, catches a corrupt download rather than a substituted release.

The same `aka.rb` and `aka.json` are attached to every release. The attached `aka.json` is
an install path of its own —
`scoop install https://github.com/akasecurity/ai-tc/releases/download/bin-latest/aka.json`
works without adding the bucket. The attached `aka.rb` is a copy to read, not to install:
current Homebrew refuses `brew install ./aka.rb`, so the tap is the only Homebrew route.
Check the provenance of the archive a package manager downloaded exactly as for a direct
download: `gh attestation verify aka-<version>-<triple>.tar.gz -R akasecurity/ai-tc`.

## Trust chain

- The one-liner fetches `install.sh` / `install.ps1` from the **`bin-latest` tag** over
  HTTPS, never `main`. The release workflow points `bin-latest` at each published
  binary release, so the tag only moves when a release is cut.
- The script downloads the archive and `SHA256SUMS` from that release and verifies the
  archive before extracting it. Both come from the same release over TLS.
- Pin an exact release with `AKA_INSTALL_REF=bin-v<version>`.

### What the checksum does and does not establish

The `SHA256SUMS` check catches a **corrupt or truncated download** — a proxy that
mangled the bytes, a connection that dropped mid-transfer, a mirror serving a stale
archive. It does not establish that the release is the one AKA published: the archive
and the sums file arrive **from the same release over the same connection**, so
anything able to substitute one is able to substitute the other. A verified checksum
means the archive matches the sums file next to it, and nothing more.

### Build provenance (verifiable, and not verified by the installers)

Every asset a `bin-v*` release publishes — each `.tar.gz`, the `.zip`, `SHA256SUMS`
itself, and the rendered `aka.rb`, `aka.json` and `VERSION` — carries a
**build-provenance attestation**, generated in the release workflow and signed with a
short-lived Sigstore certificate. It records which repository, workflow and commit
produced those exact bytes. The `bin-latest` download links are covered too: the rolling
release's archives are byte-identical renames of that release's versioned archives, and
an attestation identifies an artifact by its digest, so they verify under their alias
names; the `SHA256SUMS` beside them lists those alias names and is attested in its own
right. Check one with the GitHub CLI:

```bash
gh attestation verify aka-<version>-<triple>.tar.gz -R akasecurity/ai-tc
# and the file the installer verifies against:
gh attestation verify SHA256SUMS -R akasecurity/ai-tc
```

**The installers do not do this, and require no `gh`.** `install.sh` and `install.ps1`
verify the checksum and stop there — a one-liner that depended on the GitHub CLI would
fail on most machines it is meant to bootstrap. Verifying provenance is a step you take
deliberately, on a machine that has `gh`, and it is the step that distinguishes a
corrupt download from a substituted release.

### What nothing here covers

- **The installers themselves.** `install.sh` and `install.ps1` are fetched from
  `bin-latest`, which is a **movable tag** — the release workflow force-moves it on
  every release. They are covered by neither the checksum (they are not release
  assets) nor the attestation. Piping either script to a shell trusts the tag. Read
  the script first, or install from a checkout.
- **Gatekeeper, on macOS.** A file downloaded by a browser is quarantined and assessed
  on first launch; a file fetched by `curl` is **not quarantined at all**, so the
  binary the one-liner installs is never assessed. The binary is ad-hoc signed — that
  is what lets it run on Apple Silicon — and is neither Developer ID signed nor
  notarized, so a browser-downloaded archive would be refused where the
  `curl`-installed one runs.
- **Which release the `bin-latest` links serve.** They always resolve to the newest
  binary release — each release replaces the assets behind them. A link fetched
  yesterday and one fetched today can be different versions, each correctly attested;
  pin a version with its `bin-v<version>` release instead.

## Uninstalling

`brew uninstall aka` and `scoop uninstall aka` remove the binary and the package
manager's own bookkeeping only. What `aka` itself wrote stays behind: `~/.aka`, the
Chrome native-messaging manifest `aka extension install` registers, and on macOS the
LaunchAgent `aka attach` installs.

## Overrides

| Variable                            | Default              | Purpose                                                              |
| ----------------------------------- | -------------------- | -------------------------------------------------------------------- |
| `AKA_INSTALL_REF`                   | latest `bin-v*`      | Pin a specific release (`bin-v0.8.1`).                               |
| `AKA_INSTALL_DIR`                   | `~/.local/share/aka` | Where versions are extracted.                                        |
| `AKA_BIN_DIR`                       | `~/.local/bin`       | Where the `aka` symlink is placed (POSIX).                           |
| `AKA_DOWNLOAD_BASE` + `AKA_VERSION` | —                    | Fetch the archive + `SHA256SUMS` from a local/mirror base (testing). |

## Tests

```bash
pnpm --filter @akasecurity/installer test
```

Both scripts are **executed** here, not read: `test/` serves a fixture release over
loopback (`AKA_DOWNLOAD_BASE`, the last row above), then runs the real `install.sh` /
`install.ps1` against it. The cases are the happy path — download → verify → extract →
link → `aka --version` — plus the two refusals the verification step exists for: an
archive tampered with after `SHA256SUMS` was written, and an archive `SHA256SUMS` does
not list at all. Each refusal asserts the MESSAGE as well as the exit code, because the
two paths are separately guarded and both exit non-zero: an exit-code-only check stays
green while one guard is gone.

Which cases can run depends on the host, and a case that cannot is skipped rather than
quietly passing:

| Case                      | Linux / macOS                                                       | Windows                                                           |
| ------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------- |
| script encoding (6 cases) | ✅                                                                  | ✅                                                                |
| `install.sh`, all three   | ✅                                                                  | skipped — `uname -s` reports MINGW and the script refuses that OS |
| `install.ps1` refusals    | ✅ where `pwsh` exists                                              | ✅                                                                |
| `install.ps1` happy path  | skipped — the junction and the user-`Path` rewrite are Windows-only | opt-in — `AKA_INSTALLER_ALLOW_USER_PATH=1`                        |

**The Windows happy path is opt-in, and deliberately so.** It rewrites the persisted
user `Path`, because that is what the installer does. The suite snapshots the value and
puts it back, but the restore is not quite lossless: reading through `[Environment]`
expands any `%VAR%` reference and writes the result back as a plain string. So a plain
`pnpm test` on a Windows workstation would flatten a contributor's `Path` — and a run
killed before the restore would leave a temp directory on it. Set
`AKA_INSTALLER_ALLOW_USER_PATH=1` to run it; CI does, a workstation need not. (That
expansion is `install.ps1`'s own behaviour on every user who installs, not something the
suite introduces — a separate defect, tracked separately.)

`test/script-encoding.test.ts` guards something the other cases cannot see: both scripts
must be **pure ASCII**. A BOM-less `.ps1` is decoded by Windows PowerShell 5.1 with the
system ANSI codepage, and under CP1252 an em dash's UTF-8 bytes end in U+201D — which
PowerShell's lexer accepts as a closing double quote. One em dash inside a double-quoted
string therefore stops the whole file parsing, and the error names a quote several lines
away rather than the character or the encoding. ASCII is the fix rather than a BOM
because it decodes identically under every codepage and survives every consumption path.

CI runs all of it: `ci.yml` has no path filter, so an installer-only PR is exercised on
all three platforms, and `build-binaries.yml` additionally points the suite at the real
`archive:sea` output on every supported target — the shipped script installing the
artifact a user downloads.
