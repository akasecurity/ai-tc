---
name: aka-scan
description: Scan working-tree source files for code security flaws
---

# AKA scan

## Single-repo scan (default)

Run the worktree scan script and show the user its output **exactly as printed**.
The script already prints its content inside a Markdown code fence — reproduce
that verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is space-aligned monospace that Markdown would otherwise
collapse.

```bash
node "${PLUGIN_ROOT}/scripts/filescan.js" --dir "${PWD}"
```

This scans all source files (`.ts`, `.js`, `.py`, `.java`, `.rb`, `.cs`, `.go`,
`.rs`, `.php`, and more) under the current project directory for insecure code
patterns — SQL injection, command injection, XSS, insecure deserialization, weak
cryptography, hardcoded credentials, dev-mode configuration leaks, and other
OWASP Top 10 issues.

Results are recorded to the local store (`~/.aka/data/aka.db`) and are visible
via the aka-findings skill. Re-running this scan is safe — files whose content
has already been recorded are skipped.

Files excluded by the repo's `.gitignore` are **still scanned** — local scratch
and generated files are a common place for real secrets to hide — but their
findings are marked as coming from gitignored content and reported as
informational in the summary.

To exclude paths from scanning entirely, add a `.akaignore` file (gitignore
syntax, any directory level). Unlike `.gitignore`, `.akaignore` is a **hard
skip**: matching files are never read and produce no findings. A negation also
re-includes a directory the scanner skips by default — e.g. `!vendor/` scans
first-party code living under `vendor/`.

## Multi-repo scan (opt-in)

To scan **all git repositories** found under the current directory (up to 4
directory levels deep), use the `--discover` flag:

```bash
node "${PLUGIN_ROOT}/scripts/filescan.js" --discover
```

To search from a different directory, pass `--root` (and optionally `--depth`):

```bash
node "${PLUGIN_ROOT}/scripts/filescan.js" --discover --root ~/projects --depth 3
```

Discovery walks the filesystem from the search root looking for `.git`
directories. It skips large system directories (`Library`, `node_modules`, etc.)
and stops recursing once a repo root is found (submodules are not separately
enumerated). The output shows a per-repository breakdown in addition to the
aggregate totals.

**Scope confirmation:** `--discover` never sweeps the home directory implicitly —
the default root is the current directory. Before passing a `--root` outside the
current project (especially `--root ~`, the whole-machine sweep), tell the user
what will be read and ask for explicit confirmation. Do not assume consent from
a generic "scan everything" phrasing without naming the scope.

Deduplication is global across all repos in a single `--discover` run — a file
whose content hash is already recorded (from a previous scan or a live hook
capture) is skipped regardless of which repo it lives in.
