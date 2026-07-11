---
description: Launch the AKA web dashboard in your browser (reads your local store)
---

# AKA dashboard

Launch the AKA web dashboard and relay the short status the script prints **as-is**.
The command returns immediately: it starts the dashboard server in the background
and it opens in the browser once ready, so a lack of further output is **not** an
error — do not wait on it or re-run it. If the script prints install guidance (the
`aka` CLI isn't installed), relay that verbatim.

If the user asked for a specific port, pass `--port <N>` through unchanged;
otherwise run it with no arguments.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/dashboard.js" [--port <N>]
```

This mirrors the `aka dashboard` CLI command: it serves the OSS web-ui against
your local store at `~/.aka/data` (no backend) and opens
`http://localhost:4319/security`. The web server is bundled in the
`@akasecurity/cli` package — the plugin ships no server of its own — so the
launcher delegates to the `aka` CLI and, if it isn't installed, prints how to get
it. For the terminal-only read surfaces, use `/aka:health`, `/aka:findings`,
`/aka:recommend`, `/aka:audit` or `/aka:tokens` instead.
