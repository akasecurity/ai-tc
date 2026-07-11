---
description: List installed AKA detection packs, versions, and available updates
---

# AKA detections

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is a space-aligned monospace table that Markdown would
otherwise collapse. Do not reformat the columns or restate each row.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" detections
```

This lists the detection packs installed in `~/.aka/data/aka.db` — one row per
pack with its installed version, the latest version this plugin ships, rule
count, enabled state, assigned enforcement policy, and whether an update is
available. These packs are what the plugin actually scans with.

Detection updates are **never applied automatically** — a plugin upgrade only
records what's newly available; the installed packs keep running unchanged
until the user updates them. This command is strictly **read-only**: do not
apply, enable, disable, or re-policy a detection from here. If the user wants
to update, tell them to run one of these themselves in a terminal:

- `aka detections update --all` — update every pack
- `aka detections update <pack-id>` — update one pack
- `aka dashboard` → Detections → **Update** — review and apply in the dashboard
