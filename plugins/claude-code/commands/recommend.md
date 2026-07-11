---
description: Surface AKA's top recommendations from recent findings
---

# AKA recommend

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: the output is space-aligned monospace whose lines start
with characters like `1.` and `●`; shown unfenced, Markdown collapses the
indentation and turns those into auto-numbered lists and bullets. You may expand
on the suggested next steps if the user asks, but lead with the output as-is.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" recommend
```

This groups recent findings by category (ranked by severity, then frequency) and
prints a plain-language next step for each. It is read-only over
`~/.aka/data/aka.db`.
