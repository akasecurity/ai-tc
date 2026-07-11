---
description: Show AKA detection activity and local security posture
---

# AKA health

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is space-aligned monospace (gauges, bars, a 7-day chart)
that Markdown would otherwise collapse. Do not reformat or summarize the table;
you may add at most one short sentence of context after it.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" health
```

This reads the local store at `~/.aka/data/aka.db` (detection activity, action
breakdown, category coverage, last 7 days). It is read-only. If the store is
empty, the script says so — relay that as-is; nothing is wrong.
