# System Overview

AKA's open-source surface is **local-first**: a Claude Code plugin captures and scans
your AI activity, a pure detection engine decides what matches, and the results land in
a local SQLite store that the `aka` CLI and the web dashboard read directly. There is
no server, no Postgres, and no account — nothing leaves your machine.

## Repository layout

```
ai-tc/
├── cli/                      The `aka` CLI — bundles the web-ui for `aka dashboard`
├── web-ui/                   OSS Next.js dashboard (reads the local SQLite store)
├── plugins/
│   └── claude-code/          Claude Code plugin — hook scripts + /aka:* commands
├── packages/
│   ├── schema/               Zod contracts + local-store schema — single source of truth
│   ├── detections/           Pure detection engine (no I/O)
│   ├── persistence/          Local SQLite store adapter (node:sqlite) + ~/.aka file I/O
│   ├── plugin-sdk/           Plugin adapter interface + shared plugin runtime
│   ├── plugin-runtime/       Standalone data gateway wiring the SDK to the local store
│   ├── scanner/              Working-tree / multi-repo file-scan pipeline
│   ├── local-ops/            Shared CLI/web-ui operations (updates, plugin registry, fs scan)
│   ├── extract/              Text extraction helpers (CSV, …)
│   ├── dashboard-ui/         Presentational React views shared by the dashboard
│   ├── ui-kit/               Shared React primitives (shadcn/Radix)
│   └── eslint-config/        Shared lint configuration
├── rules/                    Built-in detection packs (fixtures required for every rule)
│   ├── core-pii/ · core-phi/ · core-financial/ · core-code-context/
│   ├── secrets/ · secrets-infra/
│   └── code-flaws/
├── docs/                     This MkDocs site
└── tools/                    CLI installer (install.sh / install.ps1 / install.mjs)
```

## Package dependency rules

AKA enforces strict import boundaries via the pnpm workspace graph + `tsc` (a forbidden
import does not resolve / fails typecheck) and a dedicated CI gate
(`pnpm check:boundaries`). Violating them is a CI failure.

```
plugins/claude-code           →  @akasecurity/plugin-sdk, @akasecurity/plugin-runtime, @akasecurity/scanner
cli                           →  @akasecurity/persistence, @akasecurity/local-ops, @akasecurity/detections,
                                 @akasecurity/plugin-sdk, @akasecurity/dashboard-ui, @akasecurity/schema
web-ui                        →  @akasecurity/persistence, @akasecurity/dashboard-ui, @akasecurity/schema,
                                 @akasecurity/detections, @akasecurity/local-ops
@akasecurity/scanner          →  @akasecurity/plugin-runtime, @akasecurity/plugin-sdk (node:fs only)
@akasecurity/plugin-runtime   →  @akasecurity/plugin-sdk, @akasecurity/persistence, @akasecurity/schema
@akasecurity/plugin-sdk       →  @akasecurity/detections, @akasecurity/persistence, @akasecurity/schema
@akasecurity/local-ops        →  @akasecurity/schema, @akasecurity/persistence, @akasecurity/detections
@akasecurity/persistence      →  node:sqlite, @akasecurity/schema (no fetch, no Drizzle)
@akasecurity/detections       →  @akasecurity/schema (no I/O, no Node-API deps)
@akasecurity/dashboard-ui     →  @akasecurity/ui-kit, @akasecurity/schema (types) — props-driven, no data fetching
```

Three cross-cutting rules every contributor must remember:

1. **No `process.env` reads by default** — enforced by `n/no-process-env: 'error'`; the
   few spots that need the host environment (the plugin's provider resolution, the CLI
   spawning the dashboard) opt out explicitly.
2. **No `fetch()` in the open-source surface** — AKA is local-only. The CLI, web-ui,
   persistence, and detection engine reach only the local store and package-manager
   shell-outs; nothing calls an AKA service.
3. **`packages/schema` is the single source of truth** — consumers import its Zod types
   rather than defining local view-model shapes.

## Local-first plugin

The plugin is fully useful with **no server and no Docker**. Every hook invocation
is a fresh, short-lived process: Claude Code pipes a JSON event to a hook script's
stdin and reads a JSON decision from stdout. The hook path is entirely local — rule
packs are bundled into the scripts at build time, detection runs in-process via
`@akasecurity/detections`, and events + findings are written to the local SQLite store via
`@akasecurity/persistence`.

```
 Claude Code ──hooks──▶ AKA plugin (adapter) ──▶ @akasecurity/plugin-sdk
                                                      │ writes
                                                      ▼
        ~/.aka/data/aka.db   (events · findings · policies · audit)
                ▲                          ▲
     aka CLI reads it directly    OSS web-ui reads it directly
   (@akasecurity/persistence)       (@akasecurity/persistence, Server Components)
```

Detection runs in-process, and results surface through slash commands
(`/aka:health`, `/aka:findings`, `/aka:recommend`, `/aka:audit`), the `aka` CLI, and the
web dashboard. The shared data shapes live in `@akasecurity/schema` / `@akasecurity/persistence`,
so a new plugin (Claude Code first, others later) adds only a thin tool-specific adapter,
never a copy of the storage/detection logic.

## Data flow

### Event capture (plugin → local store)

```
┌────────────────────────────────────────────┐
│  Claude Code session                        │
│                                             │
│  1. User types prompt                       │
│  2. UserPromptSubmit hook fires             │
│     → user-prompt-submit.js reads stdin     │
│     → createPluginRuntime().processText()   │
│        → scan() against bundled rules       │
│        → resolve per-detection policy       │
│        → block / warn (prompts can't be     │
│          rewritten in place)                │
│     → writes {decision} to stdout           │
│  3. event + any findings appended to        │
│     ~/.aka/data/aka.db                       │
└────────────────────────────────────────────┘
```

`PreToolUse` and `PostToolUse` hooks additionally redact tool inputs (`updatedInput`)
and outputs (`updatedToolOutput`) where the host allows. See the
[Claude Code plugin](../plugin/claude-code.md) page for the full hook contract and its
honest capability limits.

### The web dashboard (web-ui)

The OSS **web-ui** (`web-ui`, Next.js) reads the local SQLite store directly
through `@akasecurity/persistence` in Server Components — no HTTP client, no auth. It renders
the shared presentational `*View` components from `@akasecurity/dashboard-ui` (which depend
only on `@akasecurity/ui-kit` + `@akasecurity/schema` types and do no data fetching), and it
mutates the store through Next.js Server Actions:

- **Detections** — list/detail/stats over `installed_packs`; changing a detection's
  enforcement policy (or toggling it) is a Server Action.
- **Policies** — the built-in policy catalog (monitor / warn / redact / block) with live
  "used by N detections" counts, plus the read-only local enforcement config.
- **Data Shares** — the local egress register; the Block/Allow decision persists via a
  Server Action.
- **Inventory** — the asset model (harnesses / assets / projects / files); per-file
  LLM-access and MCP-trust edits are Server Actions.
- **Activity** — harness sessions reconstructed from the `audit_events` timeline, with
  **token reporting** folded in (per-provider/model token counts, with cost derived at
  read time from the pure `defaultCostModel` in `@akasecurity/schema`; token counts are stored
  truth, cost is never persisted).

The web-ui ships **no sample data** — pages render only what the plugin and CLI actually
wrote (`purgeSampleData()` runs once at bootstrap to drop any retired demo rows an older
build may have left behind).

## Local store schema

The local store schema is defined with Drizzle in `@akasecurity/schema`
(`src/drizzle/local/sqlite.ts`) and read/written through `@akasecurity/persistence`. It is
single-node and single-user — there is no tenancy and no row-level security.

| Table                    | Purpose                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `events`                 | Each captured prompt / response / code_change                                        |
| `findings`               | Each rule match on an event                                                          |
| `policies`               | Per-detection action config (monitor / warn / redact / block)                        |
| `installed_packs`        | Installed detection packs — version, enabled state, assigned policy                  |
| `inventory`              | Existence/dimension rows (`host`, `harness`, `user`), content-addressed and deduped  |
| `source_project`         | The repository/project a session ran against, content-addressed by remote url        |
| `audit_events`           | Timeline/fact rows forming a self-referential tree (`session → run → tool_call → …`) |
| `classified_data`        | Small class dimension of recognized sensitive-data kinds (`aws_key`, `email_pii`, …) |
| `inspection_definitions` | A detection rule version (id encodes the version, so a finding cites the exact rule) |
| `inspection_findings`    | A hit of a definition against an audit event                                         |

Inventory/source rows carry content-addressed ids (`sha256(…)`, computed in
`@akasecurity/persistence`) so repeat sessions upsert idempotently. Hot filter keys
(`os_version`, `harness_version`) are SQLite generated columns over the JSON `attributes`
bag, indexed for facets.

### Timestamp representation

SQLite cannot store `TIMESTAMP WITH TIME ZONE` natively, so timestamps are stored as
epoch-millis integers and converted at the persistence boundary:

| Layer              | Representation                     |
| ------------------ | ---------------------------------- |
| SQLite column      | `integer` (epoch-millis)           |
| Zod (API boundary) | `z.string().datetime()` (ISO-8601) |

`packages/schema/src/time.ts` exports two pure helpers with no Drizzle import:
`isoToEpochMillis(iso)` on the write path and `epochMillisToIso(ms)` on the read path.
The raw integer never escapes the persistence layer — everything above it sees ISO-8601
strings.

## Detection engine

Detection is a pure function of `(text, rules)` with no I/O, living in
`@akasecurity/detections`. It is bundled into the plugin scripts, imported by the CLI, and
imported by the web-ui, so every surface scans identically. See the
[Detection Engine](detection-engine.md) page for the scan/redact internals and
[Writing Rules](../rules/writing-rules.md) for the rule format.
