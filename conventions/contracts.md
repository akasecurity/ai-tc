### 2. Contracts before code

`@akasecurity/schema` is the spine. The Zod schemas in `src/zod/` define every data boundary. Add shapes there before implementing them anywhere else.

**Do not create new types and interfaces — use the ones exported from `@akasecurity/schema` to the maximum extent.** Consumers (web-ui, CLI, plugin) import the schema types directly rather than redefining local "view-model" shapes or adapters. A new type is justified only when there is genuinely no schema equivalent (e.g. pure presentation descriptors like `{ label, icon, color }`). If a shape is missing, add it to `@akasecurity/schema/src/zod/` first, then consume it.

**The agent vocabulary is ONE registry, and outside it an id is spelled through a
member rather than as a literal.** Unlike §3 and §4, this is a CONVENTION and not a
gate: no lint rule and no derived audit enforces it, so read it as what review looks
for rather than as something CI will catch. Two neighbouring id spaces are
deliberately outside it and are not violations — `AGENT_PLUGINS[].id` in
`packages/local-ops/src/registry.ts` (the ref `aka plugins install` takes, which
carries its own `sourceTool` field alongside) and the browser extension's
content-script provider ids, which name a web app rather than a capture and whose
files import nothing from schema on purpose. That is a statement about how an
`AGENT_PLUGINS` id is SPELLED, and only that: the entries' install coordinates ARE
gated, by `packages/eslint-config/test/release-identity.test.js` — `pluginName`,
`marketplace` and `cliBin` are all present or all absent, `installHint` is present
exactly when they are absent (the state of both hint-only entries, Antigravity and
Copilot: neither host has a marketplace this plugin installs from, and each installs
from a local directory), every `npmPackage` names a tracked non-private workspace
package, the entries' `npmPackage` set equals the set of tracked non-private
`plugins/*` packages, so every published plugin appears in `aka plugins list` and
`aka plugins install` — though only an entry with a `pluginRef` also reaches the
update notice, `aka check-updates` and the dashboard's Updates page, since
`gatherReport` skips one without — and an entry whose marketplace is this repository agrees with
`.claude-plugin/marketplace.json`.
`src/zod/harness-map.ts` holds both spellings as named-member const objects —
`SOURCE_TOOL` (the wire id a plugin stamps on a capture, `'claude-code'`) and `HARNESS` (the
display id the dashboard renders, `'claudecode'`). Four rules keep them from re-multiplying,
which they had done into five hand-typed copies:

- **A narrower enum is `Harness.extract([...])` over MEMBER NAMES**, never a fresh
  `z.enum([...])` of the same strings. `Provider`, `HarnessId` and `FindingProvider` are each
  that, so a subset structurally cannot carry an id the registry does not define, while each
  keeps its own member ORDER (`Provider`'s is the dashboard's display order, and
  `.extract()` preserves the order passed).
- **Call sites spell `HARNESS.ClaudeCode` / `SOURCE_TOOL.ClaudeCode`, not the literal.** A
  literal that merely equals a member is invisible to a rename, which is exactly how these
  drifted. Keyed tables use computed member keys (`[HARNESS.ClaudeCode]: …`), which keeps
  `satisfies Record<Harness, …>` exhaustiveness — so **a table over a vocabulary is
  ANNOTATED `Record<ThatVocabulary, …>`**, and that one rule needs no per-table test. It
  covers the `.extract()` subsets exactly as it covers the whole enum: a table annotated
  `Record<HarnessId, …>` fails to compile the moment `HarnessId`'s extract list grows
  (TS2741 — verified, not assumed). What the compile error cannot reach is a collection
  keyed on NOTHING — an array of rows carrying its id in a field — because adding a member
  changes no type it mentions. Give it a key, or it owes a TEST.
- **Adding an id is one edit to the registry PLUS a deliberate decision per subset.**
  `.extract()` takes explicit member names, so a member added to `HARNESS` joins no subset
  on its own: it is a compile error at every table keyed on the whole enum (which is what
  prompts the lettermark and the kind), and silently absent from `Provider`, `HarnessId`
  and `FindingProvider` until each is extended on purpose. Until then it renders under no
  scan-coverage row, gets no label, and buckets to the miss path. That is the intended
  shape — subsets answer different questions and none should widen by accident — but do
  not read the compile error as telling you the work is finished.
- **The two vocabularies are joined by MEMBER NAME**, so `TOOL_TO_HARNESS` pairs them without
  either spelling being retyped, and a member in only one of them is meaningful rather than an
  omission (`Cli`/`Unknown` capture under no harness; `Windsurf`/`Api` render under no
  capture). Anything that reads the join BACKWARDS derives it — `toDbProviderFilter` is the
  inverse of that one table rather than a second map, because the hand-written copy it
  replaced had to be edited in step with it and nothing checked that it was. Deriving it
  gives up the exhaustiveness that `Record<FindingProvider, string[]>` carried, and no
  compile error replaces it, so the agreement is asserted as SETS in
  `packages/schema/test/zod/harness-map.test.ts` — every provider but the miss bucket must
  name at least one stored value. That case is the only non-vacuous one: the round-trip
  iterates the table itself, and the forward check's inner loop does not run on an empty
  array. It has to be non-vacuous because an empty result is the miss bucket's own contract
  (`'api'` → `[]`, matching any unknown value in-memory), so a provider with no rows reads
  as the miss bucket rather than as no findings.

Declared as const objects rather than TypeScript `enum`s deliberately:
`packages/plugin-sdk/src/scan-worker.ts` is loaded by raw Node under type **stripping** and
reaches schema through `@akasecurity/detections`, so an `enum` — which emits runtime code
rather than erasing — fails at load on that path only. The repo has no `enum` declarations,
and adding one anywhere schema can reach is what would break it.
