## Dependency advisories

CI gates every PR (and a daily run) on two audits via `tools/audit-gate`: `pnpm audit`
over `pnpm-lock.yaml`, and `npm audit` over an end-user resolution of the published
CLI's runtime `dependencies` (`--artifact` mode — coverage the workspace lockfile
cannot provide, since consumers re-resolve the published ranges and `pnpm.overrides`
do not reach them). A **high or critical** advisory in either fails the check, so a
new or bumped dependency that carries one will not merge. Fix a workspace hit by
upgrading, or by raising a floor in the root `pnpm.overrides` (the existing entries
there are exactly such floors); fix an artifact hit by raising the range in
`cli/package.json` — or, when the vulnerable copy is pinned by another package (e.g.
next's own pins), by bumping that package once upstream moves. Only when an advisory
has no fixed release reachable from the tree, add an **expiring** waiver to
`.github/audit-waivers.json`, scoped to the audit it applies to — format and process
in CONTRIBUTING.md ("Dependency advisories and waivers").
`auditConfig.ignoreCves`/`ignoreGhsas` is not an approved suppression route, and the
gate refuses to run (exit 3) when it is set. **It is detected by reading the two files
pnpm takes the setting from — the root `package.json`'s `pnpm.auditConfig` and
`pnpm-workspace.yaml`'s top-level `auditConfig` — not by inspecting what pnpm returns.**
The payload cannot reveal it: pnpm removes a muted advisory from `advisories`, decrements
the `metadata` severity counts to match, and leaves the top-level `muted` array **empty**,
so a muted run is byte-for-byte the shape of a clean one. A guard reading `muted` is
therefore correct in isolation and unreachable in practice — which is what it was, while
both audits reported green. `assertNothingMuted` is kept as the payload-side half in case
a later pnpm does populate the field; `assertNoAuditConfigMutes` is the half that fires.

Both channels are real and were measured; `.npmrc` is not one, in either the flattened or
the camelCase spelling. `findAuditConfigMutes` refuses on the **presence** of the
`auditConfig` key — in **both** channels alike, and whether or not the ignore lists under
it carry entries. So an empty one is refused too, and a third key added by a later pnpm is
caught without a code change, because the key names are never enumerated. The two halves
have to answer alike here or the rule stops being statable: the YAML half cannot tell an
empty `auditConfig` from a populated one without a parser. A file that **exists but cannot
be read** is refused rather than read as "no config here" — absence means `ENOENT` and
nothing else, since a failed read that returned "nothing to see" would reach the exact
outcome this check exists to prevent. Its tests pin the discriminating case directly: a
payload reporting nothing muted **and** a manifest configuring `auditConfig` must still be
refused — delete the file read and that case, alone, goes red.

## Package dependency rules

The store-reading packages read the local SQLite store directly through
`@akasecurity/persistence`; they never reach for an HTTP client or an ORM at the app layer.
Keep these package boundaries intact — a forbidden import across a package wall is a defect.

```
@akasecurity/schema        → zod (core Zod contracts + the SQLite local-store & rule-registry schemas,
                     defined with Drizzle; also the endpoint safety rule every
                     forwarder and client shares — isSafeEndpoint /
                     unsafeEndpointReason / originOnly / LOOPBACK_HOSTS — the
                     ControlPlaneFailure type, and the raise-only enforcement
                     clamp and its category anchor — mergeRaiseOnly +
                     ruleCategoryMap)
@akasecurity/persistence   → node:sqlite, @akasecurity/schema
                     (SQLite adapter + read/view ports, plus the shared ~/.aka
                     layout/settings/fingerprint file I/O, plus the egress wire
                     projection — toEgressIngestRequest / hashProjectKey, the one
                     place an EgressIngestRequest is built, pure and beside the cap
                     helpers it applies — NO fetch client, NO Drizzle)
@akasecurity/local-ops     → @akasecurity/schema, @akasecurity/persistence, @akasecurity/detections,
                     @akasecurity/plugin-sdk (repo-identity, project-file walkers, posix
                     path normalization, and the ReDoS gates the dashboard's folder
                     scan reuses — filterUnsafeRules + createGuardedScanner, see
                     src/guarded-scan.ts and Architecture principles §5)
                     (shared CLI/web-ui operations: update report + apply via npm/claude
                     child processes, the agent-plugin registry, the fs scan pipeline,
                     the project-inventory pass, and the shares-forward outcome state
                     machine — forwardProjectEgress is what a scan surface calls to
                     forward the register it just recorded (attached? opted out?
                     switch on? credential? and, on a scoped attachment, is the project
                     enrolled along with every repository nested in it? then send),
                     with the transport injected by the caller, plus the one copy of
                     the failure sentences both surfaces render; network ONLY via
                     package-manager shell-outs — no fetch)
@akasecurity/detections    → @akasecurity/schema (pure rule engine; no I/O, no Node-API deps)
@akasecurity/extract       → (no dependencies; pure CSV/tabular parsing — `extractCsv`.
                     Consumed by @akasecurity/detections' tabular suite as a
                     dev-only dependency, so it crosses no runtime package wall)
@akasecurity/dashboard-ui  → @akasecurity/ui-kit, @akasecurity/schema (types, plus the pure
                     shared constants and formatters — no I/O)
                     (bundler-agnostic presentational views; props-driven, no data fetching)
@akasecurity/ui-kit        → @radix-ui/react-*, Tailwind (design-token UI primitives)

web-ui            → @akasecurity/persistence, @akasecurity/dashboard-ui, @akasecurity/ui-kit,
                     @akasecurity/schema, @akasecurity/detections, @akasecurity/local-ops,
                     remote (the attach verb, and the Scan page's forward of the Data
                     Shares register while attached) (Next.js dashboard; reads the local
                     store in Server Components, mutates via Server Actions — no auth.
                     The THREE network calls are the settings page verifying an access key
                     against the deployment before it writes an attachment, the Scan page
                     forwarding the register it just recorded, and the Scan page sending
                     the credential sightings it found while they are shared; everything
                     else on every page is the local store)
cli               → @akasecurity/schema, persistence, local-ops, detections,
                     plugin-runtime + remote (the attach verbs, and `aka scan`'s forward
                     of the Data Shares register and of its credential sightings while
                     attached) (the `aka` command;
                     ships the web-ui as a spawned Next server)

# Plugin
plugins/claude-code → @akasecurity/plugin-runtime, plugin-sdk
plugins/codex        → @akasecurity/plugin-runtime, plugin-sdk
plugins/antigravity  → @akasecurity/plugin-runtime, plugin-sdk
plugins/copilot      → @akasecurity/plugin-runtime, plugin-sdk (GitHub Copilot: the
                     Copilot CLI and VS Code agent mode, and the cloud coding
                     agent, which speaks the CLI's protocol. ONE package, TWO
                     payload dialects — the CLI's flat camelCase envelope and VS
                     Code's flat snake_case one — sniffed per payload in
                     src/hooks/dialect.ts and carried as a parameter from there
                     down, so the two scannable-field tables are never merged)
plugins/browser-extension → @akasecurity/plugin-runtime, plugin-sdk (the native-messaging
                     host only — Node side); the browser-side content script bundles just
                     `@akasecurity/plugin-sdk/browser` (mask.ts's Node-API-free slice) and
                     must never import anything Node-only. The MAIN-world tap
                     (`src/tap.ts`) runs with the page's own authority and REASSIGNS the
                     page's `fetch` and `XMLHttpRequest.prototype.open`/`send` to observe
                     chat traffic. It originates no network request and imports nothing,
                     and it passes §4's network ban with no opt-out because it reaches
                     those globals through its `win` parameter and a structural type — so
                     an audit of what touches `fetch` has to include it by name.
                     `test/tap-bundle.test.ts` holds the built bundle to that shape.
@akasecurity/plugin-runtime → @akasecurity/plugin-sdk, persistence, schema, remote
                     (the attached-mode gateway under src/attached/ — inert on a
                     machine that has not attached, which is why `remote` is a
                     runtime edge here and still costs a standalone machine
                     nothing: the client is constructed only once both halves of
                     an attachment are present and agree.
                     the wire projection lives in persistence and the gateway imports
                     it from there; the attached barrel re-exports it for consumers
                     that import it from this package)
@akasecurity/remote         → @akasecurity/schema, zod
                     (the control-plane transport, and the ONLY package in this
                     workspace permitted to open a socket — see §4. `src/http.ts`
                     is the one module inside it that sends; everything else
                     builds requests and parses answers.
                     TWO clients, split by whether the caller holds a credential.
                     `createRemoteClient` speaks the fourteen routes an ATTACHED
                     machine is scoped to and requires a key. `createAttachClient`
                     speaks the two anonymous routes a machine uses to OBTAIN one
                     and holds none — a separate factory rather than an optional
                     key, so a caller cannot reach any other route without a
                     credential, since that client cannot express one.
                     It also owns the READING of its own failures: classifyRemoteFailure
                     maps one of its error classes onto a RemoteFailureKind, so no
                     caller re-derives a verdict from a status code — and
                     createSharesSender is the one forwarding adapter for a scan's
                     Data Shares register, so every surface sends and reads
                     failures identically. The exact
                     export set is pinned by test/public-surface.test.ts)
@akasecurity/plugin-sdk     → @akasecurity/detections, persistence, schema
                     (provider resolution for the session-root snapshot reads the host env
                     directly at SessionStart — `provider.ts` for Claude Code,
                     `provider-codex.ts` for Codex CLI, `provider-antigravity.ts`
                     for Antigravity, each its own file-scoped
                     `n/no-process-env` opt-out), ignore (gitignore semantics for
                     the SessionStart project-file walk), node:worker_threads
                     (the isolated scan — see Architecture principles §5)
                     `src/scan-worker.ts` is the worker's own entry, exported as the
                     `./scan-worker` subpath and reachable only from `@akasecurity/detections`
                     + `./isolated-scan-protocol.ts`. It must stay that narrow: Node loads it
                     directly (bundled `.js` when installed, type-stripped `.ts` in the repo),
                     so `src/bundled-packs.generated.ts` — a JSON import per rule, without import
                     attributes — would break it at load, and it never needs them anyway
                     because the ruleset arrives over `workerData`.
                     `src/bare-command.ts` is the shared bare-name spawn planner
                     (Architecture principles §7), exported as the `./bare-command`
                     subpath rather than off the index so the plugins' dashboard
                     launcher can reach it without inlining the bundled packs. It
                     imports node:child_process/os/path and nothing else.
@akasecurity/scanner        → @akasecurity/plugin-runtime, plugin-sdk, ignore (node:fs only; no fetch, no process.env;
                     the credential sightings it finds leave through plugin-runtime)
@akasecurity/setup-wizard   → @akasecurity/plugin-sdk, schema, zod
                     (the harness-agnostic core of the /aka:setup calibration →
                     triage → remediation flow: pure logic plus dependency-injected
                     orchestration. It must NEVER name a host command, hardcode a
                     transcript location, or spawn a judge — each plugin supplies
                     those at its own I/O boundary, which is what lets multiple
                     harness plugins share this without forking it.)
```

All four CLI plugin packages bundle the SAME `plugin-runtime`/`plugin-sdk` core and differ
only in their own thin hook-entrypoint layer (stdin/stdout glue matched to each host's hook
contract) plus the harness-specific bits `plugin-sdk` deliberately keeps file-scoped (provider
resolution, tool-name → scannable-field tables).

**The hosts' hook contracts are NOT equivalent, and the differences are behavioral, not
cosmetic.** Each plugin's `skills/setup/SKILL.md` carries a "Known limitations" section that
is the authority on what its host can actually enforce; keep it accurate when the adapter
changes. The gaps that exist today:

- **Codex** fires its tool hooks per tool call, including each call a code-mode `exec`
  script makes (`exec_command` arrives as `Bash`, the web tool as `webrun`, MCP tools as
  `mcp__<server>__<tool>`); the script itself fires no hook. The plugin's PreToolUse
  matcher is `Bash|apply_patch`, so inputs are scanned for shell commands and file
  writes only. PostToolUse adds `webrun` and `mcp__*`, so web and MCP traffic is
  scanned on the way out only. PostToolUse cannot rewrite output, so a redact there
  withholds the whole result.
- **Antigravity** is the most constrained and the most different. It has only five events —
  no `SessionStart` and no `UserPromptSubmit` — so the once-per-session inventory pass hangs
  off the first `PreInvocation`. That event carries **no prompt text**, so prompts can be
  neither blocked nor redacted. `PreToolUse` has **no `updatedInput` equivalent**, so a
  `redact` policy cannot be carried out on any field — not just the executable ones the
  other two decline — and what happens instead is `WorkspaceSettings.redactFallback`,
  resolved inside `actionForFinding` rather than by the hook. That location is what keeps
  the emitted decision, `findings.actionTaken` and the ledger reading one answer; a hook
  that escalated for itself recorded a deny as `redact`. The fallback ships as `warn`, so
  a redact on this host lets the call through by default, and a `warn` has no channel to
  print on — which makes it indistinguishable from `monitor` on screen here.
  `PostToolUse` receives **no tool
  result at all**, so there is no live response scanning and no `tool-response.ts` /
  `scan-response.ts` counterpart in that package.
- **GitHub Copilot is TWO hosts behind one package, and what fails closed is the EXIT CODE.**
  On the **Copilot CLI** (and the cloud coding agent, which speaks its protocol) `preToolUse`
  is the one fail-closed event, and the hooks reference is specific about the channel: a
  hook that exits non-zero other than 2 **denies the tool call**, exit 2 denies and merges
  any stdout JSON into that deny, a timed-out one allows, and every other event fails open.
  **Empty stdout is in none of those lists.** That same reference's `preToolUse` decision
  table reads "Empty output uses default behavior", which hands the call to the host's own
  permission flow — so silence here is §1's fail-open unchanged, and the adapter writes
  **nothing on every path that reaches no verdict**. It is NOT unmeasured; the earlier
  reading that it might be is retracted, and `plugins/copilot/test/fixtures/cli/README.md`
  records under "Settled by the vendor reference" which questions the docs answer and which a
  recording still owes.
  **An explicit allow is a verdict, not a way of saying nothing**, so emitting one per clean
  call would pre-approve exactly the calls the user's own Copilot settings would have
  prompted about — a control plane widening the permissions it was installed to narrow.
  `CliPermissionDecisionOutput` therefore carries `'deny'` alone, which makes a CLI allow a
  **compile error**; VS Code's shape keeps `'allow'` because that host carries `updatedInput`
  only alongside one. What the adapter guarantees instead is that no path exits non-zero and
  none exits 2. On **VS Code agent mode** exit 2 blocks and everything else — any other
  non-zero exit, invalid JSON, a timeout — is a non-blocking warning, so that host fails
  open; it also **parses matchers and ignores them**, so the hook is spawned for every tool
  call and the unknown-tool exit is the common path rather than the rare one.
  **The two dialects are payload FORMATS, not hosts**, and the CLI speaks both: the reference
  selects the format by the event name's casing, so a manifest registering `preToolUse` and
  `PreToolUse` together spawns the hook twice per call — the second time with a payload whose
  `tool_name` is the Claude spelling (`Bash`, not `bash`) that the snake_case table has no row
  for. `plugins/copilot/hooks.json` therefore registers **camelCase events alone** — the four
  it carries are `sessionStart`, `userPromptSubmitted`, `preToolUse` and `postToolUse`, each
  once. VS Code loads that same camelCase `hooks.json` through its plugin location
  (`chat.pluginLocations`) and dispatches the four events in its own PascalCase/snake_case
  dialect, which the recording in `plugins/copilot/test/fixtures/vscode/plugin-load-1.141/`
  shows running all four hooks. Of those four only
  `preToolUse` ENFORCES. `userPromptSubmitted` and `postToolUse` capture, scan and record,
  and pass `rewritable: false` because neither host has a prompt-stop or result-withhold
  channel this repository has observed, so a `redact` resolves to `redactFallback` inside
  the runtime rather than the hook claiming an enforcement the host would ignore.
  `sessionStart` scans nothing: it opens the session root every later capture hangs off.
  `userPromptTransformed` is handled by the prompt entry and deliberately NOT registered: its
  payload re-carries `prompt` verbatim, so registering it beside `userPromptSubmitted` records
  every prompt twice.
  The VS Code half is built to the published contract and **partly confirmed against a live
  install**: one agent-mode session on VS Code 1.141.0 recorded the session start, prompt,
  tool-call and tool-result captures and a warn, in `test/fixtures/vscode/plugin-load-1.141/`.
  Only the session start, prompt and tool-result rows are verified. The block and rewrite rows
  that the tool-call capture feeds stay unverified, because a deny, an `updatedInput` rewrite, a
  large-input refusal and a flagged tool result were never driven. The warn's `systemMessage`
  reached only the hooks output channel, never the chat. The doc-derived
  fixtures sit in a separate `test/fixtures/vscode-provisional/` directory, and
  `plugins/copilot/test/fixture-provenance.test.ts` is what keeps a doc-derived specimen from
  being filed among the recordings.
- **Antigravity also fails CLOSED**, which inverts this repo's §1 rule at the boundary: a
  hook that exits non-zero, is killed on timeout, or prints nothing is read as a `deny` on
  every tool call. "Fail-open" there therefore means _always printing an explicit_
  `{"decision":"allow"}`, which is what `runHookFailOpen` in
  `plugins/antigravity/src/hooks/shared.ts` guarantees — including on a throw and on its own
  watchdog. A silent exit is a bug that would block the user's every tool call. The guarantee
  holds over everything that **yields** and cannot reach a body that blocks the thread; §1
  states that limit and names the two suites that cover each half.

**Cross-cutting rules:**

- No `process.env` reads except the sites that explicitly opt out of `n/no-process-env` — §3 tables them, and deliberately is not restated here: a second copy of that list is how the count drifted last time.
- No `fetch()` and no transport module anywhere except `@akasecurity/remote`, which reaches only the deployment a machine's own settings name and only once it has been attached on purpose (§4). Every store-reading package (`persistence`, `local-ops`, `dashboard-ui`, `ui-kit`, `detections`, `scanner`, `web-ui`, `cli`) reads the local store directly — none of them acquires DATA over a network. Two of them, `cli` and `web-ui`, do take `@akasecurity/remote`: both for the attach verb, and both for forwarding the Data Shares register a manual scan just recorded — `aka scan` and the dashboard's Scan page — on a machine that is already attached, and both for sending that scan's credential sightings while they are shared. For a pasted key that is one `whoami` round trip, which proves the key before an attachment is written. The browser-approval path adds two more, both **unauthenticated** because the caller has no credential yet and obtaining one is the point: a grant POST, then a poll of `POST /v1/attach/token` on an interval the deployment sets, until somebody decides or the grant lapses — and then the same `whoami`. None of it acquires store data, and all of it happens only while a human is attaching, which is why it does not add an egress path to §4.
- Drizzle is imported **only** by `@akasecurity/schema`, which uses it to _define_ the local-store and registry schemas. Packages that read the store do so via `node:sqlite` through `@akasecurity/persistence` — they must not import Drizzle.
- The graph above lists **runtime** edges. Test suites may additionally take `@akasecurity/plugin-sdk` as a **dev-only** dependency for fixture seeding — the bundled detection packs (`bundledDetections()` / `registerBundledPacks`) live only there, so a test that must seed `installed_packs` or the engine registry needs it. Both `cli` and `web-ui` do this in their exception tests. A dev-only test dependency is not a runtime package-wall crossing.
