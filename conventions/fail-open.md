### 1. Fail-open everywhere in the plugin

The plugin **must never break a user's Claude session**. Every hook entry wraps `main()` in
try/catch and then calls `process.exit(0)`, so a hook that fails writes **nothing to stdout and
exits 0** — which the hook protocol reads as "no opinion", i.e. allow. Failing open is the
_absence_ of output, not a payload.

**No hook emits `{ action: 'allow' }`, and none should start.** `action` is a `CaptureResult`
field that never crosses the wire; the internal fallback `handleCapture` returns when the runtime
throws is `{ action: 'log' }`, and `'allow'` is only ever assigned to an **excepted** finding.
Emitting a real opinion means writing one JSON object to stdout via `emit()`
(`plugins/claude-code/src/hooks/shared.ts`), which takes the `HookOutput` union rather than
`unknown`, so a payload outside that union cannot reach the wire at all. Its seven shapes are
`decision` and `systemMessage` at the top level, plus one `hookSpecificOutput` per hook —
`PreToolUse`'s `permissionDecision`, `PreModelSwitch`'s `permissionDecision`, `PostToolUse`'s
`updatedToolOutput`, `MessageDisplay`'s
`displayContent` and `SessionStart`'s `additionalContext`. The write is awaited, because
`process.exit` does not flush a pending pipe write and a truncated object reads as invalid JSON,
passing the original payload through unscanned.

That enumeration is derived rather than remembered, because this is the sentence that drifted last
time — it claimed four shapes while six were reaching stdout, and the two it omitted belong to the
two hooks nothing else in this file mentions. `plugins/claude-code/test/hook-output-shapes.test.ts`
reads it and drives it against the union: the count word, the two top-level keys, and each
`hookEventName` paired with the field that distinguishes it. A seventh variant added to
`HookOutput` fails to compile until that test's map names it, and fails that test until this
sentence does.

`plugins/claude-code/test/e2e/fail-open.e2e.test.ts` is what holds this rather than review: it
drives the built hooks against malformed, truncated, binary and oversized stdin, asserting exit 0
and empty stdout, and its `expectNoActionKey` fails any emitted payload carrying an `action` key.
That last check is worth **nothing** on the rows above it, which have already asserted the stdout
is empty — `''` matches no pattern. So the file also drives a real finding through each enforcing
hook at block, redact, warn and log, asserts the shape each cell is expected to emit (the positive
control, without which a hook that stopped emitting would turn every absence assertion back into
the vacuous form), and reads `expectNoActionKey` over the payload that produced. Keep both halves:
the fault rows prove silence, and only the enforcement rows can prove what the noise looks like.

Each command in the Claude Code plugin's `hooks/hooks.json` runs a launcher
(`src/hooks/launch.ts`) that enables Node's compile cache and then loads the hook from
`<name>.body.js`. That path sits before every catch the hook has: when the body cannot be
loaded, the launcher writes one fixed line to stderr (`aka: hook body failed to load;
scanning skipped`), nothing to stdout, and exits 0. `plugins/claude-code/test/e2e/hook-launcher.e2e.test.ts`
drives it.

**One path fails CLOSED on purpose: a field too large to scan in time.** Every capture path
that answers to a deadline builds its runtime with `largeInput`, so a field of
`LARGE_INPUT_THRESHOLD_CHARS` (32,768) or more is scanned in a worker under a hard deadline,
and every bounded scan in one hook process — or one native-host request — draws on one
deadline. Each sits inside whatever would otherwise answer for that path first:

- **Claude Code and Codex** (`plugins/{claude-code,codex}/src/hooks/large-input.ts`): 6 s
  from process start for UserPromptSubmit and PreToolUse, PostToolUse's existing 7 s
  field-loop deadline — inside the host's 10 s.
- **Antigravity PreToolUse** (`plugins/antigravity/src/hooks/large-input.ts`): 5.5 s from
  process start, inside `runHookFailOpen`'s 8 s WATCHDOG rather than the host's 10 s,
  because the watchdog resolves an undecided body with `{"decision":"allow"}` — a refusal
  still being decided when it fires is printed as an allow.
- **Copilot preToolUse** (`plugins/copilot/src/hooks/large-input.ts`): 15 s from process
  start, inside its 24 s watchdog, which resolves with silence — the no-opinion on both
  dialects.
- **Copilot userPromptSubmitted and postToolUse** (the same `largeInputBound` and the same
  15 s deadline, inside the same 24 s watchdog): bounded, with **no refusal half**. Neither
  event has a prompt-stop or result-withhold channel this package has confirmed, so a field
  that comes back `scanIncomplete` is reported on the notice channel as too large to scan
  (`unscannedTooLargeMessage` in `plugins/copilot/src/exception-guidance.ts`) — never
  refused, never treated as clean, and counted in the hook fail-open tally.
- **The browser extension's native host** (`captureLargeInput` in
  `plugins/browser-extension/src/native-host/host.ts`): 2 s from when it receives a prompt
  capture, with a 500 ms worker start budget drawn from it, because `background.ts`
  answers a relay the host has not answered within `RELAY_TIMEOUT_MS` (3 s) with an error,
  and the content script lets the original message through on an error.

A field whose bounded scan times out or finds no worker comes back as a `block` with
`CaptureResult.scanIncomplete` set and empty `findings`, and the caller REFUSES it wherever
its host has a channel to refuse on: UserPromptSubmit blocks the prompt, PreToolUse denies
the call — Antigravity with an explicit `{"decision":"deny"}`, Copilot in each dialect's own
deny shape — PostToolUse withholds the output, and the native host answers `action: 'block'`
with `CaptureResponse.scanIncomplete`, which the interceptor shows as a too-large banner
with no exception route, leaving the message unsent in the composer. Copilot's
userPromptSubmitted and postToolUse are the exception named above: the host sends the prompt
and delivers the result whatever the hook answers, so they REPORT the field as unscanned
instead. Why: `scan()` cannot be interrupted (§5), so without the bound a large enough field
keeps the hook busy past whatever answers for it — the host's timeout, a watchdog, the relay
— and every one of those passes the call through unscanned, except Antigravity's kill, which
denies it with no reason. Failing open there IS the gap. The refusal is a RETURNED decision,
never a throw, so nothing else in this section changes: a throw, bad stdin, an unopenable
store and a PostToolUse field the loop deadline never reached all still pass (silently, or
with Antigravity's explicit allow), and a native host that does not answer at all still lets
the message through on the relay's timeout. Anything that skips clean fields, or keys a deny
on a flagged rule, must read `scanIncomplete` first, because a refused field and a clean one
both have no findings — Antigravity's and Copilot's decisions keyed their deny on a flagged
rule, and read a refused field as clean until they did. The Claude Code, Codex, Antigravity
and Copilot `fail-open.e2e.test.ts` drive the refusal through the built hooks with the scan
worker removed (Copilot's also drive the unscanned report on its two capture hooks), and the
extension's `test/native-host/scan-worker-bundle.e2e.test.ts` drives it through the built
native host — so every bundle that runs this path also has to SHIP the worker, since a
missing one refuses every large field (or, on those two Copilot hooks, reports every one as
unscanned).

**What "fall back to allow" means is the HOST's convention, not a fixed payload.** Claude Code
and Codex read "exited 0, said nothing" as "no opinion" — so a silent `catch` is genuinely
fail-open there. **Antigravity reads it as a `deny`**: a hook that exits non-zero, is killed on
its timeout, or prints nothing blocks the tool call outright. On that host, failing open means
_printing an explicit_ `{"decision":"allow"}` on every path — see
`runHookFailOpen` in `plugins/antigravity/src/hooks/shared.ts`. Before writing a fail-open path
for a new harness, check which convention it uses; assuming this one is what turns a crashing
hook into a wedged session.

**That guarantee reaches exactly as far as the event loop does, and the gap is not academic.**
`runHookFailOpen` races the body against a `setTimeout`, so it covers a throw, an undecided
body, and a body that outruns the watchdog — everything that _yields_. It cannot preempt a body
that blocks the thread, because nothing on the calling thread can. A block that clears inside
the host's own 10s still emits and exits 0 — the denial needs the block to outlast the HOST,
not merely the watchdog. Two blocking stretches sit on the capture path and compose:
`openLocalDatabase` is synchronous `node:sqlite` whose `PRAGMA busy_timeout = 2000` is charged
per contended **statement** rather than once per open (so the reachable total is a multiple of
2s), and §5's fast-path `scan()` is synchronous and in-process whenever the ruleset carries no
pulled or custom regex rule. `emit` sits outside the race as well, so a stalled pipe has no
deadline at all — and on that path the closing `process.exit(0)` is never reached either. This is §5's argument arriving at a second boundary — the fix for an unbounded stretch is
to move it off the thread, never to lengthen the timer — and the consequence here is harsher
than a missed scan: the condition that blocks (a contended store, a held lock) persists, so the
denial does too. Do not describe the explicit-allow as unconditional; it is unconditional over
what yields.

Both halves are covered, and by different suites because they fail differently.
`plugins/antigravity/test/hooks/fail-open-wrapper.test.ts` drives `runHookFailOpen` itself —
the throw, the undecided body, the watchdog win, a late rejection that must not surface as an
unhandled rejection (which would exit non-zero, i.e. deny, by a route the wrapper never writes
to), and the synchronous-block limit pinned as behaviour rather than prose. It also asserts one
JSON object, not merely a non-empty stdout: two concatenated objects do not parse, so a second
write is a deny exactly like silence.
`plugins/antigravity/test/e2e/fail-open.e2e.test.ts` is the Claude Code sibling's mirror image
and drives all four built hooks against empty, malformed, truncated, scalar, binary and
oversized stdin plus an unopenable store. Every assertion there is a **presence** check —
absence checks are the right shape on a fail-open host and the wrong one here, where `''` is
the failure being guarded against.
