# Fail-Open E2E Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, against the REAL built hook scripts, that all five Claude Code hooks (`session-start`, `user-prompt-submit`, `pre-tool-use`, `post-tool-use`, `stop`) fail open — exit 0, no crash — across a matrix of malformed/hostile stdin and unavailable-store conditions, and pin the real wire protocol (no hook ever emits an `action` key).

**Architecture:** One new test file, `plugins/claude-code/test/e2e/fail-open.e2e.test.ts`, table-driven over the five hooks. It reuses `runHook`/`withTempHome`/`tempHomeEnv` from `plugins/claude-code/test/helpers/run-hook.ts` (already implemented on branch `qa/5-e2e-hook-harness`, open as PR #63) to spawn the built `scripts/<name>.js` against a throwaway `HOME`. No production code changes; no CI workflow changes (the plugin's `vitest.config.ts` `globalSetup` already builds `scripts/*.js` before any test file runs, so build-before-e2e ordering is already satisfied).

**Tech Stack:** TypeScript, Vitest, Node `child_process` (via the existing `runHook` helper), `node:fs`/`node:path` for fixture setup.

## Global Constraints

- Base the new branch on `qa/5-e2e-hook-harness` (PR #63) — do not duplicate the spawn/HOME-override logic it already provides.
- No changes to `plugins/claude-code/test/helpers/run-hook.ts` — treat it as a fixed dependency; all new fixtures (corrupt store, read-only home, payload builders) live locally in the new test file.
- No `process.env` reads in the new file (none are needed — `runHook`/`tempHomeEnv` already handle host-env inheritance internally), so no ESLint `n/no-process-env` opt-out is required.
- Every fail-open assertion checks `status === 0`; the two store-availability cases additionally check the wire protocol never contains an `"action"` key. Never weaken an assertion to make a red test pass — a failing row here is a genuine fail-open bug in the hook, not a bad test.
- Windows is out of scope: CI's Windows job only runs library packages (`schema`, `extract`, `detections`, `persistence`, `plugin-sdk`, `plugin-runtime`, `scanner`, `local-ops`), never the plugin's own test suite, so `chmodSync`-based read-only simulation only needs to work on Linux/macOS.

---

### Task 1: Branch setup and baseline verification

**Files:** none created or modified — this task only verifies the starting state.

**Interfaces:**

- Consumes: nothing yet.
- Produces: a local branch `qa/6-fail-open-e2e` based on `qa/5-e2e-hook-harness`, confirmed to build and pass its existing tests.

- [ ] **Step 1: Fetch and create the branch**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git fetch origin
git checkout -b qa/6-fail-open-e2e origin/qa/5-e2e-hook-harness
```

Expected: branch created, tracking history includes commit `08f2e8e Add an E2E harness that spawns the built hook scripts`.

- [ ] **Step 2: Confirm the harness files exist**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
test -f plugins/claude-code/test/helpers/run-hook.ts && echo "run-hook.ts present"
test -f plugins/claude-code/test/helpers/run-hook.test.ts && echo "run-hook.test.ts present"
```

Expected: both lines print.

- [ ] **Step 3: Run the existing harness smoke tests to confirm a clean baseline**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code test -- test/helpers/run-hook.test.ts
```

Expected: `PASS`, 6 tests passing (1 "fails with a clear message" + 5 per-hook smoke tests). This also confirms `vitest.config.ts`'s `globalSetup` freshly built `scripts/*.js` before running.

- [ ] **Step 4: Create the e2e test directory**

```bash
mkdir -p /Users/tvburger/Spaces/AKA/Development/ai-tc/plugins/claude-code/test/e2e
```

No commit for this task — nothing has changed yet; Task 2 makes the first real commit.

---

### Task 2: Malformed/hostile-input fail-open matrix (25 cases)

**Files:**

- Create: `plugins/claude-code/test/e2e/fail-open.e2e.test.ts`

**Interfaces:**

- Consumes: `runHook(name: string, stdin: string, options?: RunHookOptions): HookResult` and `withTempHome<T>(fn: (home: string) => T): T` and `tempHomeEnv(home: string): Record<string,string>`, all from `../helpers/run-hook.ts`. `HookResult` shape: `{ status: number; stdout: string; stderr: string }`.
- Produces: the `HOOKS` array and `expectNoActionKey`/`expectFailsOpen` helpers, reused by Tasks 3 and 4 in the same file.

- [ ] **Step 1: Write the test file with the payload table and the malformed-input matrix**

```typescript
/**
 * CLAUDE.md's first principle: the plugin must never break a user's Claude
 * session. Every one of the five hook entry points wraps main() in a
 * try/catch that falls back to writing nothing and exiting 0 — "allow" is
 * silence, not a JSON decision. This suite drives the REAL built scripts
 * (via runHook, from test/helpers/run-hook.ts) through the malformed-input
 * and unavailable-store matrix the fail-open contract exists for, plus a
 * regression pin on the wire protocol itself: no hook shape ever carries an
 * `action` key (that's an internal CaptureResult field, never serialized).
 */
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'fail-open-e2e-session';

function projectDir(home: string): string {
  const dir = join(home, 'project');
  mkdirSync(dir, { recursive: true });
  return dir;
}

interface HookCase {
  readonly name: string;
  // Builds a valid, store-touching payload for this hook under the given
  // temp home. Must actually reach the store-open code path (not just be
  // well-formed JSON) so the corrupt-store/read-only-home rows in Task 3/4
  // exercise something real.
  readonly validPayload: (home: string) => string;
}

const HOOKS: readonly HookCase[] = [
  {
    name: 'session-start',
    validPayload: (home) =>
      JSON.stringify({
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'SessionStart',
        source: 'startup',
      }),
  },
  {
    name: 'user-prompt-submit',
    validPayload: (home) =>
      JSON.stringify({
        prompt: 'what does this function do?',
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'UserPromptSubmit',
      }),
  },
  {
    // Bash's `command` field is in pre-tool-use-fields.ts's STATIC_FIELDS map,
    // so this reaches the store — unlike Read (used by the harness smoke
    // test), which has no field mapping and short-circuits before the store
    // ever opens.
    name: 'pre-tool-use',
    validPayload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PreToolUse',
      }),
  },
  {
    // Bash's stdout/stderr fields are in tool-response.ts's RESPONSE_TEXT_PATHS
    // map, so this reaches the store — unlike Read with a bare {content}
    // (used by the harness smoke test), which needs {file:{content}} and
    // short-circuits before the store ever opens.
    name: 'post-tool-use',
    validPayload: (home) =>
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        tool_response: { stdout: 'hello\n', stderr: '' },
        session_id: SESSION_ID,
        cwd: projectDir(home),
        hook_event_name: 'PostToolUse',
      }),
  },
  {
    name: 'stop',
    validPayload: (home) => {
      const cwd = projectDir(home);
      return JSON.stringify({
        session_id: SESSION_ID,
        transcript_path: join(cwd, 'transcript.jsonl'),
        cwd,
        hook_event_name: 'Stop',
        stop_hook_active: false,
      });
    },
  },
];

// CLAUDE.md: "no hook ever emits {action:'allow'}, and the internal fallback
// is {action:'log'}" — `action` is a CaptureResult field that never crosses
// the wire; the four real hook-output shapes (`decision`, `systemMessage`,
// `hookSpecificOutput.permissionDecision`, `hookSpecificOutput.updatedToolOutput`)
// never use that key. Pinning this guards against a future refactor that
// starts serializing the internal decision object onto stdout.
function expectNoActionKey(stdout: string): void {
  expect(stdout).not.toMatch(/"action"\s*:/);
}

function expectFailsOpen(status: number, stdout: string): void {
  expect(status).toBe(0);
  expect(stdout).toBe('');
  expectNoActionKey(stdout);
}

describe('fail-open: malformed/hostile input never breaks a hook', () => {
  const MALFORMED_JSON = '{ this is not valid json #$%^&*';
  const TRUNCATED_JSON = '{"session_id": "fail-open-e2e-session", "cwd": "/tmp/unterminated';
  // Non-text control/high-byte content, repeated — never valid JSON, never
  // printable text. (execFileSync's `input` option is UTF-8 encoded from a JS
  // string, so this can't carry byte sequences with no valid Unicode
  // interpretation — but it still stresses readStdin()/JSON.parse with dense
  // control-character and NUL-byte content, which is the failure mode this
  // row exists to catch.)
  const BINARY_STDIN = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i))
    .join('')
    .repeat(4);
  const HUGE_STDIN = 'x'.repeat(100 * 1024 * 1024); // 100 MB, not valid JSON

  for (const hook of HOOKS) {
    describe(hook.name, () => {
      it('malformed JSON → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, MALFORMED_JSON, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('empty stdin → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, '', { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('truncated JSON → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, TRUNCATED_JSON, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('binary stdin → exit 0, empty stdout', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, BINARY_STDIN, { env: tempHomeEnv(home) });
          expectFailsOpen(result.status, result.stdout);
        });
      });

      it('100 MB stdin → exit 0, empty stdout, no OOM', () => {
        withTempHome((home) => {
          const result = runHook(hook.name, HUGE_STDIN, {
            env: tempHomeEnv(home),
            timeoutMs: 30_000,
          });
          expectFailsOpen(result.status, result.stdout);
        });
      }, 35_000);
    });
  }
});
```

- [ ] **Step 2: Run the new test file**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code test -- test/e2e/fail-open.e2e.test.ts
```

Expected: `PASS`, 25 tests (5 hooks × 5 input cases), all green. If any case fails, this is a real fail-open bug in the corresponding hook source (`plugins/claude-code/src/hooks/<name>.ts`) — investigate and fix the hook via `superpowers:systematic-debugging`; do not loosen the assertion.

- [ ] **Step 3: Typecheck and lint the new file**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code typecheck
pnpm --filter @akasecurity/ai-tc-claude-code lint
```

Expected: both clean, no errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git add plugins/claude-code/test/e2e/fail-open.e2e.test.ts
git commit -m "test(plugin): verify fail-open on malformed/hostile hook input

Table-driven over all five hooks x malformed JSON, empty stdin, truncated
JSON, binary stdin, and 100MB stdin — each must exit 0 with empty stdout."
```

---

### Task 3: Corrupt-store fail-open rows (5 cases)

**Files:**

- Modify: `plugins/claude-code/test/e2e/fail-open.e2e.test.ts`

**Interfaces:**

- Consumes: `HOOKS`, `expectNoActionKey` from Task 2 (same file, no import needed — same module scope).
- Produces: a second top-level `describe` block in the same file, extended further by Task 4.

- [ ] **Step 1: Add the corrupt-store describe block**

Append to `plugins/claude-code/test/e2e/fail-open.e2e.test.ts` (after the closing brace of the `'fail-open: malformed/hostile input never breaks a hook'` describe block):

```typescript
describe('fail-open: an unavailable store never breaks a hook', () => {
  // Non-header bytes → the first PRAGMA on open fails SQLITE_NOTADB, the
  // exact read failure the fail-open path guards against (mirrors
  // test/journey/harness.ts's corruptStore()).
  function seedCorruptStore(home: string): void {
    const storeDir = join(home, '.aka', 'data');
    mkdirSync(storeDir, { recursive: true });
    writeFileSync(
      join(storeDir, 'aka.db'),
      'AKA fail-open-e2e fixture — not a database\n'.repeat(64),
    );
  }

  for (const hook of HOOKS) {
    describe(hook.name, () => {
      it('valid input, corrupt store → exit 0', () => {
        withTempHome((home) => {
          seedCorruptStore(home);
          const payload = hook.validPayload(home);
          const result = runHook(hook.name, payload, { env: tempHomeEnv(home) });
          expect(result.status).toBe(0);
          expectNoActionKey(result.stdout);
        });
      });
    });
  }
});
```

- [ ] **Step 2: Run the new rows**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code test -- test/e2e/fail-open.e2e.test.ts
```

Expected: `PASS`, now 30 tests total (25 from Task 2 + 5 new). If a hook fails here, check whether it calls `openGatewayOrNull` (fail-open by design, see `plugins/claude-code/src/hooks/store-health.ts`) or `resolveDataGateway` directly without a wrapper (currently only `post-tool-use.ts` does this — it still fails open via the outer `try/catch` around `main()`, so it should still pass, just with `stdout === ''` instead of a systemMessage).

- [ ] **Step 3: Typecheck and lint**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code typecheck
pnpm --filter @akasecurity/ai-tc-claude-code lint
```

Expected: both clean.

- [ ] **Step 4: Commit**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git add plugins/claude-code/test/e2e/fail-open.e2e.test.ts
git commit -m "test(plugin): verify fail-open with a corrupt store

Valid input against a store file that isn't a SQLite database — every
hook must still exit 0."
```

---

### Task 4: Read-only `~/.aka` fail-open rows (5 cases) + protocol-pin coverage complete

**Files:**

- Modify: `plugins/claude-code/test/e2e/fail-open.e2e.test.ts`

**Interfaces:**

- Consumes: `HOOKS`, `expectNoActionKey`, `withTempHome`, `tempHomeEnv`, `runHook` — all already imported/defined earlier in the file.
- Produces: the completed 35-case matrix (25 + 5 + 5) satisfying every row in issue #7's acceptance criteria table.

- [ ] **Step 1: Add the read-only-home fixtures and rows**

Inside the same `'fail-open: an unavailable store never breaks a hook'` describe block from Task 3, add alongside `seedCorruptStore`:

```typescript
// ~/.aka exists but is unwritable, so any mkdir/write under it (a fresh
// data dir, settings.json, a throttle marker) hits EACCES.
function seedReadOnlyAkaHome(home: string): void {
  const akaDir = join(home, '.aka');
  mkdirSync(akaDir, { recursive: true });
  chmodSync(akaDir, 0o555);
}

// chmod back before withTempHome's cleanup rmSync — a read-only dir can
// block recursive removal of anything the hook wrote inside it before
// hitting the fault.
function restoreAkaHome(home: string): void {
  try {
    chmodSync(join(home, '.aka'), 0o755);
  } catch {
    // Nothing to restore.
  }
}
```

And add the new `it` inside the existing `describe(hook.name, ...)` block, alongside `'valid input, corrupt store → exit 0'`:

```typescript
it('valid input, read-only ~/.aka → exit 0', () => {
  withTempHome((home) => {
    seedReadOnlyAkaHome(home);
    try {
      const payload = hook.validPayload(home);
      const result = runHook(hook.name, payload, { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expectNoActionKey(result.stdout);
    } finally {
      restoreAkaHome(home);
    }
  });
});
```

- [ ] **Step 2: Run the full e2e file**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code test -- test/e2e/fail-open.e2e.test.ts
```

Expected: `PASS`, 35 tests total (5 hooks × 7 matrix cases).

- [ ] **Step 3: Typecheck and lint**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code typecheck
pnpm --filter @akasecurity/ai-tc-claude-code lint
```

Expected: both clean.

- [ ] **Step 4: Commit**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git add plugins/claude-code/test/e2e/fail-open.e2e.test.ts
git commit -m "test(plugin): verify fail-open with a read-only ~/.aka

Completes the fail-open matrix from issue #7: 5 hooks x 7 input/store
conditions, 35 cases, all exiting 0 with no hook ever emitting an
'action' key on the wire."
```

---

### Task 5: Full-suite verification and wrap-up

**Files:** none created or modified.

**Interfaces:**

- Consumes: the full plugin test suite, lint, and typecheck.
- Produces: a verified, pushable branch.

- [ ] **Step 1: Run the whole plugin test suite (not just the new file)**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm --filter @akasecurity/ai-tc-claude-code test
```

Expected: `PASS`, every existing suite (journey, hooks, history, etc.) plus the new 35-case e2e suite all green — confirms the new file didn't destabilize anything (e.g. via shared global state or port/file collisions).

- [ ] **Step 2: Run the full workspace format/lint/typecheck gate**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
pnpm format:check
pnpm lint
pnpm typecheck
```

Expected: all clean.

- [ ] **Step 3: Confirm the diff is scoped to the intended file**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git diff --stat origin/qa/5-e2e-hook-harness...HEAD
```

Expected: only `plugins/claude-code/test/e2e/fail-open.e2e.test.ts` (new) plus this plan doc under `docs/superpowers/plans/`.

- [ ] **Step 4: Push the branch**

```bash
cd /Users/tvburger/Spaces/AKA/Development/ai-tc
git push -u origin qa/6-fail-open-e2e
```

Note for the PR: since this branch is based on `qa/5-e2e-hook-harness` (PR #63, not yet merged), open the PR against `qa/5-e2e-hook-harness` as its base, not `main` — retarget to `main` once #63 merges, or rebase then. Reference both issue #7 (this work) and issue #6 (the prerequisite harness) in the PR description.

**Known gap, deliberately out of scope:** issue #7's acceptance criteria include "Wired as a required check." `main`'s branch protection currently has **no required status checks configured at all** (`gh api repos/akasecurity/ai-tc/branches/main/protection` shows no `required_status_checks` key) — this is a repo-wide gap, not specific to this test file, and fixing it means changing branch protection settings (shared infrastructure, needs repo-admin action), not adding code. File a follow-up issue/task for an admin to add the "CI" workflow as a required status check on `main`; do not fold that change into this PR.
