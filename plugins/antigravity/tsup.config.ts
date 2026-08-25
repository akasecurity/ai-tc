import { copyFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { defineConfig } from 'tsup';

// esbuild (on releases predating node:sqlite in its builtin list) externalizes
// the import but strips the `node:` prefix, emitting a bare `sqlite` specifier —
// a nonexistent npm package that crashes the hook at load. esbuild's own printer
// re-applies that stripping even when an onResolve plugin pins the path, so we
// restore the prefix on the emitted bundles instead. Same fix as
// plugins/claude-code/tsup.config.ts — both bundle @akasecurity/persistence,
// which imports node:sqlite.
//
// Hardened against the two ways a naive string-replace is fragile:
//   - matches only real module-specifier positions (`… from "sqlite"`,
//     `import("sqlite")`, `require("sqlite")`), so an incidental "sqlite" string
//     in a bundled dependency is left untouched; both quote styles are handled.
//   - re-scans each file afterward and throws if a bare specifier survives, so a
//     future change to esbuild's emit fails the BUILD loudly rather than shipping
//     a bundle that dies at load. A future esbuild that keeps `node:sqlite` on its
//     own yields zero rewrites and zero leftovers — no false failure.
const SPECIFIER_SOURCE = String.raw`(\bfrom\s*|\b(?:import|require)\(\s*)(['"])sqlite\2`;

function normalizeSqliteSpecifier(outDir: string): void {
  for (const name of readdirSync(outDir)) {
    if (!name.endsWith('.js')) continue;
    const file = join(outDir, name);
    const before = readFileSync(file, 'utf8');
    const after = before.replace(
      new RegExp(SPECIFIER_SOURCE, 'g'),
      (_match, prefix: string, quote: string) => `${prefix}${quote}node:sqlite${quote}`,
    );
    if (after !== before) writeFileSync(file, after);

    if (new RegExp(SPECIFIER_SOURCE).test(after)) {
      throw new Error(
        `tsup: ${name} still imports a bare "sqlite" specifier after node:sqlite ` +
          `normalization — esbuild's emit format may have changed. The hook would ` +
          `crash at load; failing the build instead.`,
      );
    }
  }
}

export default defineConfig({
  // Named entries keep the output flat in scripts/ — hooks.json paths depend on it
  entry: {
    // Antigravity has no SessionStart and no UserPromptSubmit event — the
    // once-per-conversation inventory pass and the prompt-capture trigger both
    // hang off PreInvocation. See src/hooks/pre-invocation.ts.
    'pre-invocation': 'src/hooks/pre-invocation.ts',
    'pre-tool-use': 'src/hooks/pre-tool-use.ts',
    'post-tool-use': 'src/hooks/post-tool-use.ts',
    stop: 'src/hooks/stop.ts',
    // The isolated scan's worker thread. hooks.json never names it — the plugin
    // SDK starts it by path from whichever hook is running, and every hook
    // script lands in this same directory. See src/scan-worker.ts.
    'scan-worker': 'src/scan-worker.ts',
    // Detached token-usage reconcile worker, spawned by the Stop hook (off the hot path)
    reconcile: 'src/reconcile.ts',
    // The detached policy-sync child, spawned by SessionStart when a machine is
    // attached. Lands flat in scripts/ like every other entry, because that is
    // where triggerPolicySync resolves it from.
    sync: 'src/sync.ts',
    // Read surface (aka:health · aka:findings · aka:recommend · aka:audit) + onboarding (aka:setup)
    query: 'src/query.ts',
    // aka:dashboard — launches the web dashboard via the `aka` CLI
    dashboard: 'src/dashboard.ts',
    onboard: 'src/onboard.ts',
    // aka:setup FP-writeback adapter (reads a backfill --triage stream)
    'apply-suppressions': 'src/apply-suppressions.ts',
    intro: 'src/intro.ts',
    // aka-setup start-light card (Not-now branch)
    'start-light': 'src/start-light.ts',
    firstrun: 'src/firstrun.ts',
    backfill: 'src/backfill.ts',
    filescan: 'src/filescan.ts',
    // aka-setup frame-0.6 "Review leaked keys" — the secret-leak remediation
    // chain's production entry
    remediate: 'src/remediation/entry.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'scripts',
  splitting: false,
  // Hook scripts must be self-contained: the user's machine has no node_modules
  noExternal: [/^@akasecurity\//, 'zod'],
  onSuccess: async () => {
    normalizeSqliteSpecifier('scripts');
    // Ship the locked triage rubric next to apply-suppressions.js. runJudge's
    // default path is not in the package `files`, so the adapter reads
    // scripts/triage-rubric.md at runtime — copied here from the single source,
    // the harness-agnostic rubric owned by @akasecurity/setup-wizard (the
    // Claude Code plugin's build copies the same asset).
    copyFileSync(
      '../../packages/setup-wizard/assets/triage-rubric.md',
      join('scripts', 'triage-rubric.md'),
    );
  },
});
