// Every test file runs on a machine with NO administrator, stated rather than
// inherited.
//
// The administrative overlay (packages/persistence/src/managed-settings.ts) is
// read from absolute system paths — `/Library/Application Support/AKASecurity`
// on macOS, `%ProgramData%\AKASecurity` on Windows, `/etc/aka` on Linux —
// deliberately outside `~/.aka`, so that a lock is not removable by the party
// being locked. The consequence for the suite is that a test which builds a
// whole fake machine in a temp dir still reads the REAL administrator's file:
// `base` redirects `~/.aka` and reaches none of this.
//
// That is not a stale fixture, it is an undeclared input. It arrived as
// twenty-eight failures across @akasecurity/persistence,
// @akasecurity/plugin-sdk and the CLI, on a clean checkout of main and caused
// by no change in the tree: a laptop enrolled for dogfooding pins `runMode:
// attached`, so every case asserting the `standalone` default received
// `attached`. CI has no such file, so CI stayed green throughout and the
// failure landed only on the people who had installed one.
//
// A per-call override cannot close it. `readEffectiveSettings` and
// `applyOnboarding` both take a `managedOverride`, and both are useless for the
// reads that actually fail, which sit several frames below the test:
// `db.installedPacks.setPolicy()` reaches `readWorkspaceSettings` through
// `openControlPlaneFloors`, and `aka sync-history` reaches it again inside the
// attached-mode pass. So the declaration is process-scoped, like the property
// it describes, and installed here for the same reason the no-network guard is:
// a guarantee that has to hold in every frame belongs in setup, not at a call
// site somebody has to remember.
//
// It moves the DEFAULT only. A suite that wants an administrator still says so
// — by passing paths to `readManagedSettings`, a `managedOverride` to the two
// writers, or its own paths back through the seam below — which is what keeps
// the managed layer's own suite testing the managed layer.
//
// Which packages wire it is derived rather than counted — every one whose
// dependency closure can load @akasecurity/persistence, asserted by
// packages/eslint-config/test/no-managed-settings-guard.test.js. pnpm symlinks
// each of those to this same directory and vitest resolves symlinks, so the
// module instance this mutates is the one the code under test reads.
//
// The import names ONE MODULE by relative path, and both halves of that are
// load-bearing. A setup file is loaded before EVERY test file in every package
// that wires it, so whatever it imports is in the module cache before any of
// them registers a mock — and three suites in this package `vi.mock('node:fs')`
// and then `await import('../src/paths.ts')` to reach a branch only a mocked
// syscall can. Importing the package BARREL here pre-cached `paths.ts`,
// `fingerprint.ts` and the vault against the real `fs`, so those dynamic
// imports handed back the unmocked instance and nineteen cases failed on a
// branch they could no longer enter. (They caught it: each asserts its
// interception actually fired, which is the guard that turned a silent
// green-for-the-wrong-reason into a visible failure.) Reaching for the one
// module keeps that graph to `managed-settings.ts` itself, which nothing mocks;
// the relative path is what makes that possible, since the package exports its
// barrel alone — and it is why this seam need not be re-exported from there.
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../packages/persistence/src/managed-settings.ts';

UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
