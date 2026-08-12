// The gate for suites that cannot run on Windows because they drive a command
// through a PATH shim, and the spawn they model passes no shell.
//
// Not a flake, and not a defect in these suites: `writeCommandShim` writes a
// `.cmd` launcher on win32 because an extensionless `#!` file is unrunnable
// there, and Node's CVE-2024-27980 fix then refuses to spawn a `.cmd`/`.bat`
// unless the caller opts into a shell. `spawnCodex` does not, so neither may
// the probe — a probe that disagreed with its subject would prove nothing, and
// disagreeing in this direction is the dangerous one: the shim fails OPEN, so a
// probe that "succeeded" where the real spawn would not lets the chain reach the
// developer's real installed CLI with the seeded fixtures on stdin.
//
// So `assertShimResolves` is RIGHT to refuse here, and the refusal is reporting
// a real limitation of the code these suites model rather than one of its own.
// That limitation is tracked separately; until it moves, skipping is honest and
// a green run would not be.
//
// Scoped to the suites that actually spawn through the shim. A file's other
// suites keep running — several in this package do, and they are the reason this
// is a per-describe gate rather than a per-file one.

// Exported as a BOOLEAN rather than a ready-made `describe.skipIf(...)`: the
// inferred type of a vitest gate names runner internals that cannot be named
// across a module boundary (TS4023), so each consumer builds its own one-liner
// from this flag. The reason for skipping lives here; only the mechanics repeat.
export const shimUnsupported = process.platform === 'win32';
