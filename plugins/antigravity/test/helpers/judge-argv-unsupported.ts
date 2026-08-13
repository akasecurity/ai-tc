// The gate for the wizard-journey suite on Windows.
//
// Not a defect in that suite, and no longer the shell-free-spawn problem the
// other two plugins had: `spawnAgy` plans its spawn like its siblings do (see
// @akasecurity/plugin-sdk/bare-command), and on Windows that reaches a `.cmd`
// shim through cmd.exe under an anchored cwd. What it cannot do is carry THIS
// host's argv across cmd.exe.
//
// Antigravity's CLI takes the judge prompt in ARGV — `agy -p "<prompt>"
// --output-format json` — and documents no stdin or prompt-file input to move
// it to. That prompt is the rubric plus the raw hits, so it fails a Windows
// command line three separate ways: it is multi-line, and a command line carries
// no line break; it is several KiB against cmd.exe's 8,191-character ceiling;
// and it is built from scanned transcript text, where a `&` or a `"` AKA did not
// choose would be re-read as syntax. `planBareCommand` refuses it outright
// rather than escaping it hopefully, which is the correct answer and also means
// the judge cannot run through a batch shim at all.
//
// The journey's stub can only BE a batch shim — a test cannot author a real
// executable — so the stub is unreachable there and the suite's load-bearing
// `judgeWasInvoked()` assertions cannot be driven. A real `agy` installed as an
// executable takes the planner's direct path and runs fine on Windows; it is the
// test double that cannot, which is why this gate is scoped to this suite rather
// than described as "the judge does not work on Windows".
//
// This limitation is tracked separately. judge-argv-unsupported.test.ts pins it
// BEHAVIOURALLY, against the real planner and the real argv, so the day the
// prompt stops riding argv this gate goes red and names what to do next.

// Exported as a BOOLEAN rather than a ready-made `describe.skipIf(...)`: the
// inferred type of a vitest gate names runner internals that cannot be named
// across a module boundary (TS4023), so each consumer builds its own one-liner
// from this flag. The reason for skipping lives here; only the mechanics repeat.
export const judgeArgvUnsupported = process.platform === 'win32';
