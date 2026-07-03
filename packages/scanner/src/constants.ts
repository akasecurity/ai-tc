// Directory names skipped by BOTH the file walker and repo discovery: language
// and tooling caches that are enormous, machine-generated, and never contain
// first-party code. One list so the two traversals can't drift apart; each
// side extends it with its own concerns (walk: build outputs + .git; discover:
// macOS system dirs — and deliberately NOT .git, whose presence is the
// detection signal).
export const COMMON_SKIP_DIRS = ['node_modules', '__pycache__', '.venv', 'venv', '.cache'];
