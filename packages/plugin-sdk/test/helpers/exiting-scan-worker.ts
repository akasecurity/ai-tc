/**
 * A scan worker that loads cleanly, registers nothing, and lets its event loop
 * empty — so the thread exits on its own without ever answering.
 *
 * Distinct from `crashing-scan-worker.ts`, which throws and reaches the parent
 * as an `'error'`. This is the quieter shape: no error is ever emitted, only an
 * `'exit'`. In the shipped plugin it would take a truncated or mis-built
 * `scripts/scan-worker.js` that parses but registers no message listener. The
 * parent has to latch it anyway — a thread that dies by itself dies the same
 * way again, and respawning it once per rule burns the pre-flight's whole pass
 * budget inside a pass that was already doomed.
 *
 * Node loads this file directly, so it stays on plain type annotations like the
 * worker it replaces.
 */
export {};
