// Node 24's V8 can abort a process with
// `Check failed: jit_page_->allocations_.erase(addr) == 1` while freeing code
// after worker threads are terminated (nodejs/node#66366, fixed in V8 upstream,
// not backported to 24.x). It surfaces as a test worker that exits with no
// failure of its own, and the issue reports that turning off wasm code GC
// removes it. Every package whose test process can terminate a worker loads
// this file.
//
// Set here rather than through vitest's `execArgv`: that lands in
// `process.execArgv`, which every `new Worker` inherits, and Node refuses a V8
// flag in a worker's arguments. V8 flags are process-wide, so this reaches the
// worker isolates too.
//
// Gated to the 24 line, the one the abort is reported on. When a 24.x release
// carries the backport, gate on the releases before it.
// packages/eslint-config/test/no-wasm-code-gc-guard.test.js fails if an owing
// package drops this file, if this Node's V8 no longer knows the flag
// (`setFlagsFromString` does not throw on an unknown one), or if `.nvmrc` or a
// workflow pins a Node major past this gate.
import { setFlagsFromString } from 'node:v8';

if (process.versions.node.split('.')[0] === '24') setFlagsFromString('--no-wasm-code-gc');
