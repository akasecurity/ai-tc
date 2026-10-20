// Node 24.21's V8 can abort a process with
// `Check failed: jit_page_->allocations_.erase(addr) == 1` while freeing code
// after worker threads are terminated (nodejs/node#66366, fixed in V8 upstream,
// not yet in 24.x). A suite that terminates scan workers on purpose took a test
// worker down on CI this way several times, and it reproduced on 24.21.0 at
// about one run in thirty. The issue reports that turning off wasm code GC
// removes it; our own runs could not yet show a difference either way.
//
// Set here rather than through vitest's `execArgv`: that lands in
// `process.execArgv`, which every `new Worker` inherits, and Node refuses a V8
// flag in a worker's arguments. V8 flags are process-wide, so this reaches the
// worker isolates too. Remove once 24.x carries the backport.
import { setFlagsFromString } from 'node:v8';

setFlagsFromString('--no-wasm-code-gc');
