/**
 * A clock that reads WORK rather than elapsed time, for the pre-flight's
 * corroborating measurement.
 *
 * `checkRuleTiming` excludes a rule on wall time — the hook's harness timeout is
 * wall-clock, so that is the right unit for the bound — but it may only CACHE a
 * breach that this clock agrees was spent executing. A descheduled thread
 * accrues elapsed time having run nothing, and the verdict is permanent and
 * never re-measured, so the difference decides whether a legitimate rule is
 * disabled for good.
 *
 * It lives here rather than in `@akasecurity/detections` because that package
 * takes no Node-API dependency: it is the pure rule engine, and part of it is
 * bundled for the browser extension's content script, where `process` does not
 * exist. Reading CPU time is a Node capability, so it is supplied BY the callers
 * that have one — which is also why `checkRuleTiming` takes the clock as a
 * required parameter rather than reaching for one itself.
 */

/**
 * CPU consumed by the calling THREAD, in milliseconds, as a monotonic clock.
 *
 * Per-thread is the measurement that matters, and the reason is where this runs.
 * The product's pre-flight executes inside the isolated scan's worker thread
 * (that is the whole point — the battery decides a pattern is unsafe by driving
 * it into backtracking, so measuring is itself a way to hang), while
 * `process.cpuUsage()` sums EVERY thread in the process. On that path a
 * process-wide reading charges the probe with whatever the main thread and V8's
 * background GC and compiler threads did in the same window, and the error runs
 * in the inflating direction — toward corroborating a stall, which is the false
 * accusation the corroboration exists to refuse.
 *
 * `process.threadCpuUsage()` reads the thread's own accounting and is what the
 * platform floor here provides (Node 24; the API landed in 22.15 / 23.9).
 *
 * The fallback is deliberate and its direction is stated rather than assumed.
 * Where per-thread accounting is absent, a process-wide reading is still
 * incomparably better than wall time for this question: the stalls it must
 * reject burned 0.2-7.7ms against breaches of 105-185ms, and no plausible amount
 * of neighbouring-thread CPU closes a gap that size. What it can do is inflate
 * toward the OLD behaviour — cache a breach that should not have been cached —
 * so it degrades to today's defect at worst and never past it. Falling back to
 * wall time, by contrast, would restore the defect outright, and returning a
 * constant would silently un-quarantine every hostile rule on the machine.
 */
export function workClockMs(): number {
  // Called as a METHOD on each branch rather than through a local binding. A
  // binding would be an unbound method reference — which lint refuses, and
  // rightly: `process.cpuUsage` reads `this`, so a detached call is a latent
  // bug even where the per-thread branch happens not to need it. The presence
  // check is a property read, resolved per call rather than latched at module
  // load, because this module is loaded on both the main thread and the scan
  // worker.
  const usage =
    typeof process.threadCpuUsage === 'function' ? process.threadCpuUsage() : process.cpuUsage();
  return (usage.user + usage.system) / 1000;
}
