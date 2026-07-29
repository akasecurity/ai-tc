/**
 * A scan worker that dies at load, before it can answer anything.
 *
 * The failure it stands in for is the one a hard-timeout mechanism has to get
 * right: if a dead worker is reported as a timeout, an immediate crash reads as
 * a slow scan, the real error is lost, and the caller waits out a budget it
 * never needed to spend. Node loads this file directly, so it stays on plain
 * type annotations like the worker it replaces.
 */
throw new Error('scan worker failed to load');
