/**
 * A scan worker that dies at load, before it can answer anything.
 *
 * Used here as a TRIPWIRE rather than a fault: a case whose whole claim is
 * "this ruleset needs no worker" points at this file, so a change that starts
 * one anyway fails loudly instead of passing on a worker nobody noticed. Node
 * loads it directly, so it stays on plain type annotations like the worker it
 * replaces.
 */
throw new Error('scan worker failed to load');
