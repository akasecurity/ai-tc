/**
 * A scan worker that loads cleanly and then never announces itself.
 *
 * It stands in for a thread that is merely slow to start — a cold machine, or a
 * Windows runner whose antivirus is reading the freshly written script. The
 * parent must report that as a slow start and not as a rule that hung: the two
 * have completely different consequences, since only the second one gets a rule
 * quarantined forever. Node loads this file directly, so it stays on plain type
 * annotations like the worker it replaces.
 */
import { parentPort } from 'node:worker_threads';

// Registered so the thread stays alive and idle rather than exiting, which the
// parent would report as a crash instead of a slow start.
parentPort?.on('message', () => {
  // Deliberately never answers.
});
