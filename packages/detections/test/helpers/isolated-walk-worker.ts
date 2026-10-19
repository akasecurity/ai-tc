// The probe walk for one rule, on a thread of its own. Started by
// `walkInIsolation` (isolated-walk.ts); Node loads this file directly, so it
// imports only what type stripping can load.
import { parentPort, workerData } from 'node:worker_threads';

import type { Rule } from '@akasecurity/schema';

import { worstProbeMs } from '../../src/security/redos-probe.ts';

const threadCpuMs = (): number => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};

const { ms, probe } = worstProbeMs(workerData as Rule, threadCpuMs);
parentPort?.postMessage({ ms, probe, probeLength: probe.length });
