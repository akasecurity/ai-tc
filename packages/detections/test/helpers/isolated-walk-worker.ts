// The probe walk for one rule, on a thread of its own. Started by
// `walkInIsolation` (isolated-walk.ts); Node loads this file directly, so it
// imports only what type stripping can load.
import { parentPort, workerData } from 'node:worker_threads';

import type { Rule } from '@akasecurity/schema';

import { worstProbeMs } from '../../src/security/redos-probe.ts';
import { threadCpuMs } from './growth-clock.ts';

const { rule, stepMs } = workerData as { rule: Rule; stepMs: number };

// This thread's CPU time, read in whole steps of `stepMs` when that is set, so
// a caller can drive the walk on a clock as coarse as a tick-credited one.
const steppedThreadCpuMs = (): number => {
  const ms = threadCpuMs();
  return stepMs > 0 ? Math.floor(ms / stepMs) * stepMs : ms;
};

const { ms, probe } = worstProbeMs(rule, steppedThreadCpuMs);
parentPort?.postMessage({ ms, probe, probeLength: probe.length });
