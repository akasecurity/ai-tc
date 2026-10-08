import type { Register } from 'claude-code';

import * as engine from '../engine.js';

// Loads the built engine so `claude plugin validate` checks the module the way
// the engine will load it.
export const register: Register = () => {
  engine.registerBundledPacks();
};
