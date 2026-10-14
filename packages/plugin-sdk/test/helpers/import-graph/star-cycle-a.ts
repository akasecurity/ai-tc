// A star-export cycle for `sdk-import-graph.test.ts`: a and b re-export each
// other, and only a reaches c. Every module in the cycle exports `fromC`.
export * from './star-cycle-b.ts';
export * from './star-cycle-c.ts';
