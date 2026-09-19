// The tsup config's entry keys, read from the EVALUATED module rather than the
// config file's text. A regex over the source matches a commented-out entry
// (or one inside a block comment) exactly as readily as a real one, so it
// cannot tell "removed" from "declared" — reading the object tsup itself
// builds the bundle from is the only form that can.
import tsupConfig from '../../tsup.config.ts';

export function declaredEntryKeys(): string[] {
  const config: unknown = tsupConfig;
  if (typeof config !== 'object' || config === null || Array.isArray(config)) {
    throw new Error('tsup.config.ts no longer exports a single options object');
  }
  const { entry } = config as { entry?: unknown };
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new Error('tsup.config.ts no longer declares its entries as a named map');
  }
  return Object.keys(entry);
}
