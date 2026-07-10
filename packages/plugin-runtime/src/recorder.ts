// The binary-name half of an available-pack `recorded_by` stamp
// (`<binary>@<version>`; see SqliteInstalledPacksRepository.recordInventory).
// SessionStart stamps the plugin's own mirror writes with PLUGIN_RECORDER_BINARY,
// and the stale-session notice (standalone-gateway) routes its remedy on the SAME
// constant — so the producer and the consumer can't drift on the literal, and a
// rename lands in one place. The CLI stamps its own name (`aka-cli`) from
// cli; the notice only needs to recognise the plugin, treating every other
// recorder as "another binary".
export const PLUGIN_RECORDER_BINARY = 'plugin';

/** The `recorded_by` stamp a plugin SessionStart writes: `plugin@<version>`. */
export function pluginRecordedBy(version: string): string {
  return `${PLUGIN_RECORDER_BINARY}@${version}`;
}
