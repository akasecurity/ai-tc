// The `--home <path>` (or `--home=<path>`) override the `/aka:setup` wizard scripts
// accept so the journey harness can point the whole script chain at a throwaway
// ~/.aka home instead of the real one. Returns the path, or undefined when the flag
// is absent — the scripts then thread it into loadConfig(base), so undefined falls
// back to the default ~/.aka. A flag, not an env var: the plugin's n/no-process-env
// rule forbids reading process.env, so the flag is the only channel.
export function parseHomeFlag(argv: string[]): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--home') {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) return next;
    } else if (arg?.startsWith('--home=')) {
      return arg.slice('--home='.length);
    }
  }
  return undefined;
}
