/** The shared `[aka] ` stderr prefix for operator-facing warnings. */
export function akaWarn(message: string): void {
  process.stderr.write(`[aka] ${message}\n`);
}
