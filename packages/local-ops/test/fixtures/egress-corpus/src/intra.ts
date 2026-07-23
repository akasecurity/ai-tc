// Readiness probe against the internal database proxy. A bare client call with
// the URL as its only argument and no options object.
export async function databaseIsReady(): Promise<boolean> {
  const res = await fetch('https://db.internal/health');
  return res.ok;
}
