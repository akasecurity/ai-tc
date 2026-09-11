# Samples the Windows runner while the test legs run.
#
# Everything anyone has proposed for the `Windows · Unit tests` leg — capping the
# vitest pool, serialising the step, raising the ceiling, cutting per-test store
# setup — is a guess about a resource NO LOG IN THIS REPOSITORY MEASURES. No job
# records the runner's CPU steal, its disk queue or its memory pressure, so every
# causal claim about that leg is inferred from the shape of timing data.
#
# It matters that this SAMPLES rather than snapshots. The failures are stalls in
# the tail: individual tests that take 0.6-1.8s on a green run intermittently take
# 20-55s, with nothing in between. A before/after reading cannot see that; a
# periodic one can say whether the disk queue or the CPU was saturated while it
# happened.
#
# It must never fail the job it is measuring. The counter names are locale-bound,
# so a runner image that renames one has to cost a missing measurement rather than
# a red leg — hence the empty catch, which is deliberate and not an oversight.
$ErrorActionPreference = 'Continue'
$out = Join-Path $env:RUNNER_TEMP 'runner-samples.csv'
'time,cpu_pct,disk_queue,avail_mb' | Set-Content $out
while ($true) {
  try {
    $counters = Get-Counter -Counter @(
      '\Processor(_Total)\% Processor Time',
      '\PhysicalDisk(_Total)\Current Disk Queue Length',
      '\Memory\Available MBytes'
    ) -ErrorAction Stop
    $values = $counters.CounterSamples | ForEach-Object { [math]::Round($_.CookedValue, 1) }
    "$(Get-Date -Format o),$($values -join ',')" | Add-Content $out
  } catch {
    # A counter this image does not carry: keep sampling the ones it does on the
    # next tick rather than ending the series.
  }
  Start-Sleep -Seconds 10
}
