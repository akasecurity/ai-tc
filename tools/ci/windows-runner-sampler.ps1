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

# PER COUNTER, not one call for the three. Under `-ErrorAction Stop` a single
# call promotes any per-counter error to a terminating one, so a name this image
# does not carry loses the whole tick — and since a renamed counter is not a
# transient condition, it loses EVERY tick and the file ends as its header line
# alone. That is the empty series this sampler exists to never produce, and it
# would read exactly like a quiet runner.
#
# Read separately, a missing counter costs its own column and nothing else.
function Read-Counter {
  param([string] $Path)
  try {
    $sample = (Get-Counter -Counter $Path -ErrorAction Stop).CounterSamples[0]
    return [math]::Round($sample.CookedValue, 1)
  } catch {
    return ''
  }
}

while ($true) {
  $cpu = Read-Counter '\Processor(_Total)\% Processor Time'
  $disk = Read-Counter '\PhysicalDisk(_Total)\Current Disk Queue Length'
  $mem = Read-Counter '\Memory\Available MBytes'
  "$(Get-Date -Format o),$cpu,$disk,$mem" | Add-Content $out
  Start-Sleep -Seconds 10
}
