#!/usr/bin/env bash
#
# Run a command with every outbound network path blocked except loopback.
#
#   tools/ci/no-network-test.sh pnpm test
#
# WHY A NAMESPACE AND NOT A FIREWALL RULE. The obvious form — `iptables -A OUTPUT
# -o lo -j ACCEPT` then `-A OUTPUT -j REJECT` — also cuts the Actions runner
# agent off from GitHub, since the agent streams step output from the same host
# over the same OUTPUT chain. The job would be reported as lost rather than
# failed. `unshare --net` gives this command tree its own empty network stack
# instead, so the agent keeps its connectivity and the blocking is total for
# everything inside.
#
# WHY IT DROPS BACK TO THE CALLER. `unshare` needs root to create the namespace
# and to bring `lo` up, but running the suite as root would silently weaken it:
# root ignores the 0444 mode that `packages/persistence/test/helpers/
# fault-injection.ts` uses to build a read-only store, so those cases would
# report `effective: false` and skip. `setpriv` hands the original uid/gid back
# before the command runs, so this job exercises the same suite as every other.
#
# WHAT THE VITEST GUARD DOES NOT COVER, and this does: a child process. A
# shell-out (`npm view`, `claude -p`) is a separate process with its own copy of
# node:net, so `test/setup/no-network.ts` cannot see it. Inside this namespace it
# has nowhere to go.
#
# Linux only — it is the CI job's mechanism, not a developer workflow. The vitest
# guard runs everywhere, on every platform, in every job.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

# Phase 1: outside the namespace. Re-enter as root in a fresh network namespace,
# carrying the caller's identity and the environment the toolchain needs. `sudo
# env VAR=...` is used rather than `sudo -E` because preserving the whole
# environment needs a sudoers SETENV grant that is not guaranteed, while `env` is
# just the command sudo was asked to run.
if [ "${AKA_NO_NETWORK_INSIDE:-}" != "1" ]; then
  exec sudo env \
    AKA_NO_NETWORK_INSIDE=1 \
    "AKA_NO_NETWORK_UID=$(id -u)" \
    "AKA_NO_NETWORK_GID=$(id -g)" \
    "PATH=$PATH" \
    "HOME=$HOME" \
    CI=1 \
    DO_NOT_TRACK=1 \
    TURBO_TELEMETRY_DISABLED=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    unshare --net -- "$0" "$@"
fi

# Phase 2: inside the namespace, as root. A fresh namespace has a loopback
# interface but leaves it DOWN, and the suite genuinely uses loopback (the CLI's
# isPortFree bind probe, the dashboard boot test). Bring it up, then drop back to
# the caller and re-enter this script one last time.
if [ "$(id -u)" -eq 0 ] && [ "${AKA_NO_NETWORK_DROPPED:-}" != "1" ]; then
  if [ -z "${AKA_NO_NETWORK_UID:-}" ] || [ -z "${AKA_NO_NETWORK_GID:-}" ]; then
    echo "no-network: no caller identity to drop back to. Run this script as the" >&2
    echo "no-network: unprivileged user; it re-enters itself under sudo." >&2
    exit 2
  fi
  ip link set lo up
  # The kernel normally attaches 127.0.0.1/8 when loopback comes up; assign it by
  # hand if it did not, rather than discovering it in the positive control below.
  ip addr show lo | grep -q 'inet 127\.0\.0\.1' || ip addr add 127.0.0.1/8 dev lo
  export AKA_NO_NETWORK_DROPPED=1
  exec setpriv \
    --reuid="$AKA_NO_NETWORK_UID" \
    --regid="$AKA_NO_NETWORK_GID" \
    --init-groups \
    --inh-caps=-all \
    "$0" "$@"
fi

# Phase 3: inside the namespace, unprivileged.
#
# The positive control. An empty network stack and a broken command look
# identical from a green run, so prove the block is real before trusting the
# result — the same reason the fault injectors in packages/persistence refuse to
# run vacuously. Two probes, because either alone can pass for the wrong reason:
# a name that must resolve (DNS is gone) and a literal address that must connect
# (routing is gone).
echo "no-network: verifying egress is actually blocked"

# A probe whose own tooling is missing reports "not blocked = false" and the
# control passes without probing anything — the precise shape of vacuous pass it
# exists to prevent. Demand the tools first.
for tool in getent timeout ip; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "no-network: FAILED — '$tool' is not installed, so the egress probe below" >&2
    echo "no-network: cannot run and would pass without proving anything." >&2
    exit 1
  fi
done

if getent hosts registry.npmjs.org >/dev/null 2>&1; then
  echo "no-network: FAILED — DNS still resolves inside the namespace." >&2
  echo "no-network: the suite would have passed without proving anything." >&2
  exit 1
fi

# 1.1.1.1:443 is a literal, so this probe needs no DNS. Any outcome other than a
# connection failure means packets are still leaving.
if timeout 10 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "no-network: FAILED — a TCP connection to 1.1.1.1:443 succeeded." >&2
  echo "no-network: the suite would have passed without proving anything." >&2
  exit 1
fi

# Loopback must still work, or the run below would fail for the wrong reason.
if ! ip addr show lo | grep -q 'inet 127\.0\.0\.1'; then
  echo "no-network: FAILED — loopback is not up; the suite needs it." >&2
  exit 1
fi

echo "no-network: egress is blocked, loopback is up — running: $*"
exec "$@"
