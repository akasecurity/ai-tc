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
# For the same reason it refuses to START as root: there would be no unprivileged
# identity to drop back to, and the suite would run with those cases quietly
# skipped. Run it as the unprivileged user; it elevates itself.
#
# WHAT THE VITEST GUARD DOES NOT COVER, and this does: a child process. A
# shell-out (`npm view`, `claude -p`) is a separate process with its own copy of
# node:net, so `test/setup/no-network.ts` cannot see it. Inside this namespace it
# has nowhere to go.
#
# Linux only — it is the CI job's mechanism, not a developer workflow. The vitest
# guard runs everywhere, on every platform, in every job. Every refusal path
# below is driven with stubbed probe tooling by
# `packages/eslint-config/test/no-network-runtime.test.js`: a positive control
# that nothing exercises is one edit away from being decorative.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

# `id` is demanded before anything reads a uid, for the same reason the probe
# tools are demanded before the egress control runs: a check whose own tooling is
# missing does not fail, it passes without checking. `[ "$(id -u)" -eq 0 ]` with
# no `id` on PATH substitutes the empty string, and `[ "" -eq 0 ]` is not false —
# it is an ERROR, exit 2, which `if` reads as false. `set -e` does not fire
# inside an `if` condition, so every privilege decision below would silently
# invert: the start-as-root refusal would not refuse, the drop-back would carry
# an empty uid, and the phase-3 control would wave a root run through. Measured,
# not reasoned: with `id` off PATH the script ran the command and exited 0.
if ! command -v id >/dev/null 2>&1; then
  echo "no-network: FAILED — 'id' is not installed, so every privilege check below" >&2
  echo "no-network: would evaluate to false without checking anything and the suite" >&2
  echo "no-network: could run as root with its read-only-store cases skipping." >&2
  exit 1
fi

# Captured once. The value cannot change within one exec of this script, and a
# single reader is also a single place for the failure handling above to cover.
SELF_UID="$(id -u)"

# Phase 1: outside the namespace. Re-enter as root in a fresh network namespace,
# carrying the caller's identity and the environment the toolchain needs. `sudo
# env VAR=...` is used rather than `sudo -E` because preserving the whole
# environment needs a sudoers SETENV grant that is not guaranteed, while `env` is
# just the command sudo was asked to run.
if [ "${AKA_NO_NETWORK_INSIDE:-}" != "1" ]; then
  # Refuse rather than run weakened. See "WHY IT DROPS BACK TO THE CALLER": as
  # root the drop-back below is a no-op, and the read-only-store cases skip
  # instead of asserting. That is a quieter suite still reporting green, so it
  # fails here and there is deliberately no override.
  if [ "$SELF_UID" -eq 0 ]; then
    echo "no-network: FAILED — started as root. This script elevates itself; running" >&2
    echo "no-network: it as root leaves no unprivileged identity to drop back to, and" >&2
    echo "no-network: the read-only-store cases in packages/persistence would skip" >&2
    echo "no-network: rather than assert. Run it as the unprivileged user." >&2
    exit 2
  fi
  exec sudo env \
    AKA_NO_NETWORK_INSIDE=1 \
    "AKA_NO_NETWORK_UID=$SELF_UID" \
    "AKA_NO_NETWORK_GID=$(id -g)" \
    "PATH=$PATH" \
    "HOME=$HOME" \
    CI=1 \
    DO_NOT_TRACK=1 \
    TURBO_TELEMETRY_DISABLED=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    TURBO_NO_UPDATE_NOTIFIER=1 \
    NO_UPDATE_NOTIFIER=1 \
    unshare --net -- "$0" "$@"
fi

# Phase 2: inside the namespace, as root. A fresh namespace has a loopback
# interface but leaves it DOWN, and the suite genuinely uses loopback (the CLI's
# isPortFree bind probe, the dashboard boot test). Bring it up, then drop back to
# the caller and re-enter this script one last time.
if [ "$SELF_UID" -eq 0 ] && [ "${AKA_NO_NETWORK_DROPPED:-}" != "1" ]; then
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
# THE PRIVILEGE CONTROL, which is the other half of the positive control below
# and guards a quieter failure. Phase 2 drops back to the caller because root
# ignores the 0444 mode `fault-injection.ts` builds a read-only store with, so
# the read-only cases in packages/persistence would report `effective: false`
# and SKIP. A skip is not a failure: the suite would still report green, with
# those cases silently uncovered. That hazard is why this script refuses to
# START as root — but the refusal only guards the front door. Nothing checked
# that the drop-back actually landed, so a `setpriv` that stopped working, or a
# future edit to phase 2, would be invisible: green run, quieter suite, no
# signal anywhere. Assert it instead of assuming it. Cheap, and it converts the
# one silent failure on this path into a loud one.
if [ "$SELF_UID" -eq 0 ]; then
  echo "no-network: FAILED — still root at the point the command runs, so the" >&2
  echo "no-network: privilege drop-back did not happen. The read-only-store cases" >&2
  echo "no-network: in packages/persistence would report 'effective: false' and" >&2
  echo "no-network: skip, and the run would report green having quietly lost them." >&2
  exit 1
fi

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
for tool in getent node; do
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

# The TCP half. 1.1.1.1:443 is a literal, so it needs no DNS. The probe proves
# its own mechanism against a loopback listener before trusting a failure, and
# reports BROKEN rather than "blocked" when that does not work — so a probe that
# cannot connect to anything can never be read as an absent network. It also
# subsumes the loopback check this used to make by grepping `ip addr`: a real
# bind-and-connect is the property the suite depends on, where a matching line of
# `ip` output was only a proxy for it. See egress-probe.mjs.
probe="${0%/*}/egress-probe.mjs"
if [ ! -f "$probe" ]; then
  echo "no-network: FAILED — the egress probe is missing at $probe, so the TCP" >&2
  echo "no-network: half of the control cannot run." >&2
  exit 1
fi

probe_status=0
node "$probe" 1.1.1.1 443 || probe_status=$?
case "$probe_status" in
0) ;;
1)
  echo "no-network: FAILED — a TCP connection to 1.1.1.1:443 succeeded." >&2
  echo "no-network: the suite would have passed without proving anything." >&2
  exit 1
  ;;
*)
  echo "no-network: FAILED — the egress probe could not run (exit $probe_status), so" >&2
  echo "no-network: it cannot show the network is gone. Its own output is above." >&2
  exit 1
  ;;
esac

echo "no-network: egress is blocked, loopback is up — running: $*"
exec "$@"
