#!/usr/bin/env bash
#
# Install the packed CLI tarball and exercise it, with every outbound path gone.
#
#   tools/ci/no-network-test.sh tools/ci/packaged-cli-egress.sh "$workdir"
#
# WHY THIS EXISTS, when three gates already stand behind the local-only claim:
# none of them reaches a published tarball. The lint ban reads source text in the
# workspace, and the tarball is a build output no lint pass targets. The vitest
# guard patches transports inside a worker, and nothing loads the tarball into
# one. The namespace job covers every process the SUITE starts, and the suite
# never installs the tarball. All three observe either source text or an executed
# call, so an artifact nothing executes sits outside all of them — and the
# bundling step is exactly where a dependency can arrive that the workspace
# source does not carry.
#
# WHY THE INSTALL HAPPENS HERE RATHER THAN IN THE CALLER. Installing inside the
# namespace covers the artifact's INSTALL-time behaviour as well as its runtime:
# a lifecycle script anywhere in the dependency graph runs during `npm ci`, and
# outside the namespace it would run with a route off the host. The caller's
# prepare step resolves that graph and fills npm's cache while a route still
# exists — the same bargain the namespace job already makes with `pnpm install` —
# and leaves package.json + package-lock.json behind for this to install from.
# `npm ci` runs WITHOUT `--offline` deliberately: offline makes npm refuse before
# it tries, where a plain install genuinely attempts the connection and lets the
# namespace be the thing that stops it.
#
# WHAT MAKES IT NON-VACUOUS. `no-network-test.sh` proves the block is real before
# this file runs at all, so that half is not repeated here. The control this file
# owns is the opposite one: a scan that examined nothing exits 0 and reports no
# findings, which is byte-for-byte the shape of a clean run. So the seeded value
# is taken from the detection rule's own fixture, and the run FAILS unless that
# rule fires on it — the same reason the fault injectors elsewhere in this repo
# refuse to take effect vacuously.
#
# Linux only in practice, because its wrapper is: this is the CI leg's mechanism,
# not a developer workflow. Every refusal below is driven with hand-written stubs
# by packages/eslint-config/test/packaged-cli-egress.test.js.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <workdir>" >&2
  echo "  <workdir> is the directory the prepare step left package.json and" >&2
  echo "  package-lock.json in, describing an install of the packed tarball." >&2
  exit 2
fi

work="$1"
repo_root="${0%/*}/../.."

# This file ends by claiming egress was blocked, and it does not establish that
# itself: `no-network-test.sh` does, with a DNS probe and a TCP probe, before it
# execs anything. Duplicating those here would be a second copy of a control that
# already exists; refusing to make the claim without them is the cheaper half.
#
# Run bare, every check below passes with a full route off the host — the install
# succeeds, the scan finds its seeded value, the dashboard answers — and the leg
# reports a guarantee nothing verified. That is the same shape the wrapper's own
# probes exist to prevent, reached one level out, so there is deliberately no
# override. `AKA_NO_NETWORK_INSIDE` is the wrapper's own phase marker, set before
# it re-enters the namespace and inherited through the drop back to the caller.
if [ "${AKA_NO_NETWORK_INSIDE:-}" != "1" ]; then
  echo "packaged-cli: FAILED — this has to run under tools/ci/no-network-test.sh," >&2
  echo "packaged-cli: which proves egress is really gone before handing over. Run" >&2
  echo "packaged-cli: bare, every check below passes with a full network route and" >&2
  echo "packaged-cli: this reports a guarantee nothing established." >&2
  exit 2
fi

# The rule this leg asserts on. Named here rather than inline so the fixture the
# seed is built from and the id the control looks for cannot drift apart.
rule_id='secrets/aws-access-key'
port=4319

# Demand the tooling first. A step whose own tool is missing fails in a way that
# reads like the thing it was checking — `npm` absent looks like a broken
# artifact, `curl` absent looks like a dashboard that never came up — so each one
# is named before anything runs.
for tool in node npm curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "packaged-cli: FAILED — '$tool' is not installed, so this leg cannot run" >&2
    echo "packaged-cli: and would report on nothing." >&2
    exit 1
  fi
done

# Validate the workdir before anything derives a path from it. Everything below
# builds `$work/...` and one of those lines is an `rm -rf`, so an empty argument
# would aim it at `/home`, `/seed` and `/scan.json`. `$#` is 1 for an empty
# string, so the usage check above does not catch it — and the workflow reaches
# exactly that shape if the prepare step ever stops exporting its path. Ordering
# is not a defence: the checks below happen to exit first today, which is luck
# rather than a guarantee.
if [ -z "$work" ] || [ ! -d "$work" ]; then
  echo "packaged-cli: FAILED — '$work' is not a directory. The prepare step" >&2
  echo "packaged-cli: creates it, packs the tarball into its parent, and exports" >&2
  echo "packaged-cli: the path; an empty value here usually means that export was" >&2
  echo "packaged-cli: renamed or never ran." >&2
  exit 2
fi

for f in package.json package-lock.json; do
  if [ ! -f "$work/$f" ]; then
    echo "packaged-cli: FAILED — $work/$f is missing, so there is no packed" >&2
    echo "packaged-cli: install to verify. The prepare step packs the tarball and" >&2
    echo "packaged-cli: resolves its dependency graph while a network route still" >&2
    echo "packaged-cli: exists; it has to run before this one." >&2
    exit 2
  fi
done

# The seeded value comes from the rule's own fixtures rather than being written
# out here. A hand-written literal drifts from the pattern it is meant to match,
# and a seed the rule no longer fires on turns the control below into a test of
# nothing — it would report "no findings" exactly as a clean scan does. Reading
# the fixture is also what keeps a secret-shaped literal out of this public tree.
fixture="$repo_root/rules/secrets/fixtures/aws-access-key.json"
if [ ! -f "$fixture" ]; then
  echo "packaged-cli: FAILED — the rule fixture is missing at $fixture, so the" >&2
  echo "packaged-cli: seeded scan below cannot be built from the rule it asserts on." >&2
  exit 1
fi

seed_text=$(node -e '
  const { readFileSync } = require("node:fs");
  const examples = JSON.parse(readFileSync(process.argv[1], "utf8"));
  const hit = Array.isArray(examples) && examples.find((e) => e && e.shouldMatch === true);
  if (!hit || typeof hit.text !== "string" || hit.text === "") {
    console.error("packaged-cli: the fixture carries no positive example to seed with.");
    process.exit(1);
  }
  process.stdout.write(hit.text);
' "$fixture")

home="$work/home"
seed="$work/seed"
scan_json="$work/scan.json"
rm -rf "$home" "$seed" "$scan_json"
mkdir -p "$seed"
printf '%s\n' "$seed_text" >"$seed/credentials.txt"

echo "packaged-cli: installing the packed tarball with no route off this host"
if ! (cd "$work" && npm ci --no-audit --no-fund --fetch-retries=0 --fetch-timeout=15000); then
  echo "packaged-cli: FAILED — installing the packed tarball needed the network." >&2
  echo "packaged-cli: Either something in the artifact's dependency graph reached" >&2
  echo "packaged-cli: out while installing, or the prepare step left that package" >&2
  echo "packaged-cli: out of npm's cache. npm's own output is above." >&2
  exit 1
fi

bin="$work/node_modules/.bin/aka"
if [ ! -x "$bin" ]; then
  echo "packaged-cli: FAILED — the aka bin is missing from the installed tarball," >&2
  echo "packaged-cli: so nothing below would have exercised the packaged artifact." >&2
  exit 1
fi

echo "packaged-cli: aka init"
if ! "$bin" init --home "$home"; then
  echo "packaged-cli: FAILED — 'aka init' did not succeed with egress blocked." >&2
  exit 1
fi

echo "packaged-cli: aka scan"
if ! "$bin" scan "$seed" --home "$home" --format json >"$scan_json"; then
  echo "packaged-cli: FAILED — 'aka scan' did not succeed with egress blocked." >&2
  exit 1
fi

# The control. Exiting 0 having scanned nothing is indistinguishable from exiting
# 0 having scanned a clean tree, so the seeded rule must actually have fired.
# The second half is the privacy property the artifact exists to hold: findings
# carry the masked value, never the raw one.
if ! node -e '
  const { readFileSync } = require("node:fs");
  const [file, ruleId, raw] = process.argv.slice(1);

  let report;
  try {
    report = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    console.error(`packaged-cli: the scan report is not JSON: ${err.message}`);
    process.exit(1);
  }

  const findings = Array.isArray(report.findings) ? report.findings : [];
  if (!findings.some((f) => f && f.ruleId === ruleId)) {
    console.error(
      `packaged-cli: the packaged scan did not report ${ruleId} on the seeded file. ` +
        "A scan that examined nothing reports exactly this, so the leg is treated " +
        "as having proved nothing rather than as clean.",
    );
    console.error(
      `packaged-cli: rules that did fire: ${JSON.stringify(findings.map((f) => f && f.ruleId))}`,
    );
    process.exit(1);
  }

  // Every string in the report, keys included, walked rather than matched
  // against the file bytes: JSON escapes a quote, so a raw value carrying one
  // would slip a substring check over the raw text while still being perfectly
  // readable to anyone holding the file.
  const strings = [];
  const walk = (node) => {
    if (typeof node === "string") {
      strings.push(node);
    } else if (Array.isArray(node)) {
      node.forEach(walk);
    } else if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node)) {
        strings.push(key);
        walk(value);
      }
    }
  };
  walk(report);
  const haystack = strings.join(" ");

  // The window runs over the SECRET, not over the whole seeded line. The fixture
  // is a line of code — `const key = "\u2026"` — and an eight-character window over
  // ordinary code text collides with output carrying no secret at all, which
  // reddens this leg for a leak that did not happen. Drive it with the
  // high-entropy run instead, which is the part that must never appear anywhere.
  const token =
    (raw.match(/[A-Za-z0-9_\-+/=]{16,}/g) ?? []).sort((a, b) => b.length - a.length)[0] ?? raw;

  // A RUN of that value rather than all of it, the same eight characters the
  // suites use: a report that echoed a truncated secret has disclosed one, and a
  // whole-value check stays green on it.
  const ECHO_RUN = 8;
  const windows =
    token.length < ECHO_RUN
      ? [token]
      : Array.from({ length: token.length - ECHO_RUN + 1 }, (_, i) =>
          token.slice(i, i + ECHO_RUN),
        );
  if (windows.some((w) => haystack.includes(w))) {
    console.error("packaged-cli: the scan report echoed the raw seeded value.");
    process.exit(1);
  }
' "$scan_json" "$rule_id" "$seed_text"; then
  exit 1
fi

# The bundled dashboard is the largest thing the packaging step adds — it is a
# whole Next standalone server, with a dependency graph the workspace source
# does not carry — so it is booted here rather than only at release. Loopback is
# up inside the namespace, and everything else is gone.
server="$work/node_modules/@akasecurity/cli/web-ui/web-ui/server.js"
if [ ! -f "$server" ]; then
  echo "packaged-cli: FAILED — the bundled standalone server is missing at" >&2
  echo "packaged-cli: $server, so the tarball ships no working dashboard." >&2
  exit 1
fi

echo "packaged-cli: booting the bundled dashboard"
PORT="$port" HOSTNAME=127.0.0.1 node "$server" &
srv=$!
# Reap it however this exits, including on the failure path below: a server left
# holding the port turns the next run's boot into a mystery.
trap 'kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true' EXIT

ok=0
attempt=0
# Counted with shell arithmetic rather than `seq`, which is not POSIX and is one
# more thing that has to be on PATH for this loop to mean anything.
while [ "$attempt" -lt 30 ]; do
  attempt=$((attempt + 1))
  if curl -fsS "http://127.0.0.1:$port/security" >/dev/null 2>&1; then
    ok=1
    break
  fi
  # A server that died is never going to answer, so stop waiting out the full
  # window for it — the failure below should read as "it crashed", not "it was
  # slow".
  kill -0 "$srv" 2>/dev/null || break
  sleep 2
done

if [ "$ok" != 1 ]; then
  echo "packaged-cli: FAILED — the bundled dashboard did not serve /security with" >&2
  echo "packaged-cli: egress blocked. Either it is broken, or it depends on" >&2
  echo "packaged-cli: reaching something off this host to come up." >&2
  exit 1
fi

echo "packaged-cli: the packaged CLI installs, scans and serves the dashboard with egress blocked"
