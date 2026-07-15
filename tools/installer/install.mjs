#!/usr/bin/env node
// AKA bootstrap installer — the single Node codepath both directions share.
//
//   node install.mjs                       → install the global `aka` CLI
//   node install.mjs --plugin claude-code  → install an agent plugin
//
// The shell entrypoints (install.sh / install.ps1) only ensure Node is present
// and then hand off here. Plugin onboarding (the claude-code `/aka:setup` opt-in)
// invokes this to add the CLI; the CLI's `aka plugins install` invokes it to add
// plugins — one real installer, reused both ways.
//
// Packages install from the public npm registry — no auth, no registry override.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

const SCOPE = '@akasecurity';
const CLI_PACKAGE = `${SCOPE}/cli`;

// Agent plugins installable as npm globals. Claude Code is distributed through the
// Claude Code plugin marketplace, NOT npm, so it is intentionally absent here —
// `--plugin claude-code` prints the marketplace path instead.
const NPM_PLUGIN_PACKAGES = {
  // cursor: `${SCOPE}/plugin-cursor`,  // when it ships
};

const log = (m) => process.stdout.write(`aka: ${m}\n`);
function fail(m) {
  process.stderr.write(`aka: ${m}\n`);
  process.exit(1);
}

// Minimum Node major the CLI runs on. Must match the `engines.node` floor that
// @akasecurity/cli publishes, and the Node version the shell entrypoints name.
const MIN_NODE_MAJOR = 24;

function requireNode() {
  const major = Number(process.versions.node.split('.')[0]);
  if (Number.isNaN(major) || major < MIN_NODE_MAJOR) {
    fail(
      `Node ${MIN_NODE_MAJOR}+ is required (found ${process.versions.node}). Install it from https://nodejs.org and re-run.`,
    );
  }
}

// Drop a stale `@akasecurity → npm.pkg.github.com` scope mapping from ~/.npmrc if
// one is present (earlier installer releases wrote it). The packages live on the
// public npm registry, so a leftover GitHub Packages mapping makes
// `npm i -g @akasecurity/cli` fail with a 401. Only the scope line this installer
// owns is touched — auth-token lines and every other line are left exactly as-is,
// since they may serve the user's other registries.
function cleanupLegacyNpmrc() {
  const npmrc = join(homedir(), '.npmrc');
  if (!existsSync(npmrc)) return;
  const existing = readFileSync(npmrc, 'utf8');
  const legacyScopeLine = `${SCOPE}:registry=https://npm.pkg.github.com`;

  const kept = existing.split('\n').filter((line) => line.trim() !== legacyScopeLine);
  const next = kept.join('\n');
  if (next !== existing) {
    writeFileSync(npmrc, next);
    log(
      `Removed a stale ${SCOPE} registry override from ${npmrc} (packages install from the public npm registry).`,
    );
  }
}

function npmInstallGlobal(pkg) {
  log(`Installing ${pkg} globally…`);
  execFileSync('npm', ['install', '-g', pkg], { stdio: 'inherit' });
}

function installCli() {
  npmInstallGlobal(CLI_PACKAGE);
  log('✓ Installed the AKA CLI. Run `aka init` to set up your local store.');
}

function installPlugin(id) {
  if (id === 'claude-code') {
    log('Claude Code is installed from the Claude Code plugin marketplace, not npm.');
    log('With the CLI installed, `aka plugins install claude-code` does it end-to-end;');
    log('or add the AKA marketplace in Claude Code manually, then run `aka init`.');
    return;
  }
  const pkg = NPM_PLUGIN_PACKAGES[id];
  if (!pkg) {
    fail(`Unknown or not-yet-available plugin '${id}'. Try the CLI: \`aka plugins list\`.`);
  }
  npmInstallGlobal(pkg);
  log(`✓ Installed the ${id} plugin.`);
}

function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: { plugin: { type: 'string' }, cli: { type: 'boolean' } },
  });
  requireNode();
  cleanupLegacyNpmrc();
  if (values.plugin) {
    installPlugin(values.plugin);
  } else {
    installCli();
  }
}

main();
