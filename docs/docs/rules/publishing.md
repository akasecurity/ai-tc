# Publishing rules

Detection rules are versioned, attributed, and distributed as **rule packs**. The
built-in packs live in this repository under `rules/`, and new first-party detections
are contributed the same way any other change is: **as a pull request to `rules/`**.

## Packs are the unit of publishing

A pack is a directory with a `manifest.json`, its rule files, and mandatory fixtures
(see [Writing Rules](writing-rules.md)). The `version` in `manifest.json` is a semver
string and is the unit of publishing: each published `(pack, version)` is **immutable**,
so editing a rule means bumping `version` in its pack's `manifest.json`.

## Contributing a rule

1. Add or edit the rule and its fixtures under `rules/<pack>/`.
2. Bump `version` in the pack's `manifest.json`.
3. Open a pull request.

CI runs the detection fixtures — the correctness gate — and validates every pack's
structure on the PR. **A pack whose fixtures fail is never merged.** You can run the
same checks locally:

```bash
pnpm test --filter @akasecurity/detections
```

## From merge to release

Once a rule PR merges, the maintainers verify the change and ship it: the packs under
`rules/` are bundled into the next CLI and plugin releases at build time, under the
`aka` namespace (the `aka/<pack>` slugs you see in `aka detections`). Contributors do
not run any publisher themselves — merging to `rules/` is the whole contribution flow.

## Getting updated packs

Upgrading the CLI or plugin records what's newly available, but never silently changes
what scans: installed packs are snapshotted into the local store, the plugin scans with
the installed snapshot, and updates are applied manually (`aka detections update` or
the dashboard's **Update** button), never automatically — see
[Managing detection packs](../getting-started/cli.md#manage-detection-packs).
