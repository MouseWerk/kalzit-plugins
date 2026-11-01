# Kalzit plugins

The registry of community plugins for [Kalzit](https://github.com/MouseWerk/Kalzit) and the
source of the signed plugin catalog that Kalzit reads.

**Catalog address for Kalzit:** `https://mousewerk.github.io/kalzit-plugins/catalog.json`
(Administration, Plugins, Catalog). The signature is next to it at the same address with `.sig`
appended.

- Submitting a plugin: [CONTRIBUTING.md](CONTRIBUTING.md).
- Plugins stay in their authors' repositories; `plugins/<id>/plugin.toml` points at their releases.
- Review and signing happen before a plugin appears: CI checks every package without running it,
  the owner approves the pull request, and the catalog is signed in the protected
  `catalog-signing` environment after the owner approves the run.
- Revocations in [revocations.toml](revocations.toml) go into the signed catalog and reach every
  installation that reads it.

## Layout

| Path | |
|---|---|
| `plugins/<id>/plugin.toml` | One plugin: texts, category, permissions, screenshots and its versions with release URL, SHA-256, size and key id. |
| `publishers/<name>.pub` | A publisher's Ed25519 public key, base64. |
| `revocations.toml` | Withdrawn versions. |
| `keys/catalog.pub` | The public key of the catalog signing key. |
| `tools/registry` | `kalzit-registry`: the checks and the catalog build, with Kalzit's own plugin crates. |
| `signer` | `kalzit-catalog-signer`: the only code built next to the catalog key. |
| `.github/workflows/ci.yml` | Checks for every pull request, read-only and without secrets. |
| `.github/workflows/publish.yml` | Builds, signs and publishes the catalog from main to GitHub Pages. |

## What is published

On GitHub Pages, from main after each merge and twice a month (an index is valid for 30 days):

- `catalog.json` and `catalog.json.sig`: the index in Kalzit's catalog format 1, signed in
  Kalzit's catalog context;
- `store.json`: the store data the Kalzit website builds its plugin pages from;
- `screenshots/<id>/...` and `publishers/<name>.pub`.

License: AGPL-3.0-only.
