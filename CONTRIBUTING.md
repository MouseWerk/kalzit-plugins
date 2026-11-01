# Submitting a plugin

This repository is the registry of community plugins for
[Kalzit](https://github.com/MouseWerk/Kalzit). Every plugin in it is listed in the signed catalog
that Kalzit reads and in the plugin store on the Kalzit website. A plugin stays in your own
repository: the registry only points at its releases.

How a plugin gets in:

1. You build and sign a package in your own repository and attach it to a release there.
2. You open a pull request here with a small manifest that points at that release.
3. CI downloads the package and checks it: its SHA-256 and size, its signature with your
   publisher key, its manifest, and that the permissions you list are exactly the ones the package
   declares. CI never runs plugin code.
4. The owner reviews the pull request. Merging it publishes the plugin: the catalog is built,
   signed in a protected environment after the owner's approval, and published.

## Before you start

- Read [docs/plugins/authoring.md](https://github.com/MouseWerk/Kalzit/blob/main/docs/plugins/authoring.md)
  in the Kalzit repository: how to write a data source or panel plugin and how to package it with
  `kalzit-plugin`.
- Pick an id in reverse domain notation of a domain or account you control, such as
  `io.github.yourname.redis`. Ids under `io.kalzit.` and `dev.kalzit.` belong to Kalzit.
- Create your publisher key once and keep the private half secret:
  `kalzit-plugin keygen --out publisher.key` (it prints the public key). Sign every package with
  it: `kalzit-plugin package ... --key-file publisher.key`, and check the result with `kalzit-plugin verify --package <zip> --public-key <your public key>`. Store the private key like any release
  secret, for example in a protected environment of your repository.

## What the pull request contains

```text
plugins/<id>/plugin.toml            the manifest below
plugins/<id>/screenshots/<file>     optional, up to 8 png, webp or jpg files of at most 1 MiB
publishers/<name>.pub               your public key, once: one line, base64 (44 characters)
```

`plugins/<id>/plugin.toml`:

```toml
id = "io.github.yourname.redis"      # equals the directory name and the package's id
name = "Redis"                       # equals the package's name, at most 64 characters
kind = "datasource"                  # datasource or panel, as in the package
category = "databases"               # databases, metrics-and-logs, files-and-apis, visualization, utilities
publisher = "yourname"               # publishers/yourname.pub
author = "Your Name"                 # shown as the publisher, at most 64 characters
source = "https://github.com/yourname/kalzit-redis"
license = "MIT"
homepage = "https://github.com/yourname/kalzit-redis#readme"   # optional

[description]                        # one line each, at most 280 characters
en = "Keys and streams of Redis as frames."
de = "Schlüssel und Streams aus Redis als Tabellen."             # optional

[permissions]
# The network targets the package declares, in the words Kalzit's catalog uses: "host:port" for a
# fixed host, "*:port" for a host from the settings with a default port, "*" for any other target
# from the settings. Exactly the package's targets, lowercase. Panels have none: they run in a
# sandboxed frame without network access.
network = ["*:6379"]

[[screenshots]]                      # optional
file = "screenshots/query.webp"
alt = { en = "A query of a Redis stream in Explore.", de = "Eine Abfrage eines Redis-Streams in Explore." }

[[versions]]                         # oldest first; add new versions at the end
version = "1.0.0"                    # equals the package's version
released = "2026-11-01"
url = "https://github.com/yourname/kalzit-redis/releases/download/v1.0.0/io.github.yourname.redis-1.0.0.zip"
sha256 = "<64 lowercase hex digits of the package file>"
size = 1840000                       # the package file's size in bytes
key_id = "<16 hex digits>"           # the key id of your publisher key, as kalzit-plugin keygen prints it
```

Compute the hash and size of the package file with `sha256sum` and `stat -c %s` (or
`Get-FileHash` and `(Get-Item file).Length` on Windows).

## What CI checks

- The manifest's schema and texts, the category, unique ids, and that nothing in the plugin's
  directory is unlisted.
- Every version: the package downloaded from `url` has exactly `size` bytes and `sha256`, is a
  valid Kalzit package (paths, files and hashes as Kalzit checks them), is signed with your
  publisher key, and its id, version, kind and name match the entry. The listed network targets
  must equal the package's targets, and fixed hosts must not be private or loopback addresses,
  which Kalzit refuses. A panel bundle must be one Kalzit can serve.
- Against main: published versions never change and new versions are higher than all published
  ones; a published key, publisher, kind or revocation never changes, and a published plugin is
  not removed.
- The catalog built from the registry is one Kalzit takes. A preview of it is attached to the CI
  run as the artifact `catalog-preview` (unsigned).

To check locally before you open the pull request (needs Rust):

```sh
cargo build --release --manifest-path tools/registry/Cargo.toml
tools/registry/target/release/kalzit-registry fetch-list
# download each listed package into packages/<sha256>, then:
tools/registry/target/release/kalzit-registry check --packages packages
```

## Updates, key changes and revocations

- A new version: add a `[[versions]]` entry at the end in a new pull request.
- Plugins stay bound to the key that signed them (Kalzit refuses an update signed by another key).
  A key change needs a hand-over signed by the old key; open an issue first.
- A version with a vulnerability, or every version after a leaked key, is withdrawn in
  `revocations.toml`. Kalzit refuses to install revoked versions from the catalog and shows the
  revocation on installed plugins. Report security problems privately to the owner.

## Catalog key (owner)

The catalog is signed with an Ed25519 key of its own, which exists only in the `catalog-signing`
environment of this repository. Only the owner creates and handles it.

1. Create the key on a trusted machine with `kalzit-sign` from a checkout of MouseWerk/Kalzit
   (the same tool and format as the release key: 32 bytes in base64 in a file only you can read):

   ```sh
   cargo run --release -p kalzit-release --bin kalzit-sign -- keygen --out catalog-signing.key
   ```

   It prints the public key and its key id (the hint about the release secret does not apply here).
2. Store it straight from the file as the environment secret:

   ```sh
   gh secret set KALZIT_CATALOG_SIGNING_KEY --env catalog-signing --repo MouseWerk/kalzit-plugins < catalog-signing.key
   ```

   Keep an encrypted offline copy, then delete the file.
3. Add the public key (the base64 line `keygen` printed) as `keys/catalog.pub` in a pull request.
   The signing job refuses a secret that does not belong to this key.
4. In Kalzit: Administration, Plugins, Signature and trust, Add key with this public key (check
   the key id), then Allow for the catalog. In the Catalog tab enter
   `https://mousewerk.github.io/kalzit-plugins/catalog.json` as the address, switch it on and load
   it. Kalzit's own plugins (`dev.kalzit.*`) are signed with Kalzit's compiled plugin key; a
   community plugin installs once its publisher key from `publishers/` is trusted the same way.
