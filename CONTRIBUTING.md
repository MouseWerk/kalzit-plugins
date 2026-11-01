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
publishers/<name>.toml              once: the names your plugins may show as author
```

`publishers/<name>.toml`:

```toml
authors = ["Your Name"]
```

`plugins/<id>/plugin.toml`:

```toml
id = "io.github.yourname.redis"      # equals the directory name and the package's id
name = "Redis"                       # equals the package's name, at most 64 characters
kind = "datasource"                  # datasource or panel, as in the package
category = "databases"               # databases, metrics-and-logs, files-and-apis, visualization, utilities
publisher = "yourname"               # publishers/yourname.pub
author = "Your Name"                 # shown as the publisher; one of the authors in publishers/yourname.toml
source = "https://github.com/yourname/kalzit-redis"   # the repository the release assets belong to
license = "MIT"
homepage = "https://github.com/yourname/kalzit-redis#readme"   # optional

[description]                        # one line each, at most 280 characters
en = "Keys and streams of Redis as frames."
de = "Schlüssel und Streams aus Redis als Tabellen."             # optional

[[screenshots]]                      # optional
file = "screenshots/query.webp"
alt = { en = "A query of a Redis stream in Explore.", de = "Eine Abfrage eines Redis-Streams in Explore." }

[[versions]]                         # oldest first; add new versions at the end
version = "1.0.0"                    # equals the package's version
released = "2026-11-01"
# A release asset of `source`: the address starts with <source>/releases/download/.
url = "https://github.com/yourname/kalzit-redis/releases/download/v1.0.0/io.github.yourname.redis-1.0.0.zip"
sha256 = "<64 lowercase hex digits of the package file>"
size = 1840000                       # the package file's size in bytes
key_id = "<16 hex digits>"           # the key id of your publisher key, as kalzit-plugin keygen prints it
# The network targets this version declares, in the words Kalzit's catalog uses: "host:port" for a
# fixed host, "*:port" for a host from the settings with a default port, "*" for any other target
# from the settings. Exactly the package's targets, lowercase; a new version may change them.
# Panels have none: they run in a sandboxed frame without network access.
network = ["*:6379"]
```

Compute the hash and size of the package file with `sha256sum` and `stat -c %s` (or
`Get-FileHash` and `(Get-Item file).Length` on Windows).

## What CI checks

- The manifest's schema and texts, the category, unique ids, that the author belongs to the
  publisher, that every `url` is a release asset of `source`, and that nothing in the plugin's
  directory is unlisted or a link.
- Every version that is new: the package downloaded from `url` has exactly `size` bytes and `sha256`, is a
  valid Kalzit package (paths, files and hashes as Kalzit checks them), is signed with your
  publisher key, and its id, version, kind and name match the entry. The listed network targets
  must equal the package's targets, and fixed hosts must not be private or loopback addresses,
  which Kalzit refuses. A panel bundle must be one Kalzit can serve.
- Against main: published versions never change and new versions are higher than all published
  ones; a published key, publisher, kind or revocation never changes, and a published plugin is
  not removed. A rotation entry in `keys/rotations.toml` comes only with the key change it
  records. Every `url` has no query, fragment, `.` or `..` segment (also percent-encoded), and an
  author name belongs to one publisher only.
- The catalog built from the registry is one Kalzit takes. A preview of it is attached to the CI
  run as the artifact `catalog-preview` (unsigned).

**Owner attention.** The Review workflow runs on every pull request from main's own workflow file
(`pull_request_target`) and with main's own registry tool, built from main and reading the pull
request's files as data only, so a pull request cannot hide its flags by changing `tools/` or
`.github/`. It flags, in the run summary and as annotations:

- every change under `.github/`, `tools/`, `signer/`, `keys/`, `publishers/` or
  `revocations.toml`, unconditionally;
- changes of the name, author, source or homepage of a published plugin, new publishers, changed
  author lists and key rotations, as main's tool finds them; when the pull request changes the
  tool or the formats so that main's tool cannot read it, that is flagged too.

The registry has a single maintainer, so code owner reviews are not required (nobody could
approve the owner's own pull requests). The unconditional flags and the owner's review of every
pull request before merging take their place; CODEOWNERS still requests that review.

Packages are checked once. A version is downloaded and checked when it is new: not listed with
the same address, hash, size, key, name and network targets in the catalog published last (whose
signature is checked with the catalog key first). Versions it lists keep their recorded SHA-256
and size and are not downloaded again, and revoked versions are never downloaded. The trade-off:
a release asset that is deleted or replaced after its version was published no longer stops
every publish (and so cannot let the catalog expire), but the registry does not notice it either.
That stays safe, because Kalzit checks the SHA-256 and the signature of every package it downloads
from the catalog and refuses one that differs; such a version simply fails to install until it is
revoked. A version that is changed in the registry is checked again.

To check locally before you open the pull request (needs Rust):

```sh
cargo build --release --manifest-path tools/registry/Cargo.toml
tools/registry/target/release/kalzit-registry fetch-list   # without --previous: every version that is not revoked
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

Once `keys/catalog.pub` exists, CI refuses a pull request that changes or removes it, with one
exception, a rotation (after a suspected leak, or on schedule):

1. Create the new key as above and store it as `KALZIT_CATALOG_SIGNING_KEY` (this replaces the
   old secret; publishing pauses until step 2 is merged).
2. In one pull request, replace `keys/catalog.pub` with the new public key and append to
   `keys/rotations.toml`:

   ```toml
   [[rotation]]
   from = "<old public key, base64>"
   to = "<new public key, base64>"
   date = "2026-11-01"
   reason = "Scheduled rotation."
   ```

   CI accepts the change only with exactly this new entry and marks it for the owner. Recorded
   rotations are never changed or removed, and no entry is added without a key change. The old
   key is still accepted for the published catalog (as the record of checked packages) only for an
   index published before the end of the rotation's `date`; after that, an index signed with it
   counts as no record, and every version is checked again.
3. Every Kalzit that reads the catalog has pinned the old key for its address: administrators add
   and allow the new key, then confirm the key change when Kalzit refreshes the catalog. After a
   leak, also take back the old key there.
