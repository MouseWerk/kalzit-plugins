//! `kalzit-registry`, the checks and the catalog build of the plugin registry.
//!
//! ```text
//! kalzit-registry fetch-list [--root .] [--base <dir>] [--all]
//! kalzit-registry check [--root .] [--base <dir>] [--packages <dir>] [--all]
//! kalzit-registry build [--root .] --packages <dir> --out <dir> --site-url <https url> [--now <unix secs>]
//! kalzit-registry verify-catalog --index <file> --signature <file> --public-key-file <file> [--now <unix secs>]
//! ```
//!
//! `fetch-list` prints `<sha256> <size> <url>` per package to download: the versions that are new
//! against `--base` (a checkout of main), or all with `--all` or without a base. `check` checks the
//! registry files, the rules against the base, and every package of those versions, read from
//! `<packages>/<sha256>`. `build` checks everything and writes the catalog index, the store data,
//! the screenshots and the publisher keys into `--out`. `verify-catalog` checks a signed index the
//! way Kalzit does before the site is published.

mod package;
mod registry;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Signature;
use kalzit_plugin_api::catalog::{self, Accepted, CatalogEntry, CatalogIndex, Revocation};
use kalzit_plugin_api::signing;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::registry::{CATEGORIES, Problems, Registry};

/// How long a published index stays valid. Kalzit takes at most 31 days; the publish workflow
/// runs at least twice a month, so a missed run leaves time.
const VALIDITY_SECS: u64 = 30 * 24 * 3600;

const REGISTRY_URL: &str = "https://github.com/MouseWerk/kalzit-plugins";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    pairs: Vec<(String, String)>,
    flags: BTreeSet<String>,
}

impl Options {
    fn parse(args: &[String], values: &[&str], flags: &[&str]) -> Result<Options, String> {
        let mut o = Options { pairs: Vec::new(), flags: BTreeSet::new() };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let name = arg.strip_prefix("--").ok_or_else(|| format!("unexpected argument {arg}"))?;
            if flags.contains(&name) {
                o.flags.insert(name.to_string());
            } else if values.contains(&name) {
                let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                o.pairs.push((name.to_string(), value.clone()));
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(o)
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name).ok_or_else(|| format!("--{name} is required"))
    }
    fn root(&self) -> PathBuf {
        PathBuf::from(self.get("root").unwrap_or("."))
    }
    fn now(&self) -> Result<u64, String> {
        match self.get("now") {
            Some(n) => n.parse().map_err(|_| "--now is Unix seconds".to_string()),
            None => Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs()),
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: kalzit-registry fetch-list|check|build|verify-catalog ...";
    let (command, rest) = args.split_first().ok_or(usage)?;
    match command.as_str() {
        "fetch-list" => {
            let o = Options::parse(rest, &["root", "base"], &["all"])?;
            let (registry, versions) = load_checked(&o)?;
            for (id, version) in versions {
                let (_, v) = registry.version(&id, &version).expect("listed");
                println!("{} {} {}", v.sha256, v.size, v.url);
            }
            Ok(())
        }
        "check" => {
            let o = Options::parse(rest, &["root", "base", "packages"], &["all"])?;
            let (registry, versions) = load_checked(&o)?;
            match o.get("packages") {
                Some(dir) => {
                    verify_packages(&registry, &versions, Path::new(dir))?;
                    println!("registry valid; {} package(s) checked", versions.len());
                }
                None => println!("registry files valid; packages not checked (pass --packages)"),
            }
            // The index built from these files must be one Kalzit takes.
            let now = o.now()?;
            index_bytes(&registry, now)?;
            Ok(())
        }
        "build" => {
            let o = Options::parse(rest, &["root", "packages", "out", "site-url", "now"], &[])?;
            build(&o)
        }
        "verify-catalog" => {
            let o = Options::parse(rest, &["index", "signature", "public-key-file", "now"], &[])?;
            verify_catalog(&o)
        }
        other => Err(format!("unknown command {other}; {usage}")),
    }
}

fn today(now: u64) -> i64 {
    (now / 86_400) as i64
}

fn fail(problems: Problems) -> String {
    let mut text = format!("{} problem(s):\n", problems.0.len());
    for p in problems.0 {
        text.push_str(&format!("- {p}\n"));
    }
    text
}

/// Loads the registry, compares it with the base if given, and answers the versions whose
/// packages are to be checked.
fn load_checked(o: &Options) -> Result<(Registry, BTreeSet<(String, String)>), String> {
    let now = o.now()?;
    let mut problems = Problems::default();
    let registry = Registry::load(&o.root(), today(now), &mut problems);
    let mut versions = registry.all_versions();
    if let Some(base) = o.get("base") {
        // The base was valid when it was merged; its own problems (a date, a rule added later) are
        // not this change's.
        let base = Registry::load(Path::new(base), i64::MAX / 2, &mut Problems::default());
        let new = registry.compare_with_base(&base, &mut problems);
        if !o.flags.contains("all") {
            versions = new;
        }
    }
    if !problems.is_empty() {
        return Err(fail(problems));
    }
    Ok((registry, versions))
}

fn verify_packages(
    registry: &Registry,
    versions: &BTreeSet<(String, String)>,
    dir: &Path,
) -> Result<Vec<(String, String, package::Verified)>, String> {
    let mut problems = Problems::default();
    let mut out = Vec::new();
    for (id, version) in versions {
        let (plugin, v) = registry.version(id, version).expect("listed");
        let publisher = &registry.publishers[&plugin.file.publisher];
        let path = dir.join(&v.sha256);
        let result = std::fs::read(&path)
            .map_err(|e| format!("{} was not downloaded ({e})", v.url))
            .and_then(|bytes| package::verify(plugin, v, publisher, &bytes));
        match result {
            Ok(verified) => {
                println!("ok {id} {version}");
                out.push((id.clone(), version.clone(), verified));
            }
            Err(e) => problems.add(format!("plugins/{id} version {version}: {e}")),
        }
    }
    if !problems.is_empty() {
        return Err(fail(problems));
    }
    Ok(out)
}

/// The catalog index, exactly as Kalzit reads it, checked with Kalzit's own parser.
fn index_bytes(registry: &Registry, now: u64) -> Result<(CatalogIndex, Vec<u8>), String> {
    let mut plugins = Vec::new();
    for (id, plugin) in &registry.plugins {
        let f = &plugin.file;
        for v in &f.versions {
            plugins.push(CatalogEntry {
                id: id.clone(),
                version: v.version.clone(),
                kind: f.kind.clone(),
                name: f.name.clone(),
                key_id: v.key_id.clone(),
                url: v.url.clone(),
                sha256: v.sha256.clone(),
                size: v.size,
                description: Some(f.description.en.clone()),
                publisher: Some(f.author.clone()),
                network: f.permissions.network.clone(),
            });
        }
    }
    let revoked = registry
        .revocations
        .iter()
        .map(|r| Revocation { id: r.id.clone(), versions: r.versions.clone(), reason: r.reason.clone() })
        .collect();
    let index = CatalogIndex {
        format: catalog::CATALOG_FORMAT,
        sequence: now,
        published_at: now,
        expires_at: now + VALIDITY_SECS,
        plugins,
        revoked,
    };
    let bytes = serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?;
    // Any key will do: the signature is checked separately (`verify-catalog`).
    let any_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
    catalog::parse_index(&bytes, &any_key, &Accepted::default(), now)
        .map_err(|e| format!("Kalzit would refuse the index: {e} ({})", e.code()))?;
    Ok((index, bytes))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn build(o: &Options) -> Result<(), String> {
    let now = o.now()?;
    let site = o.required("site-url")?.trim_end_matches('/').to_string();
    if !registry::https_url(&site) {
        return Err("--site-url must be an https:// address".into());
    }
    let out = PathBuf::from(o.required("out")?);
    if out.exists() {
        return Err(format!("{} exists already; build into a new directory", out.display()));
    }
    let mut problems = Problems::default();
    let registry = Registry::load(&o.root(), today(now), &mut problems);
    if !problems.is_empty() {
        return Err(fail(problems));
    }
    let verified = verify_packages(&registry, &registry.all_versions(), Path::new(o.required("packages")?))?;
    let (index, bytes) = index_bytes(&registry, now)?;
    write(&out.join("catalog.json"), &bytes)?;

    // The catalog key, once the owner has added its public half (CONTRIBUTING.md, "Catalog key").
    let catalog_key = match std::fs::read_to_string(o.root().join("keys/catalog.pub")) {
        Ok(text) => {
            let key = kalzit_plugin_tool::public_key(text.trim()).map_err(|e| format!("keys/catalog.pub: {e}"))?;
            Some((text.trim().to_string(), signing::key_id(&key)))
        }
        Err(_) => None,
    };

    let mut publishers = Vec::new();
    for (name, p) in &registry.publishers {
        write(&out.join(format!("publishers/{name}.pub")), format!("{}\n", p.text).as_bytes())?;
        publishers.push(json!({
            "name": name, "publicKey": p.text, "keyId": signing::key_id(&p.key),
            "url": format!("{site}/publishers/{name}.pub"),
        }));
    }

    let mut plugins = Vec::new();
    for (id, plugin) in &registry.plugins {
        let f = &plugin.file;
        let mut shots = Vec::new();
        for s in &f.screenshots {
            let source = plugin.dir.join(&s.file);
            let image = std::fs::read(&source).map_err(|e| format!("{}: {e}", source.display()))?;
            let size = imagesize::blob_size(&image).map_err(|e| format!("{}: {e}", source.display()))?;
            write(&out.join(format!("screenshots/{id}/{}", s.file.trim_start_matches("screenshots/"))), &image)?;
            shots.push(json!({
                "url": format!("{site}/screenshots/{id}/{}", s.file.trim_start_matches("screenshots/")),
                "alt": { "en": s.alt.en, "de": s.alt.de }, "width": size.width, "height": size.height,
            }));
        }
        let revocation_of = |version: &str| index.revocation(id, version).map(|r| r.reason.clone());
        let versions: Vec<Value> = f
            .versions
            .iter()
            .rev()
            .map(|v| {
                let extra = verified.iter().find(|(i, ver, _)| i == id && *ver == v.version).map(|(_, _, x)| x);
                json!({
                    "version": v.version, "released": v.released, "url": v.url, "sha256": v.sha256,
                    "size": v.size, "keyId": v.key_id,
                    "minKalzit": extra.map(|x| x.min_kalzit.clone()),
                    "platforms": extra.map(|x| x.platforms.clone()).unwrap_or_default(),
                    "revoked": revocation_of(&v.version),
                })
            })
            .collect();
        let latest = f.versions.iter().rev().find(|v| revocation_of(&v.version).is_none()).map(|v| v.version.clone());
        let own_revocations: Vec<Value> = registry
            .revocations
            .iter()
            .filter(|r| &r.id == id)
            .map(|r| json!({ "versions": r.versions, "reason": r.reason }))
            .collect();
        plugins.push(json!({
            "id": id, "name": f.name, "kind": f.kind, "category": f.category,
            "description": { "en": f.description.en, "de": f.description.de },
            "author": f.author, "publisher": f.publisher,
            "keyId": signing::key_id(&registry.publishers[&f.publisher].key),
            "source": f.source, "license": f.license, "homepage": f.homepage,
            "network": f.permissions.network, "screenshots": shots,
            "latest": latest, "versions": versions, "revoked": own_revocations,
        }));
    }

    let store = json!({
        "format": 1,
        "generatedAt": now,
        "registry": REGISTRY_URL,
        "contributing": format!("{REGISTRY_URL}/blob/main/CONTRIBUTING.md"),
        "catalog": {
            "url": format!("{site}/catalog.json"),
            "signatureUrl": format!("{site}/catalog.json.sig"),
            "keyId": catalog_key.as_ref().map(|(_, id)| id.clone()),
            "publicKey": catalog_key.as_ref().map(|(k, _)| k.clone()),
            "sequence": index.sequence,
            "publishedAt": index.published_at,
            "expiresAt": index.expires_at,
            "sha256": hex::encode(Sha256::digest(&bytes)),
        },
        "categories": CATEGORIES,
        "publishers": publishers,
        "plugins": plugins,
        "revocations": registry.revocations.iter().map(|r| json!({ "id": r.id, "versions": r.versions, "reason": r.reason })).collect::<Vec<_>>(),
    });
    let store_bytes = serde_json::to_vec_pretty(&store).map_err(|e| e.to_string())?;
    write(&out.join("store.json"), &store_bytes)?;
    write(&out.join("index.html"), landing(&site).as_bytes())?;
    println!("built {} entries of {} plugin(s) into {}", index.plugins.len(), registry.plugins.len(), out.display());
    Ok(())
}

/// A plain page at the root of the site, for people who open the address in a browser.
fn landing(site: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width, initial-scale=1\"><title>Kalzit plugin catalog</title></head>\n<body>\n\
         <h1>Kalzit plugin catalog</h1>\n<p>The signed plugin catalog for Kalzit. Enter this address as the \
         catalog address in Kalzit (Administration, Plugins, Catalog):</p>\n<p><code>{site}/catalog.json</code></p>\n\
         <p>Submissions, review and revocations: <a href=\"{REGISTRY_URL}\">{REGISTRY_URL}</a>.</p>\n</body>\n</html>\n"
    )
}

fn verify_catalog(o: &Options) -> Result<(), String> {
    let index = std::fs::read(o.required("index")?).map_err(|e| e.to_string())?;
    let sig_bytes = std::fs::read(o.required("signature")?).map_err(|e| e.to_string())?;
    let key_text = std::fs::read_to_string(o.required("public-key-file")?).map_err(|e| e.to_string())?;
    let key = kalzit_plugin_tool::public_key(key_text.trim())?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Detached {
        key_id: String,
        signature: String,
    }
    let sig: Detached = serde_json::from_slice(&sig_bytes).map_err(|e| format!("the signature file: {e}"))?;
    if sig.key_id != signing::key_id(&key) {
        return Err(format!("signed with key {}, expected {}", sig.key_id, signing::key_id(&key)));
    }
    let raw = BASE64.decode(sig.signature.trim()).map_err(|_| "the signature is not base64")?;
    let signature = Signature::from_slice(&raw).map_err(|_| "the signature is not 64 bytes")?;
    if !signing::verify_catalog(&key, &index, &signature) {
        return Err("the catalog signature does not verify".into());
    }
    let now = o.now()?;
    let parsed = catalog::parse_index(&index, &key, &Accepted::default(), now)
        .map_err(|e| format!("Kalzit would refuse the index: {e} ({})", e.code()))?;
    println!(
        "catalog valid: sequence {}, {} entries, signed with key {}",
        parsed.sequence,
        parsed.plugins.len(),
        sig.key_id
    );
    Ok(())
}
