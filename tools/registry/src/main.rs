//! `kalzit-registry`, the checks and the catalog build of the plugin registry.
//!
//! ```text
//! kalzit-registry fetch-list [--root .] [--previous <dir>]
//! kalzit-registry check [--root .] [--base <dir>] [--previous <dir>] [--packages <dir>]
//! kalzit-registry build [--root .] --packages <dir> --out <dir> --site-url <https url> [--previous <dir>] [--now <unix secs>]
//! kalzit-registry verify-catalog --index <file> --signature <file> --public-key-file <file> [--now <unix secs>]
//! ```
//!
//! Packages are checked once: a version is downloaded and checked when it is neither revoked nor
//! listed unchanged in the last published catalog. `--previous` is a directory with that catalog
//! as published (`catalog.json`, `catalog.json.sig`, `store.json`; missing files mean nothing was
//! published yet); it counts only when its signature verifies with the catalog key. Versions it
//! lists keep their recorded SHA-256 and size without a new download, so a release asset that
//! later disappears does not stop publishing (CONTRIBUTING.md, "What CI checks").
//!
//! `fetch-list` prints `<sha256> <size> <url>` per package to download. `check` checks the
//! registry files, the rules against `--base` (a checkout of main), and the downloaded packages
//! (`<packages>/<sha256>`). `build` checks everything and writes the catalog index, the store
//! data, the screenshots and the publisher keys into `--out`. `verify-catalog` checks a signed
//! index the way Kalzit does before the site is published.

mod package;
mod registry;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use kalzit_plugin_api::catalog::{self, Accepted, CatalogEntry, CatalogIndex};
use kalzit_plugin_api::signing;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::registry::{CATEGORIES, Problems, Registry, VersionEntry, revocations_of};

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
}

impl Options {
    fn parse(args: &[String], values: &[&str]) -> Result<Options, String> {
        let mut o = Options { pairs: Vec::new() };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let name = arg.strip_prefix("--").ok_or_else(|| format!("unexpected argument {arg}"))?;
            if !values.contains(&name) {
                return Err(format!("unknown option --{name}"));
            }
            let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            o.pairs.push((name.to_string(), value.clone()));
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
            let o = Options::parse(rest, &["root", "previous", "now"])?;
            let registry = load(&o)?;
            let previous = Previous::load(o.get("previous"), &registry);
            for (id, version) in to_download(&registry, &previous) {
                let (_, v) = registry.version(&id, &version).expect("listed");
                println!("{} {} {}", v.sha256, v.size, v.url);
            }
            Ok(())
        }
        "check" => {
            let o = Options::parse(rest, &["root", "base", "previous", "packages", "now"])?;
            let registry = load(&o)?;
            if let Some(base) = o.get("base") {
                compare(&registry, Path::new(base))?;
            }
            let previous = Previous::load(o.get("previous"), &registry);
            let versions = to_download(&registry, &previous);
            report_skipped(&registry, &versions);
            match o.get("packages") {
                Some(dir) => {
                    verify_packages(&registry, &versions, Path::new(dir))?;
                    println!("registry valid; {} package(s) checked", versions.len());
                }
                None => println!("registry files valid; packages not checked (pass --packages)"),
            }
            // The index built from these files must be one Kalzit takes.
            index_bytes(&registry, o.now()?)?;
            Ok(())
        }
        "build" => {
            let o = Options::parse(rest, &["root", "packages", "out", "site-url", "previous", "now"])?;
            build(&o)
        }
        "verify-catalog" => {
            let o = Options::parse(rest, &["index", "signature", "public-key-file", "now"])?;
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

fn load(o: &Options) -> Result<Registry, String> {
    let mut problems = Problems::default();
    let registry = Registry::load(&o.root(), today(o.now()?), &mut problems);
    if !problems.is_empty() {
        return Err(fail(problems));
    }
    Ok(registry)
}

/// The rules against the base; changes that need the owner's eye are annotated in the CI run.
fn compare(registry: &Registry, base: &Path) -> Result<(), String> {
    // The base was valid when it was merged; its own problems (a date, a rule added later) are
    // not this change's.
    let base = Registry::load(base, i64::MAX / 2, &mut Problems::default());
    let mut problems = Problems::default();
    let mut attention = Vec::new();
    registry.compare_with_base(&base, &mut problems, &mut attention);
    let mut summary = String::new();
    for a in &attention {
        println!("::warning title=Needs the owner's attention::{a}");
        summary.push_str(&format!("- {a}\n"));
    }
    if !summary.is_empty()
        && let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY")
    {
        let text = format!("### Needs the owner's attention\n\n{summary}\n");
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()));
    }
    if !problems.is_empty() {
        return Err(fail(problems));
    }
    Ok(())
}

/// The catalog entry of one version, as the index lists it.
fn entry_for(registry: &Registry, id: &str, v: &VersionEntry) -> CatalogEntry {
    let f = &registry.plugins[id].file;
    CatalogEntry {
        id: id.to_string(),
        version: v.version.clone(),
        kind: f.kind.clone(),
        name: f.name.clone(),
        key_id: v.key_id.clone(),
        url: v.url.clone(),
        sha256: v.sha256.clone(),
        size: v.size,
        description: Some(f.description.en.clone()),
        publisher: Some(f.author.clone()),
        network: v.network.clone(),
    }
}

/// What the store shows of a package beyond its entry.
#[derive(Clone)]
struct Extra {
    min_kalzit: Option<String>,
    platforms: Vec<String>,
}

/// The last published catalog, once its signature verified. Its messages go to stderr, so
/// `fetch-list` prints nothing but packages on stdout.
#[derive(Default)]
struct Previous {
    entries: BTreeMap<(String, String), CatalogEntry>,
    /// Per package SHA-256, what the published store data said of it (display only).
    extras: BTreeMap<String, Extra>,
}

impl Previous {
    fn load(dir: Option<&str>, registry: &Registry) -> Previous {
        let Some(dir) = dir.map(Path::new) else { return Previous::default() };
        let (Ok(index), Ok(sig)) =
            (std::fs::read(dir.join("catalog.json")), std::fs::read(dir.join("catalog.json.sig")))
        else {
            eprintln!("no published catalog: every version that is not revoked is checked");
            return Previous::default();
        };
        let Some((key, not_after)) = registry.previous_catalog_keys().into_iter().find_map(|(k, not_after)| {
            let key = kalzit_plugin_tool::public_key(&k).ok()?;
            verify_signature(&index, &sig, &key).ok().map(|_| (key, not_after))
        }) else {
            eprintln!(
                "::warning::the published catalog does not verify with the catalog key: every version is checked"
            );
            return Previous::default();
        };
        // An expired index is still a signed record of what was checked; only its form counts here.
        let Ok(parsed) = serde_json::from_slice::<CatalogIndex>(&index) else {
            eprintln!("::warning::the published catalog cannot be read: every version is checked");
            return Previous::default();
        };
        // The key before a rotation counts only for an index published before the rotation.
        if parsed.published_at > not_after {
            eprintln!(
                "::warning::the published catalog is signed with the key before the rotation: every version is checked"
            );
            return Previous::default();
        }
        eprintln!(
            "published catalog: sequence {}, {} entries, signed with key {}",
            parsed.sequence,
            parsed.plugins.len(),
            signing::key_id(&key)
        );
        let entries = parsed.plugins.into_iter().map(|e| ((e.id.clone(), e.version.clone()), e)).collect();
        let mut extras = BTreeMap::new();
        // The store data counts only when it belongs to exactly this index.
        let index_sha = hex::encode(Sha256::digest(&index));
        if let Ok(store) = std::fs::read(dir.join("store.json"))
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()))
            && store["catalog"]["sha256"].as_str() == Some(index_sha.as_str())
        {
            for v in store["plugins"].as_array().into_iter().flatten().flat_map(|p| p["versions"].as_array()).flatten()
            {
                if let Some(sha) = v["sha256"].as_str() {
                    let platforms =
                        v["platforms"].as_array().into_iter().flatten().filter_map(|p| p.as_str().map(String::from));
                    extras.insert(
                        sha.to_string(),
                        Extra { min_kalzit: v["minKalzit"].as_str().map(String::from), platforms: platforms.collect() },
                    );
                }
            }
        }
        Previous { entries, extras }
    }

    /// Whether the published catalog lists this version with the same package: address, hash,
    /// size, key, kind, name and network targets (the name is checked against the package's
    /// manifest). Descriptions may change without a new check.
    fn carries(&self, entry: &CatalogEntry) -> bool {
        self.entries.get(&(entry.id.clone(), entry.version.clone())).is_some_and(|p| {
            p.name == entry.name
                && p.url == entry.url
                && p.sha256 == entry.sha256
                && p.size == entry.size
                && p.key_id == entry.key_id
                && p.kind == entry.kind
                && p.network == entry.network
        })
    }
}

/// The versions to download and check: neither revoked nor carried over from the published
/// catalog.
fn to_download(registry: &Registry, previous: &Previous) -> BTreeSet<(String, String)> {
    registry
        .all_versions()
        .into_iter()
        .filter(|(id, version)| {
            let (_, v) = registry.version(id, version).expect("listed");
            !registry.revoked(id, version) && !previous.carries(&entry_for(registry, id, v))
        })
        .collect()
}

fn report_skipped(registry: &Registry, checked: &BTreeSet<(String, String)>) {
    for (id, version) in registry.all_versions().difference(checked) {
        let why = if registry.revoked(id, version) {
            "revoked, not downloaded"
        } else {
            "unchanged in the published catalog, not downloaded again"
        };
        println!("skip {id} {version}: {why}");
    }
}

fn verify_packages(
    registry: &Registry,
    versions: &BTreeSet<(String, String)>,
    dir: &Path,
) -> Result<BTreeMap<String, Extra>, String> {
    let mut problems = Problems::default();
    let mut out = BTreeMap::new();
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
                out.insert(
                    v.sha256.clone(),
                    Extra { min_kalzit: Some(verified.min_kalzit), platforms: verified.platforms },
                );
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
        for v in &plugin.file.versions {
            plugins.push(entry_for(registry, id, v));
        }
    }
    let index = CatalogIndex {
        format: catalog::CATALOG_FORMAT,
        sequence: now,
        published_at: now,
        expires_at: now + VALIDITY_SECS,
        plugins,
        revoked: revocations_of(&registry.revocations),
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
    let registry = load(o)?;
    let previous = Previous::load(o.get("previous"), &registry);
    let versions = to_download(&registry, &previous);
    report_skipped(&registry, &versions);
    let mut extras = verify_packages(&registry, &versions, Path::new(o.required("packages")?))?;
    for (sha, extra) in &previous.extras {
        extras.entry(sha.clone()).or_insert_with(|| extra.clone());
    }
    let (index, bytes) = index_bytes(&registry, now)?;
    write(&out.join("catalog.json"), &bytes)?;

    let catalog_key = match &registry.catalog_key {
        Some(text) => {
            let key: VerifyingKey = kalzit_plugin_tool::public_key(text)?;
            Some((text.clone(), signing::key_id(&key)))
        }
        None => None,
    };

    let mut publishers = Vec::new();
    for (name, p) in &registry.publishers {
        write(&out.join(format!("publishers/{name}.pub")), format!("{}\n", p.text).as_bytes())?;
        publishers.push(json!({
            "name": name, "publicKey": p.text, "keyId": signing::key_id(&p.key),
            "url": format!("{site}/publishers/{name}.pub"), "authors": p.authors,
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
            let name = s.file.trim_start_matches("screenshots/");
            write(&out.join(format!("screenshots/{id}/{name}")), &image)?;
            shots.push(json!({
                "url": format!("{site}/screenshots/{id}/{name}"),
                "alt": { "en": s.alt.en, "de": s.alt.de }, "width": size.width, "height": size.height,
            }));
        }
        let revocation_of = |version: &str| index.revocation(id, version).map(|r| r.reason.clone());
        let versions: Vec<Value> = f
            .versions
            .iter()
            .rev()
            .map(|v| {
                let extra = extras.get(&v.sha256);
                json!({
                    "version": v.version, "released": v.released, "url": v.url, "sha256": v.sha256,
                    "size": v.size, "keyId": v.key_id, "network": v.network,
                    "minKalzit": extra.and_then(|x| x.min_kalzit.clone()),
                    "platforms": extra.map(|x| x.platforms.clone()).unwrap_or_default(),
                    "revoked": revocation_of(&v.version),
                })
            })
            .collect();
        let latest = f.versions.iter().rev().find(|v| revocation_of(&v.version).is_none());
        let shown = latest.or(f.versions.last());
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
            // The targets of the version the store offers (per version under `versions`).
            "network": shown.map(|v| v.network.clone()).unwrap_or_default(),
            "screenshots": shots,
            "latest": latest.map(|v| v.version.clone()), "versions": versions, "revoked": own_revocations,
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

/// Checks a detached catalog signature (`{ "keyId", "signature" }`) over `index` with `key`.
fn verify_signature(index: &[u8], sig_bytes: &[u8], key: &VerifyingKey) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Detached {
        key_id: String,
        signature: String,
    }
    let sig: Detached = serde_json::from_slice(sig_bytes).map_err(|e| format!("the signature file: {e}"))?;
    if sig.key_id != signing::key_id(key) {
        return Err(format!("signed with key {}, expected {}", sig.key_id, signing::key_id(key)));
    }
    let raw = BASE64.decode(sig.signature.trim()).map_err(|_| "the signature is not base64")?;
    let signature = Signature::from_slice(&raw).map_err(|_| "the signature is not 64 bytes")?;
    if !signing::verify_catalog(key, index, &signature) {
        return Err("the catalog signature does not verify".into());
    }
    Ok(sig.key_id)
}

fn verify_catalog(o: &Options) -> Result<(), String> {
    let index = std::fs::read(o.required("index")?).map_err(|e| e.to_string())?;
    let sig_bytes = std::fs::read(o.required("signature")?).map_err(|e| e.to_string())?;
    let key_text = std::fs::read_to_string(o.required("public-key-file")?).map_err(|e| e.to_string())?;
    let key = kalzit_plugin_tool::public_key(key_text.trim())?;
    let key_id = verify_signature(&index, &sig_bytes, &key)?;
    let parsed = catalog::parse_index(&index, &key, &Accepted::default(), o.now()?)
        .map_err(|e| format!("Kalzit would refuse the index: {e} ({})", e.code()))?;
    println!("catalog valid: sequence {}, {} entries, signed with key {key_id}", parsed.sequence, parsed.plugins.len());
    Ok(())
}
