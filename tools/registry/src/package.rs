//! Checks one downloaded package against its registry entry, the way Kalzit checks a package
//! from the catalog before it installs it (MouseWerk/Kalzit server/src/plugins/catalog.rs,
//! `download` and `compare`, and docs/api/plugins.md, "Packages"). The package is only read as a
//! zip file: no plugin code runs.

use kalzit_plugin_api::catalog::{same_network, target_words};
use kalzit_plugin_api::signing::key_id;
use sha2::{Digest, Sha256};

use crate::registry::{Plugin, Publisher, VersionEntry, private_host};

/// Largest panel bundle Kalzit serves (`plugin.bundle_invalid`).
const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// What the package says beyond the registry entry, for the store.
pub struct Verified {
    pub min_kalzit: String,
    pub platforms: Vec<String>,
}

/// Checks `bytes`, downloaded from `version.url`, against the entry and the publisher's key.
pub fn verify(
    plugin: &Plugin,
    version: &VersionEntry,
    publisher: &Publisher,
    bytes: &[u8],
) -> Result<Verified, String> {
    let f = &plugin.file;
    if bytes.len() as u64 != version.size {
        return Err(format!("the package has {} bytes, the entry says {}", bytes.len(), version.size));
    }
    let sha = hex::encode(Sha256::digest(bytes));
    if sha != version.sha256 {
        return Err(format!("the package's SHA-256 is {sha}, the entry says {}", version.sha256));
    }
    // Paths, entry kinds, the manifest and exactly the listed files with their hashes.
    let contents = kalzit_plugin_tool::read(bytes)?;
    let m = &contents.manifest;
    // The signature, with the publisher's key in full (not only its key id).
    if contents.signature.is_none() {
        return Err("the package is not signed; the catalog lists signed packages only".into());
    }
    kalzit_plugin_tool::verify(bytes, Some(&publisher.key))?;
    if version.key_id != key_id(&publisher.key) {
        return Err(format!("key_id {} is not the publisher's key", version.key_id));
    }
    for (field, listed, packaged) in [
        ("id", f.id.as_str(), m.id.as_str()),
        ("version", version.version.as_str(), m.version.as_str()),
        ("kind", f.kind.as_str(), m.kind.as_str()),
        ("name", f.name.as_str(), m.name.as_str()),
    ] {
        if listed != packaged {
            return Err(format!("{field}: the entry says {listed}, the package's manifest says {packaged}"));
        }
    }
    // The permissions Kalzit's sandbox enforces are the manifest's network targets: the entry must
    // name exactly those (Kalzit refuses a catalog package whose targets differ), and fixed hosts
    // must pass Kalzit's default target rules.
    if !same_network(&version.network, m) {
        let declared: Vec<String> = m.permissions.network.iter().map(target_words).collect();
        return Err(format!(
            "network must list exactly the package's targets: [{}]",
            declared.iter().map(|t| format!("\"{t}\"")).collect::<Vec<_>>().join(", ")
        ));
    }
    for t in &m.permissions.network {
        if let Some(host) = &t.host
            && private_host(host)
        {
            return Err(format!("the package reaches the fixed host {host}, which Kalzit refuses"));
        }
    }
    match m.kind.as_str() {
        "panel" => {
            if !m.permissions.network.is_empty() {
                return Err("a panel declares network targets; panels have no network access".into());
            }
            let bundle = m.panel.as_ref().ok_or("a panel without [panel]")?;
            let code = contents.files.get(&bundle.path).ok_or("the panel bundle is missing")?;
            check_bundle(code)?;
        }
        _ => {
            if m.binaries.is_empty() {
                return Err("a data source without binaries".into());
            }
        }
    }
    Ok(Verified { min_kalzit: m.min_kalzit.clone(), platforms: m.binaries.keys().cloned().collect() })
}

/// Kalzit serves a panel bundle inside an HTML document: UTF-8 without NUL characters, at most
/// 8 MiB, without `</script` or `<!--`.
fn check_bundle(code: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(code).map_err(|_| "the panel bundle is not UTF-8".to_string())?;
    let lower = text.to_ascii_lowercase();
    if code.len() > MAX_BUNDLE_BYTES || text.contains('\0') || lower.contains("</script") || lower.contains("<!--") {
        return Err("the panel bundle is larger than 8 MiB or contains NUL, </script or <!--".into());
    }
    Ok(())
}
