//! The registry files and the checks on them (CONTRIBUTING.md): `plugins/<id>/plugin.toml`,
//! `publishers/<name>.pub` and `revocations.toml`. Everything here is static: no network and no
//! plugin code. Packages are read by `package.rs` from files the workflow downloaded.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use kalzit_plugin_api::signing::key_id;
use serde::Deserialize;

/// The store's categories, in the order the website lists them.
pub const CATEGORIES: &[&str] = &["databases", "metrics-and-logs", "files-and-apis", "visualization", "utilities"];

/// Kalzit's own plugin public keys (MouseWerk/Kalzit server/src/plugins/package.rs,
/// `COMPILED_KALZIT_KEYS`): ids under `io.kalzit.` and `dev.kalzit.` need one of them.
pub const KALZIT_PLUGIN_KEYS: &[&str] =
    &["6RZV2LeoOy9gDyW7Izi8OXRoDbMjsWQ3FiZabeC4D6c=", "t0SLQ6UM+XNRoqJJai/6aSx8t8ITdjIz3uL7tuv0gh8="];

/// Longest one-line text in the catalog (`kalzit_plugin_api::catalog::MAX_TEXT_CHARS`).
pub const MAX_TEXT_CHARS: usize = kalzit_plugin_api::catalog::MAX_TEXT_CHARS;

/// Largest package Kalzit downloads from the catalog.
pub const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;

pub const MAX_SCREENSHOTS: usize = 8;
pub const MAX_SCREENSHOT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginFile {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub category: String,
    /// The file name of the publisher key, without `.pub`.
    pub publisher: String,
    /// The name shown as the publisher (the catalog's `publisher` label).
    pub author: String,
    /// The author's repository the releases come from.
    pub source: String,
    pub license: String,
    #[serde(default)]
    pub homepage: Option<String>,
    pub description: Texts,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub screenshots: Vec<Screenshot>,
    pub versions: Vec<VersionEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Texts {
    pub en: String,
    #[serde(default)]
    pub de: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    /// The package's network targets in the catalog's words (`catalog::target_words`).
    #[serde(default)]
    pub network: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Screenshot {
    /// `screenshots/<name>` inside the plugin's directory.
    pub file: String,
    pub alt: Alt,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alt {
    pub en: String,
    pub de: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionEntry {
    pub version: String,
    /// The release date, `YYYY-MM-DD`.
    pub released: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// The key id of the publisher key that signs the package.
    pub key_id: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationsFile {
    #[serde(default)]
    pub revoked: Vec<RevocationEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    pub id: String,
    pub versions: String,
    pub reason: String,
}

pub struct Publisher {
    pub name: String,
    pub text: String,
    pub key: VerifyingKey,
}

pub struct Plugin {
    pub dir: PathBuf,
    pub file: PluginFile,
}

/// The registry as read from one checkout.
pub struct Registry {
    pub root: PathBuf,
    pub publishers: BTreeMap<String, Publisher>,
    pub plugins: BTreeMap<String, Plugin>,
    pub revocations: Vec<RevocationEntry>,
}

/// Problems found, all of them, so an author sees everything in one run.
#[derive(Default)]
pub struct Problems(pub Vec<String>);

impl Problems {
    pub fn add(&mut self, text: impl Into<String>) {
        self.0.push(text.into());
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A short text for people: not empty, at most `max` characters, no control or bidirectional
/// override characters (as the catalog checks it).
pub fn plain_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty()
        && text.chars().count() <= max
        && !text.chars().any(|c| c.is_control() || is_bidi_control(c))
}

/// Characters that reorder how text is shown (as `kalzit_plugin_api::manifest::is_bidi_control`).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
}

/// A plugin id as Kalzit's manifest accepts it (`kalzit_plugin_api::manifest::valid_id`).
pub fn valid_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('.').collect();
    (3..=64).contains(&id.len())
        && parts.len() >= 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && parts[0].as_bytes()[0].is_ascii_lowercase()
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An `https://` URL with a host and no whitespace, control characters or user info.
pub fn https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty()
        && !authority.contains('@')
        && url.len() <= 2048
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

/// A host Kalzit's target rules refuse by default: loopback, private, shared, link-local,
/// unique-local and unspecified addresses, and `localhost`.
pub fn private_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || (a == 100 && (64..128).contains(&b))
        }
        Ok(IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            ip.is_loopback() || ip.is_unspecified() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// Days since 1970-01-01 of a civil date, or `None` for an invalid one.
pub fn days_from_civil(text: &str) -> Option<i64> {
    let parts: Vec<&str> = text.split('-').collect();
    let [y, m, d] = parts.as_slice() else { return None };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&m) || d < 1 || d > month_days[(m - 1) as usize] {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

impl Registry {
    /// Reads and checks a registry checkout. `today` is the current day (days since 1970).
    pub fn load(root: &Path, today: i64, problems: &mut Problems) -> Registry {
        let mut registry = Registry {
            root: root.to_path_buf(),
            publishers: BTreeMap::new(),
            plugins: BTreeMap::new(),
            revocations: Vec::new(),
        };
        registry.load_publishers(problems);
        registry.load_plugins(today, problems);
        registry.load_revocations(problems);
        registry
    }

    fn load_publishers(&mut self, problems: &mut Problems) {
        let dir = self.root.join("publishers");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            problems.add("publishers/ is missing");
            return;
        };
        for entry in entries.flatten() {
            let file = entry.file_name().to_string_lossy().to_string();
            let Some(name) = file.strip_suffix(".pub") else {
                problems.add(format!("publishers/{file}: only <name>.pub files belong here"));
                continue;
            };
            if !valid_name(name) {
                problems.add(format!("publishers/{file}: the name must be 1 to 40 of a-z, 0-9 and -"));
                continue;
            }
            let text = match read_text(&entry.path()) {
                Ok(t) => t,
                Err(e) => {
                    problems.add(e);
                    continue;
                }
            };
            let line = text.trim();
            if line.lines().count() != 1 || line.len() != 44 {
                problems.add(format!("publishers/{file}: one line with the base64 Ed25519 public key (44 characters)"));
                continue;
            }
            match kalzit_plugin_tool::public_key(line) {
                Ok(key) if !key.is_weak() => {
                    self.publishers
                        .insert(name.to_string(), Publisher { name: name.to_string(), text: line.into(), key });
                }
                Ok(_) => problems.add(format!("publishers/{file}: a weak key")),
                Err(e) => problems.add(format!("publishers/{file}: {e}")),
            }
        }
    }

    fn load_plugins(&mut self, today: i64, problems: &mut Problems) {
        let dir = self.root.join("plugins");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            problems.add("plugins/ is missing");
            return;
        };
        let mut lower_ids = BTreeSet::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !entry.path().is_dir() {
                problems.add(format!("plugins/{name}: only one directory per plugin belongs here"));
                continue;
            }
            let path = entry.path().join("plugin.toml");
            let text = match read_text(&path) {
                Ok(t) => t,
                Err(e) => {
                    problems.add(e);
                    continue;
                }
            };
            let file: PluginFile = match toml::from_str(&text) {
                Ok(f) => f,
                Err(e) => {
                    problems.add(format!("plugins/{name}/plugin.toml: {e}"));
                    continue;
                }
            };
            if file.id != name {
                problems.add(format!("plugins/{name}/plugin.toml: id {} must equal the directory name", file.id));
                continue;
            }
            // Ids must be unique, also in case: Windows and macOS checkouts would mix them up.
            if !lower_ids.insert(name.to_ascii_lowercase()) {
                problems.add(format!("plugins/{name}: another plugin has the same id in other case"));
            }
            let plugin = Plugin { dir: entry.path(), file };
            self.check_plugin(&plugin, today, problems);
            self.plugins.insert(name, plugin);
        }
    }

    fn check_plugin(&self, plugin: &Plugin, today: i64, problems: &mut Problems) {
        let f = &plugin.file;
        let at = format!("plugins/{}/plugin.toml", f.id);
        let mut bad = |what: String| problems.add(format!("{at}: {what}"));
        if !valid_id(&f.id) {
            bad("id: lowercase reverse domain notation of at most 64 characters, such as dev.example.redis".into());
        }
        if !matches!(f.kind.as_str(), "datasource" | "panel") {
            bad(format!("kind {} is neither datasource nor panel", f.kind));
        }
        if !CATEGORIES.contains(&f.category.as_str()) {
            bad(format!("category {} is not one of {}", f.category, CATEGORIES.join(", ")));
        }
        if f.name.trim().is_empty() || f.name.chars().count() > 64 || f.name.chars().any(char::is_control) {
            bad("name: 1 to 64 characters".into());
        }
        if !plain_text(&f.author, 64) {
            bad("author: 1 to 64 characters, one line".into());
        }
        if !plain_text(&f.license, 64) {
            bad("license: an SPDX expression, such as MIT or Apache-2.0".into());
        }
        if !https_url(&f.source) {
            bad("source: the https:// address of the repository the releases come from".into());
        }
        if f.homepage.as_deref().is_some_and(|h| !https_url(h)) {
            bad("homepage: an https:// address".into());
        }
        if !plain_text(&f.description.en, MAX_TEXT_CHARS) {
            bad(format!("description.en: one line of at most {MAX_TEXT_CHARS} characters"));
        }
        if f.description.de.as_deref().is_some_and(|d| !plain_text(d, MAX_TEXT_CHARS)) {
            bad(format!("description.de: one line of at most {MAX_TEXT_CHARS} characters"));
        }
        let publisher = self.publishers.get(&f.publisher);
        if publisher.is_none() {
            bad(format!("publisher {}: publishers/{}.pub is missing", f.publisher, f.publisher));
        }
        let reserved = kalzit_plugin_api::manifest::is_reserved_id(&f.id);
        if reserved && publisher.is_some_and(|p| !KALZIT_PLUGIN_KEYS.contains(&p.text.as_str())) {
            bad("ids under io.kalzit. and dev.kalzit. are signed with Kalzit's own plugin key only".into());
        }

        // Network targets in the catalog's words; the package must declare exactly these.
        let targets = &f.permissions.network;
        if targets.len() > kalzit_plugin_api::catalog::MAX_NETWORK_ENTRIES {
            bad("permissions.network: at most 32 targets".into());
        }
        if f.kind == "panel" && !targets.is_empty() {
            bad("permissions.network: panels run in a sandboxed frame without network access".into());
        }
        let mut seen = BTreeSet::new();
        for t in targets {
            if !plain_text(t, 255) || t.chars().any(char::is_whitespace) || t != &t.to_lowercase() {
                bad(format!("permissions.network {t}: host:port, *:port or *, lowercase"));
            } else if !seen.insert(t) {
                bad(format!("permissions.network {t}: listed twice"));
            } else if t != "*" {
                let host = t.rsplit_once(':').map_or(t.as_str(), |(h, _)| h);
                if host != "*" && private_host(host) {
                    bad(format!("permissions.network {t}: Kalzit refuses private and loopback addresses"));
                }
            }
        }

        // Screenshots: files in the plugin's directory, reviewed with it.
        if f.screenshots.len() > MAX_SCREENSHOTS {
            bad(format!("screenshots: at most {MAX_SCREENSHOTS}"));
        }
        let mut listed = BTreeSet::from(["plugin.toml".to_string()]);
        for s in &f.screenshots {
            let Some(name) = s.file.strip_prefix("screenshots/") else {
                bad(format!("screenshots {}: files go into screenshots/", s.file));
                continue;
            };
            let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
            let name_ok = !name.is_empty()
                && name.len() <= 64
                && !name.starts_with('.')
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
            if !name_ok || !matches!(ext, "png" | "webp" | "jpg" | "jpeg") {
                bad(format!("screenshots {}: a png, webp or jpg file named with a-z, 0-9, - and _", s.file));
                continue;
            }
            if !listed.insert(s.file.clone()) {
                bad(format!("screenshots {}: listed twice", s.file));
            }
            let path = plugin.dir.join(&s.file);
            match std::fs::metadata(&path) {
                Ok(m) if m.len() > MAX_SCREENSHOT_BYTES => bad(format!("screenshots {}: larger than 1 MiB", s.file)),
                Ok(_) => {
                    if imagesize::size(&path).is_err() {
                        bad(format!("screenshots {}: not a readable image", s.file));
                    }
                }
                Err(_) => bad(format!("screenshots {}: the file is missing", s.file)),
            }
            if !plain_text(&s.alt.en, 200) || !plain_text(&s.alt.de, 200) {
                bad(format!("screenshots {}: alt.en and alt.de, one line of at most 200 characters", s.file));
            }
        }
        // Nothing else in the directory, so a review sees everything that is published.
        for path in files_below(&plugin.dir) {
            if !listed.contains(&path) {
                bad(format!("{path}: not listed in plugin.toml"));
            }
        }

        // Versions: ascending, each signed by the publisher's key.
        if f.versions.is_empty() {
            bad("versions: at least one".into());
        }
        let mut previous: Option<semver::Version> = None;
        for v in &f.versions {
            let label = format!("version {}", v.version);
            match semver::Version::parse(&v.version) {
                Ok(parsed) => {
                    if previous.as_ref().is_some_and(|p| parsed <= *p) {
                        bad(format!("{label}: versions are listed oldest first and only increase"));
                    }
                    previous = Some(parsed);
                }
                Err(_) => bad(format!("{label}: not a semantic version")),
            }
            match days_from_civil(&v.released) {
                Some(day) if day <= today + 1 => {}
                Some(_) => bad(format!("{label}: released lies in the future")),
                None => bad(format!("{label}: released is a date like 2026-11-01")),
            }
            if !https_url(&v.url) {
                bad(format!("{label}: url must be an https:// address without user info"));
            }
            if !lower_hex(&v.sha256, 64) {
                bad(format!("{label}: sha256 is 64 lowercase hex digits"));
            }
            if v.size == 0 || v.size > MAX_PACKAGE_BYTES {
                bad(format!("{label}: size is the package's size in bytes, at most 256 MiB"));
            }
            if let Some(p) = publisher
                && v.key_id != key_id(&p.key)
            {
                bad(format!(
                    "{label}: key_id {} is not the key id of publishers/{}.pub ({})",
                    v.key_id,
                    p.name,
                    key_id(&p.key)
                ));
            }
        }
    }

    fn load_revocations(&mut self, problems: &mut Problems) {
        let path = self.root.join("revocations.toml");
        let file: RevocationsFile = match read_text(&path).and_then(|t| toml::from_str(&t).map_err(|e| e.to_string())) {
            Ok(f) => f,
            Err(e) => {
                problems.add(format!("revocations.toml: {e}"));
                return;
            }
        };
        for r in &file.revoked {
            let at = format!("revocations.toml ({} {})", r.id, r.versions);
            if r.versions.len() > 128 || semver::VersionReq::parse(&r.versions).is_err() {
                problems.add(format!("{at}: versions is a semver requirement such as *, <1.2.1 or =1.0.0"));
            }
            if !plain_text(&r.reason, MAX_TEXT_CHARS) {
                problems.add(format!("{at}: reason, one line of at most {MAX_TEXT_CHARS} characters"));
            }
        }
        if file.revoked.len() > 4096 {
            problems.add("revocations.toml: at most 4096 entries");
        }
        self.revocations = file.revoked;
    }

    /// The rules between the base branch and this change: nothing published is changed or taken
    /// away, versions only increase, keys and publishers stay. Answers the versions that are new.
    pub fn compare_with_base(&self, base: &Registry, problems: &mut Problems) -> BTreeSet<(String, String)> {
        for (name, old) in &base.publishers {
            match self.publishers.get(name) {
                Some(new) if new.key == old.key => {}
                Some(_) => problems.add(format!(
                    "publishers/{name}.pub: a published key never changes; a new key goes into a new file"
                )),
                None => problems.add(format!("publishers/{name}.pub: a published key is never removed")),
            }
        }
        for (id, old) in &base.plugins {
            let Some(new) = self.plugins.get(id) else {
                problems.add(format!(
                    "plugins/{id}: a published plugin is not removed; revoke its versions in revocations.toml"
                ));
                continue;
            };
            let (old, new) = (&old.file, &new.file);
            if new.publisher != old.publisher {
                problems.add(format!("plugins/{id}: the publisher of a published plugin does not change"));
            }
            if new.kind != old.kind {
                problems.add(format!("plugins/{id}: the kind of a published plugin does not change"));
            }
            if new.versions.len() < old.versions.len() || new.versions[..old.versions.len()] != old.versions[..] {
                problems.add(format!(
                    "plugins/{id}: published versions stay as they are; new versions are added at the end"
                ));
            }
        }
        for r in &base.revocations {
            if !self.revocations.contains(r) {
                problems.add(format!(
                    "revocations.toml: the revocation of {} {} is never taken back or changed",
                    r.id, r.versions
                ));
            }
        }
        let mut new = BTreeSet::new();
        for (id, plugin) in &self.plugins {
            let old = base.plugins.get(id).map(|p| p.file.versions.as_slice()).unwrap_or_default();
            for v in &plugin.file.versions {
                if !old.contains(v) {
                    new.insert((id.clone(), v.version.clone()));
                }
            }
        }
        new
    }

    /// Every (id, version) of the registry.
    pub fn all_versions(&self) -> BTreeSet<(String, String)> {
        self.plugins
            .iter()
            .flat_map(|(id, p)| p.file.versions.iter().map(move |v| (id.clone(), v.version.clone())))
            .collect()
    }

    pub fn version(&self, id: &str, version: &str) -> Option<(&Plugin, &VersionEntry)> {
        let plugin = self.plugins.get(id)?;
        plugin.file.versions.iter().find(|v| v.version == version).map(|v| (plugin, v))
    }
}

/// Files below `dir`, as `/`-separated paths relative to it.
fn files_below(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((path, prefix)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else { continue };
        for entry in entries.flatten() {
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push((entry.path(), format!("{name}/")));
            } else {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_hosts() {
        assert_eq!(days_from_civil("1970-01-01"), Some(0));
        assert_eq!(days_from_civil("2026-11-01"), Some(20_758));
        assert_eq!(days_from_civil("2026-02-29"), None);
        assert_eq!(days_from_civil("2026-1-01"), None);
        for host in
            ["localhost", "127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "100.64.0.1", "[::1]", "fd00::1"]
        {
            assert!(private_host(host), "{host}");
        }
        for host in ["db.example.dev", "8.8.8.8", "2001:db8::1"] {
            assert!(!private_host(host), "{host}");
        }
    }

    #[test]
    fn kalzit_keys_parse() {
        let ids: Vec<String> =
            KALZIT_PLUGIN_KEYS.iter().map(|k| key_id(&kalzit_plugin_tool::public_key(k).unwrap())).collect();
        assert_eq!(ids, ["581c30a0d8384cfd", "df87ab1649696788"]);
    }
}
