//! `kalzit-catalog-signer`, the only program that sees the catalog key.
//!
//! ```text
//! kalzit-catalog-signer <catalog.json> <keys/catalog.pub> <catalog.json.sig>
//! ```
//!
//! Signs the index's exact bytes in Kalzit's catalog context (MouseWerk/Kalzit
//! plugin-api/src/signing.rs, `CATALOG_CONTEXT`) with the key in the environment variable
//! `KALZIT_CATALOG_SIGNING_KEY` (32 bytes in base64, as `kalzit-sign keygen` writes them), and
//! writes the signature file Kalzit reads next to the index: `{ "keyId", "signature" }`. The key
//! must belong to the public key committed in the registry, so a wrong secret fails here; the
//! signature is checked before it is written. The key is never printed.

use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The context line of a catalog index signature; must equal Kalzit's `CATALOG_CONTEXT`.
const CATALOG_CONTEXT: &[u8] = b"kalzit-plugin-catalog-v1\n";

const KEY_ENV: &str = "KALZIT_CATALOG_SIGNING_KEY";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// The key id Kalzit computes: the first 8 bytes of the public key's SHA-256, in hex.
fn key_id(key: &VerifyingKey) -> String {
    Sha256::digest(key.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn run(args: &[String]) -> Result<String, String> {
    let [index_path, public_path, out_path] = args else {
        return Err("usage: kalzit-catalog-signer <catalog.json> <keys/catalog.pub> <catalog.json.sig>".into());
    };
    let index = std::fs::read(index_path).map_err(|e| format!("{index_path}: {e}"))?;
    let public_text = std::fs::read_to_string(public_path).map_err(|e| format!("{public_path}: {e}"))?;
    let public_bytes: [u8; 32] = BASE64
        .decode(public_text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{public_path}: not a base64 Ed25519 public key"))?;
    let expected = VerifyingKey::from_bytes(&public_bytes).map_err(|e| format!("{public_path}: {e}"))?;

    let secret = Zeroizing::new(std::env::var(KEY_ENV).map_err(|_| format!("{KEY_ENV} is not set"))?);
    let seed = Zeroizing::new(BASE64.decode(secret.trim()).map_err(|_| format!("{KEY_ENV} is not base64"))?);
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed.as_slice().try_into().map_err(|_| format!("{KEY_ENV} is not 32 bytes"))?);
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key() != expected {
        return Err(format!(
            "{KEY_ENV} belongs to key {}, but {public_path} is key {}",
            key_id(&key.verifying_key()),
            key_id(&expected)
        ));
    }

    let mut message = CATALOG_CONTEXT.to_vec();
    message.extend_from_slice(&index);
    let signature = key.sign(&message);
    expected.verify_strict(&message, &signature).map_err(|e| format!("the new signature does not verify: {e}"))?;
    let id = key_id(&expected);
    let file = format!("{{\"keyId\":\"{id}\",\"signature\":\"{}\"}}\n", BASE64.encode(signature.to_bytes()));
    std::fs::write(out_path, file).map_err(|e| format!("{out_path}: {e}"))?;
    Ok(format!("signed {index_path} with key {id}"))
}
