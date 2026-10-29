//! Reversible encryption for PINs and join-link secrets, so the admin can look them up
//! again. Their hashes still do the checking; this copy is only for display.
//!
//! The key lives outside the database (`<data_dir>/secret.key`, or `ARK_SECRET_KEY`),
//! so a copy of `ark.db` alone does not reveal PINs. Each ciphertext is bound to its
//! row id and cannot be moved to another row.

use std::path::Path;

use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::config::Config;

const KEY_FILE: &str = "secret.key";
const NONCE_LEN: usize = 12;

pub struct Vault {
    cipher: ChaCha20Poly1305,
}

impl Vault {
    pub fn load(cfg: &Config) -> anyhow::Result<Self> {
        let encoded = match &cfg.secret_key {
            Some(k) => k.clone(),
            None => read_or_create(&cfg.data_dir.join(KEY_FILE))?,
        };
        let bytes = STANDARD
            .decode(encoded.trim())
            .context("ARK_SECRET_KEY must be standard base64")?;
        anyhow::ensure!(bytes.len() == 32, "secret key must be 32 bytes");
        Ok(Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&bytes)),
        })
    }

    /// `secret` encrypted for row `id`, as base64url(nonce || ciphertext).
    pub fn seal(&self, id: &str, secret: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: id.as_bytes(),
                },
            )
            .expect("encrypting in memory cannot fail");
        URL_SAFE_NO_PAD.encode([&nonce[..], &sealed].concat())
    }

    /// The secret, or None if it was sealed for another row or under another key.
    pub fn open(&self, id: &str, sealed: &str) -> Option<String> {
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let (nonce, ciphertext) = bytes.split_at_checked(NONCE_LEN)?;
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: id.as_bytes(),
                },
            )
            .ok()?;
        String::from_utf8(plain).ok()
    }
}

fn read_or_create(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(k) => return Ok(k),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("reading {}", path.display()));
        }
        Err(_) => {}
    }
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let encoded = STANDARD.encode(key);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut file, encoded.as_bytes())?;
    file.sync_all()?;
    tracing::info!("created {}; back it up with the database", path.display());
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bound_to_row() {
        let dir = std::env::temp_dir().join(format!("ark-vault-{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = Vault::load(&Config::for_tests(dir.clone())).unwrap();
        let sealed = vault.seal("pin-1", "2468");
        assert_eq!(vault.open("pin-1", &sealed).as_deref(), Some("2468"));
        assert_eq!(vault.open("pin-2", &sealed), None);
        assert_ne!(vault.seal("pin-1", "2468"), sealed, "fresh nonce each time");
        // The same key file is read back on the next start.
        let again = Vault::load(&Config::for_tests(dir.clone())).unwrap();
        assert_eq!(again.open("pin-1", &sealed).as_deref(), Some("2468"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
