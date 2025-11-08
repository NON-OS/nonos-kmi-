use anyhow::{anyhow, Context, Result};
use std::{fs, path::PathBuf, time::SystemTime, sync::Arc};
use tracing::{info, warn};

use crate::crypto_provider::{NonosKernelProvider, DynProvider};
use crate::crypto_harness::{AesGcmVector, CryptoHarness};
use crossbeam_channel::unbounded;

pub struct CryptoManager {
    provider: DynProvider,
    signing_key_path: Option<PathBuf>,
    public_key_path: Option<PathBuf>,
    keys_directory: Option<PathBuf>,
    key_status: KeyStatus,
}

#[derive(Debug, Clone)]
pub struct KeyStatus {
    pub signing_key_exists: bool,
    pub public_key_exists: bool,
    pub signing_key_size: Option<u64>,
    pub public_key_size: Option<u64>,
    pub signing_key_modified: Option<SystemTime>,
    pub public_key_modified: Option<SystemTime>,
    pub permissions_valid: bool,
}

impl CryptoManager {
    pub async fn new(signing_key_path: Option<PathBuf>) -> Result<Self> {
        let (signing, public, dir) = if let Some(p) = signing_key_path.clone() {
            let parent = p.parent().ok_or_else(|| anyhow!("invalid signing key path"))?.to_path_buf();
            (Some(p), Some(parent.join("signing.pub")), Some(parent))
        } else {
            let default = dirs::home_dir().ok_or_else(|| anyhow!("home dir missing"))?.join("nonos-kernel").join(".keys");
            (Some(default.join("signing.seed")), Some(default.join("signing.pub")), Some(default))
        };

        let provider: DynProvider = Arc::new(NonosKernelProvider::new());

        let key_status = Self::check_key_status(&signing, &public)?;
        info!("crypto manager initialized");
        Ok(Self { provider, signing_key_path: signing, public_key_path: public, keys_directory: dir, key_status })
    }

    fn check_key_status(signing: &Option<PathBuf>, public: &Option<PathBuf>) -> Result<KeyStatus> {
        let signing_exists = signing.as_ref().map(|p| p.exists()).unwrap_or(false);
        let public_exists = public.as_ref().map(|p| p.exists()).unwrap_or(false);
        let signing_size = signing.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.len());
        let public_size = public.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.len());
        let signing_mod = signing.as_ref().and_then(|p| fs::metadata(p).ok()).and_then(|m| m.modified().ok());
        let public_mod = public.as_ref().and_then(|p| fs::metadata(p).ok()).and_then(|m| m.modified().ok());
        let permissions_valid = Self::check_key_permissions(signing, public);
        Ok(KeyStatus { signing_key_exists: signing_exists, public_key_exists: public_exists, signing_key_size: signing_size, public_key_size: public_size, signing_key_modified: signing_mod, public_key_modified: public_mod, permissions_valid })
    }

    fn check_key_permissions(signing: &Option<PathBuf>, public: &Option<PathBuf>) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let sp = signing.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
            let pp = public.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
            (sp == 0o600 || sp == 0) && (pp == 0o644 || pp == 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    pub async fn generate_keys(&self) -> Result<()> {
        let keys_dir = self.keys_directory.as_ref().context("keys dir not configured")?;
        if !keys_dir.exists() { tokio::fs::create_dir_all(keys_dir).await.context("create keys dir")?; }
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pk = verifying_key.to_bytes();
        tokio::fs::write(keys_dir.join("signing.seed"), &seed).await.context("write seed")?;
        tokio::fs::write(keys_dir.join("signing.pub"), &pk).await.context("write pub")?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(keys_dir.join("signing.seed"), fs::Permissions::from_mode(0o600)).await;
            let _ = tokio::fs::set_permissions(keys_dir.join("signing.pub"), fs::Permissions::from_mode(0o644)).await;
        }
        info!("generated keys in {}", keys_dir.display());
        Ok(())
    }

    pub async fn verify_key_integrity(&self) -> Result<()> {
        let signing = self.signing_key_path.as_ref().context("no signing key configured")?;
        let public = self.public_key_path.as_ref().context("no public key configured")?;
        let sk = tokio::fs::read(signing).await.context("read signing")?;
        let pk = tokio::fs::read(public).await.context("read public")?;
        if sk.len() != 32 { return Err(anyhow!("signing key wrong length")); }
        if pk.len() != 32 { return Err(anyhow!("public key wrong length")); }
        use ed25519_dalek::SigningKey;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&sk);
        let signing_key = SigningKey::from_bytes(&seed_arr);
        let derived_public = signing_key.verifying_key().to_bytes();
        if derived_public != pk.as_slice() { warn!("public key mismatch with derived"); return Err(anyhow!("public key mismatch")); }
        Ok(())
    }

    pub async fn rotate_keys(&self) -> Result<()> {
        if let Some(p) = &self.signing_key_path { if p.exists() {
            let backup = p.with_extension(format!("seed.backup.{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
            tokio::fs::copy(p, &backup).await.context("backup signing")?;
        }}
        self.generate_keys().await?;
        Ok(())
    }

    pub fn signing_key_path(&self) -> Option<&std::path::Path> { self.signing_key_path.as_deref() }
    pub fn public_key_path(&self) -> Option<&std::path::Path> { self.public_key_path.as_deref() }

    pub fn start_aes_gcm_test(&self, vectors: Vec<AesGcmVector>) -> crossbeam_channel::Receiver<crate::crypto_harness::HarnessEvent> {
        let (tx, rx) = unbounded();
        let provider = Arc::clone(&self.provider);
        let harness = CryptoHarness::new(provider, tx.clone(), 2);
        harness.run_aes_gcm_vectors(1, "aes-gcm-suite", vectors);
        rx
    }

    pub fn start_benchmark(&self, interval_ms: u64) -> crossbeam_channel::Receiver<crate::crypto_harness::HarnessEvent> {
        let (tx, rx) = unbounded();
        let provider = Arc::clone(&self.provider);
        let harness = CryptoHarness::new(provider, tx.clone(), 1);
        harness.run_benchmark_stream(2, interval_ms);
        rx
    }

    pub async fn refresh(&mut self) -> Result<()> {
        self.key_status = Self::check_key_status(&self.signing_key_path, &self.public_key_path)?;
        Ok(())
    }

    pub fn has_signing_key(&self) -> bool { self.key_status.signing_key_exists }
    pub fn has_public_key(&self) -> bool { self.key_status.public_key_exists }
    pub fn key_status(&self) -> &KeyStatus { &self.key_status }
}
