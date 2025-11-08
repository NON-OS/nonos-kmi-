use anyhow::{anyhow, Result};
use std::sync::Arc;

pub trait CryptoProvider: Send + Sync + 'static {
    fn aes_gcm_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn blake3_hash(&self, data: &[u8]) -> Vec<u8>;
    fn ed25519_sign(&self, signing_key_seed: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn ed25519_verify(&self, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool>;
    fn chacha20poly1305_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn chacha20poly1305_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub type DynProvider = Arc<dyn CryptoProvider>;

pub struct NonosKernelProvider {}

impl NonosKernelProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NonosKernelProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for NonosKernelProvider {
    fn aes_gcm_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Key, Nonce};
        
        if key.len() != 32 {
            return Err(anyhow!("AES-256 key must be 32 bytes"));
        }
        if nonce.len() != 12 {
            return Err(anyhow!("AES-GCM nonce must be 12 bytes"));
        }

        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_array));
        let nonce_ga = &Nonce::from(nonce_array);
        
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce_ga, aad, &mut buffer)
            .map_err(|e| anyhow!("AES-GCM encrypt failed: {:?}", e))?;
        
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Key, Nonce};
        
        if key.len() != 32 {
            return Err(anyhow!("AES-256 key must be 32 bytes"));
        }
        if nonce.len() != 12 {
            return Err(anyhow!("AES-GCM nonce must be 12 bytes"));
        }
        if ciphertext.len() < 16 {
            return Err(anyhow!("Ciphertext too short"));
        }

        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_array));
        let nonce_ga = &Nonce::from(nonce_array);
        
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = ct.to_vec();
        
        cipher.decrypt_in_place_detached(nonce_ga, aad, &mut buffer, tag.try_into().unwrap())
            .map_err(|e| anyhow!("AES-GCM decrypt failed: {:?}", e))?;
        
        Ok(buffer)
    }

    fn blake3_hash(&self, data: &[u8]) -> Vec<u8> {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }

    fn ed25519_sign(&self, signing_key_seed: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::{SigningKey, Signer};
        
        if signing_key_seed.len() != 32 {
            return Err(anyhow!("Ed25519 seed must be 32 bytes"));
        }

        let signing_key = SigningKey::from_bytes(signing_key_seed.try_into().unwrap());
        let signature = signing_key.sign(msg);
        Ok(signature.to_bytes().to_vec())
    }

    fn ed25519_verify(&self, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
        use ed25519_dalek::{VerifyingKey, Verifier};
        
        if public_key.len() != 32 {
            return Err(anyhow!("Ed25519 public key must be 32 bytes"));
        }
        if signature.len() != 64 {
            return Err(anyhow!("Ed25519 signature must be 64 bytes"));
        }
        
        let verifying_key = VerifyingKey::from_bytes(public_key.try_into().unwrap())
            .map_err(|e| anyhow!("Invalid public key: {:?}", e))?;
        let sig = ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap());
        
        Ok(verifying_key.verify(msg, &sig).is_ok())
    }

    fn chacha20poly1305_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Key, Nonce};
        
        if key.len() != 32 { return Err(anyhow!("ChaCha20-Poly1305 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("ChaCha20-Poly1305 nonce must be 12 bytes")); }

        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        let cipher = ChaCha20Poly1305::new(&Key::from(key_array));
        let nonce_ga = &Nonce::from(nonce_array);
        
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce_ga, aad, &mut buffer)
            .map_err(|e| anyhow!("ChaCha20Poly1305 encrypt failed: {:?}", e))?;
        
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    fn chacha20poly1305_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Key, Nonce};
        
        if key.len() != 32 { return Err(anyhow!("ChaCha20-Poly1305 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("ChaCha20-Poly1305 nonce must be 12 bytes")); }
        if ciphertext.len() < 16 { return Err(anyhow!("Ciphertext too short")); }

        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        let cipher = ChaCha20Poly1305::new(&Key::from(key_array));
        let nonce_ga = &Nonce::from(nonce_array);
        
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = ct.to_vec();
        
        cipher.decrypt_in_place_detached(nonce_ga, aad, &mut buffer, tag.try_into().unwrap())
            .map_err(|e| anyhow!("ChaCha20Poly1305 decrypt failed: {:?}", e))?;
        
        Ok(buffer)
    }
}

////////////////////////////////////////////////////////////////////////////////
// RealKernelProvider: Uses NONOS kernel crypto 
////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "kernel-crypto")]
pub struct RealKernelProvider {}

#[cfg(feature = "kernel-crypto")]
impl RealKernelProvider {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "kernel-crypto")]
impl Default for RealKernelProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "kernel-crypto")]
impl CryptoProvider for RealKernelProvider {
    fn aes_gcm_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 { return Err(anyhow!("AES-256 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("AES-GCM nonce must be 12 bytes")); }
        
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        
        match nonos_kernel::aes256_gcm_encrypt(&key_array, &nonce_array, aad, plaintext) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(anyhow!("NONOS AES-GCM encrypt failed: {}", e)),
        }
    }

    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 { return Err(anyhow!("AES-256 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("AES-GCM nonce must be 12 bytes")); }
        
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        
        match nonos_kernel::aes256_gcm_decrypt(&key_array, &nonce_array, aad, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(anyhow!("NONOS AES-GCM decrypt failed: {}", e)),
        }
    }

    fn blake3_hash(&self, data: &[u8]) -> Vec<u8> {
        nonos_kernel::blake3_hash(data)
    }

    fn ed25519_sign(&self, signing_key_seed: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        if signing_key_seed.len() != 32 { return Err(anyhow!("Ed25519 seed must be 32 bytes")); }
        
        let seed_array: [u8; 32] = signing_key_seed.try_into().unwrap();
        let keypair = nonos_kernel::ed25519::KeyPair::from_seed(&seed_array);
        let signature = nonos_kernel::sign(msg, &keypair);
        Ok(signature.to_bytes().to_vec())
    }

    fn ed25519_verify(&self, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
        if public_key.len() != 32 { return Err(anyhow!("Ed25519 public key must be 32 bytes")); }
        if signature.len() != 64 { return Err(anyhow!("Ed25519 signature must be 64 bytes")); }
        
        let pub_array: [u8; 32] = public_key.try_into().unwrap();
        let sig_array: [u8; 64] = signature.try_into().unwrap();
        let signature_struct = nonos_kernel::ed25519::Signature::from_bytes(&sig_array);
        
        Ok(nonos_kernel::verify_ed25519(msg, &signature_struct, &pub_array))
    }

    fn chacha20poly1305_encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 { return Err(anyhow!("ChaCha20-Poly1305 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("ChaCha20-Poly1305 nonce must be 12 bytes")); }
        
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        
        match nonos_kernel::chacha20poly1305_encrypt(&key_array, &nonce_array, aad, plaintext) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(anyhow!("NONOS ChaCha20Poly1305 encrypt failed: {}", e)),
        }
    }

    fn chacha20poly1305_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 { return Err(anyhow!("ChaCha20-Poly1305 key must be 32 bytes")); }
        if nonce.len() != 12 { return Err(anyhow!("ChaCha20-Poly1305 nonce must be 12 bytes")); }
        
        let key_array: [u8; 32] = key.try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        
        match nonos_kernel::chacha20poly1305_decrypt(&key_array, &nonce_array, aad, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(anyhow!("NONOS ChaCha20Poly1305 decrypt failed: {}", e)),
        }
    }
}

