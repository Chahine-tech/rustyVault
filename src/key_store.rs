use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{error, info};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key expired")]
    KeyExpired,
    #[error("Invalid key data")]
    InvalidKeyData,
    #[error("Storage error: {0}")]
    StorageError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    pub key_id: String,
    pub key_type: String,
    pub encrypted_private_key: String,
    pub public_key: String,
    pub comment: Option<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used: u64,
    pub use_count: u64,
}

pub struct KeyStore {
    key: LessSafeKey,
    keys: HashMap<String, StoredKey>,
}

impl KeyStore {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let unbound_key =
            UnboundKey::new(&aead::AES_256_GCM, master_key).expect("Failed to create unbound key");
        let key = LessSafeKey::new(unbound_key);

        Self {
            key,
            keys: HashMap::new(),
        }
    }

    pub fn add_key(
        &mut self,
        key_id: String,
        key_type: String,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        comment: Option<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<(), KeyStoreError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| KeyStoreError::EncryptionError("Failed to generate nonce".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Prepare buffer for in-place encryption
        let mut in_out = private_key;
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        // Combine nonce and encrypted data
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&in_out);

        let stored_key = StoredKey {
            key_id: key_id.clone(),
            key_type,
            encrypted_private_key: BASE64.encode(combined),
            public_key: BASE64.encode(public_key),
            comment,
            created_at: now,
            expires_at: ttl_seconds.map(|ttl| now + ttl),
            last_used: now,
            use_count: 0,
        };

        self.keys.insert(key_id, stored_key);
        info!("Added new key to store");
        Ok(())
    }

    pub fn get_key(&mut self, key_id: &str) -> Result<(Vec<u8>, Vec<u8>), KeyStoreError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key = self
            .keys
            .get_mut(key_id)
            .ok_or(KeyStoreError::KeyNotFound)?;

        // Check expiration
        if let Some(expires_at) = key.expires_at {
            if now > expires_at {
                return Err(KeyStoreError::KeyExpired);
            }
        }

        // Update usage statistics
        key.last_used = now;
        key.use_count += 1;

        // Decode the combined nonce and encrypted data
        let combined = BASE64
            .decode(&key.encrypted_private_key)
            .map_err(|_| KeyStoreError::InvalidKeyData)?;

        if combined.len() < NONCE_LEN {
            return Err(KeyStoreError::InvalidKeyData);
        }

        // Split into nonce and encrypted data
        let (nonce_bytes, encrypted_data) = combined.split_at(NONCE_LEN);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

        // Create mutable buffer for decryption
        let mut decryption_buffer = encrypted_data.to_vec();

        // Decrypt the private key
        let private_key = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut decryption_buffer)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?
            .to_vec();

        let public_key = BASE64
            .decode(&key.public_key)
            .map_err(|_| KeyStoreError::InvalidKeyData)?;

        Ok((private_key, public_key))
    }

    pub fn remove_key(&mut self, key_id: &str) -> Result<(), KeyStoreError> {
        self.keys
            .remove(key_id)
            .ok_or(KeyStoreError::KeyNotFound)
            .map(|_| {
                info!("Removed key from store: {}", key_id);
            })
    }

    pub fn list_keys(&self) -> Vec<KeyInfo> {
        self.keys
            .values()
            .map(|k| KeyInfo {
                key_id: k.key_id.clone(),
                key_type: k.key_type.clone(),
                comment: k.comment.clone(),
                created_at: k.created_at,
                expires_at: k.expires_at,
                last_used: k.last_used,
                use_count: k.use_count,
            })
            .collect()
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_keys: Vec<String> = self
            .keys
            .iter()
            .filter(|(_, k)| k.expires_at.is_some_and(|exp| now >= exp))
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_keys.len();
        for key_id in expired_keys {
            self.keys.remove(&key_id);
        }
        count
    }
}

#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub key_type: String,
    pub comment: Option<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used: u64,
    pub use_count: u64,
}
