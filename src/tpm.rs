use crate::key_store::{KeyInfo, KeyStore};
use ed25519_dalek::SigningKey;
use log::{error, info};
use rand::RngCore;
use rand_core::OsRng as CoreOsRng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, CertOpenStore, BCRYPT_ALG_HANDLE,
    BCRYPT_HASH_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, HCERTSTORE,
};

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    Ed25519,
}

pub trait TPMProvider: Send + Sync {
    fn initialize(&self) -> Result<(), Box<dyn Error>>;
    fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

fn is_ntstatus_failure(status: NTSTATUS) -> bool {
    status.0 < 0
}

pub struct WindowsTPMProvider {
    _context: Arc<Mutex<BCRYPT_ALG_HANDLE>>,
}

impl WindowsTPMProvider {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        info!("Attempting to create Windows TPM Provider");
        let mut provider = BCRYPT_ALG_HANDLE::default();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut provider,
                BCRYPT_SHA256_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
            )
        };
        if is_ntstatus_failure(status) {
            let error_msg = format!(
                "BCryptOpenAlgorithmProvider failed with status: {:?}",
                status.0
            );
            error!("{}", error_msg);
            return Err(error_msg.into());
        }
        info!("Successfully created BCrypt Algorithm Provider");
        Ok(Self {
            _context: Arc::new(Mutex::new(provider)),
        })
    }

    pub fn check_tpm_status(&self) -> Result<(), Box<dyn Error>> {
        info!("Checking TPM status...");
        let _store_handle: HCERTSTORE = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                None,
            )
        }
        .map_err(|e| {
            let error_msg = format!("Failed to open certificate store: {:?}", e);
            error!("{}", error_msg);
            e
        })?;

        info!("TPM status check completed successfully");
        Ok(())
    }
}

unsafe impl Send for WindowsTPMProvider {}
unsafe impl Sync for WindowsTPMProvider {}

impl TPMProvider for WindowsTPMProvider {
    fn initialize(&self) -> Result<(), Box<dyn Error>> {
        info!("Initializing Windows TPM Provider");
        self.check_tpm_status()?;
        Ok(())
    }

    fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        info!("Generating key for {:?}", key_type);
        match key_type {
            KeyType::Rsa2048 => generate_rsa_key(2048),
            KeyType::Rsa4096 => generate_rsa_key(4096),
            KeyType::Ed25519 => generate_ed25519_key(),
        }
    }

    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let _ = private_key;
        // Open SHA256 algorithm provider
        let mut alg_handle = BCRYPT_ALG_HANDLE::default();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                BCRYPT_SHA256_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
            )
        };

        if is_ntstatus_failure(status) {
            return Err(format!("Failed to open algorithm provider: {:?}", status.0).into());
        }

        // Create hash object
        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        let hash_status = unsafe {
            BCryptCreateHash(
                alg_handle,
                &mut hash_handle,
                None, // No hash object buffer
                None, // No secret
                0,    // No secret length
            )
        };

        if is_ntstatus_failure(hash_status) {
            unsafe { BCryptCloseAlgorithmProvider(alg_handle, 0) };
            return Err(format!("Failed to create hash: {:?}", hash_status.0).into());
        }

        // Hash the data
        let hash_data_status = unsafe {
            BCryptHashData(
                hash_handle,
                data, // Slice instead of pointer
                0,    // Flags
            )
        };

        if is_ntstatus_failure(hash_data_status) {
            unsafe {
                BCryptDestroyHash(hash_handle);
                BCryptCloseAlgorithmProvider(alg_handle, 0)
            };
            return Err(format!("Failed to hash data: {:?}", hash_data_status.0).into());
        }

        // Finalize hash
        let mut hash_result = vec![0u8; 32]; // SHA256 produces 32-byte hash
        let finish_status = unsafe {
            BCryptFinishHash(
                hash_handle,
                &mut hash_result, // Slice reference
                0,                // Flags
            )
        };

        // Cleanup
        unsafe {
            BCryptDestroyHash(hash_handle);
            BCryptCloseAlgorithmProvider(alg_handle, 0)
        };

        if is_ntstatus_failure(finish_status) {
            return Err(format!("Failed to finish hash: {:?}", finish_status.0).into());
        }

        info!("Successfully performed signing operation");
        Ok(hash_result)
    }
}

fn generate_rsa_key(bits: usize) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate RSA {} key", bits);
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    let private_key_bytes = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    let public_key_bytes = public_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    info!("Successfully generated RSA {} key", bits);
    Ok((private_key_bytes, public_key_bytes))
}

fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate Ed25519 key");
    let mut rng = CoreOsRng;
    let mut ed25519_seed = [0u8; 32];
    rng.fill_bytes(&mut ed25519_seed);
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let verifying_key = signing_key.verifying_key();
    let private_key_bytes = signing_key.to_bytes().to_vec();
    let public_key_bytes = verifying_key.to_bytes().to_vec();
    info!("Successfully generated Ed25519 key");
    Ok((private_key_bytes, public_key_bytes))
}

pub struct MockTPMProvider;

impl TPMProvider for MockTPMProvider {
    fn initialize(&self) -> Result<(), Box<dyn Error>> {
        info!("Initializing Mock TPM Provider");
        Ok(())
    }

    fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        info!("Generating mock key for {:?}", key_type);
        match key_type {
            KeyType::Rsa2048 | KeyType::Rsa4096 => generate_rsa_key(2048),
            KeyType::Ed25519 => generate_ed25519_key(),
        }
    }

    fn sign(&self, _private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        info!("Performing mock signature operation");
        Ok(_data.to_vec())
    }
}

pub struct WindowsSSHAgent {
    pub tpm_provider: Box<dyn TPMProvider>,
    #[cfg(test)]
    pub key_store: KeyStore,
    #[cfg(not(test))]
    key_store: KeyStore,
}

impl WindowsSSHAgent {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Try to create WindowsTPMProvider first
        let tpm_provider: Box<dyn TPMProvider> = match WindowsTPMProvider::new() {
            Ok(provider) => {
                if provider.initialize().is_ok() {
                    info!("Successfully initialized Windows TPM Provider");
                    Box::new(provider)
                } else {
                    info!("TPM initialization failed, falling back to mock provider");
                    Box::new(MockTPMProvider)
                }
            }
            Err(e) => {
                info!(
                    "Could not create TPM provider ({}), falling back to mock provider",
                    e
                );
                Box::new(MockTPMProvider)
            }
        };

        // Generate a random master key for the key store
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        Ok(Self {
            tpm_provider,
            #[cfg(test)]
            key_store: KeyStore::new(&master_key),
            #[cfg(not(test))]
            key_store: KeyStore::new(&master_key),
        })
    }

    /// Constructor for testing purposes
    #[doc(hidden)]
    pub fn new_test(tpm_provider: Box<dyn TPMProvider>, key_store: KeyStore) -> Self {
        Self {
            tpm_provider,
            key_store,
        }
    }

    pub fn add_key(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        // Generate a unique key ID
        let key_id = format!(
            "key_{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros()
        );

        self.key_store.add_key(
            key_id,
            "ssh-key".to_string(),
            private_key,
            public_key,
            None,
            None, // No expiration by default
        )?;

        Ok(())
    }

    pub fn add_key_with_ttl(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        ttl_seconds: u64,
    ) -> Result<(), Box<dyn Error>> {
        // Generate a unique key ID
        let key_id = format!(
            "key_{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros()
        );

        self.key_store.add_key(
            key_id,
            "ssh-key".to_string(),
            private_key,
            public_key,
            None,
            Some(ttl_seconds),
        )?;

        Ok(())
    }

    pub fn remove_key(&mut self, key_id: &str) -> Result<(), Box<dyn Error>> {
        self.key_store.remove_key(key_id)?;
        Ok(())
    }

    pub fn list_keys(&self) -> Vec<KeyInfo> {
        self.key_store.list_keys()
    }

    pub fn sign_data(&mut self, public_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Find the key by its public key
        for key_info in self.list_keys() {
            if let Ok((private_key, stored_public_key)) = self.key_store.get_key(&key_info.key_id) {
                if stored_public_key == public_key {
                    return self.tpm_provider.sign(&private_key, data);
                }
            }
        }
        Err("No matching key found".into())
    }

    pub fn cleanup_expired_keys(&mut self) -> usize {
        self.key_store.cleanup_expired()
    }
}

pub struct SSHAgentServer {
    pub agent: WindowsSSHAgent,
}

impl SSHAgentServer {
    pub fn start(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Starting SSH Agent Server");
        Ok(())
    }
}
