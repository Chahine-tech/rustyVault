use crate::key_store::{KeyInfo, KeyStore};
use ed25519_dalek::SigningKey;
use log::{error, info};
use rand::RngCore;
use rand_core::OsRng as CoreOsRng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, CertOpenStore, BCRYPT_ALG_HANDLE,
    BCRYPT_HASH_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, HCERTSTORE,
};

// SSH Agent Protocol Message Types
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SSHAgentMessageType {
    SSHAgentFailure = 5,
    SSHAgentSuccess = 6,
    SSHAgentIdentities = 11,
    SSHAgentSign = 13,
    SSHAgentAdd = 17,
    SSHAgentRemove = 18,
    SSHAgentLock = 22,
    SSHAgentUnlock = 23,
    SSHAgentRemoveAll = 19,
}

// SSH Agent Protocol Error Types
#[derive(Debug, thiserror::Error)]
pub enum SSHAgentError {
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Operation failed")]
    OperationFailed,
    #[error("Agent is locked")]
    AgentLocked,
}

// SSH Agent Protocol Message Parser
struct SSHAgentMessage {
    message_type: SSHAgentMessageType,
    payload: Vec<u8>,
}

impl SSHAgentMessage {
    fn parse(data: &[u8]) -> Result<Self, SSHAgentError> {
        if data.len() < 5 {
            return Err(SSHAgentError::InvalidMessageFormat);
        }

        // First 4 bytes are the length in network byte order (big endian)
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() != length + 4 {
            return Err(SSHAgentError::InvalidMessageFormat);
        }

        // Next byte is the message type
        let message_type = match data[4] {
            x if x == SSHAgentMessageType::SSHAgentIdentities as u8 => SSHAgentMessageType::SSHAgentIdentities,
            x if x == SSHAgentMessageType::SSHAgentSign as u8 => SSHAgentMessageType::SSHAgentSign,
            x if x == SSHAgentMessageType::SSHAgentAdd as u8 => SSHAgentMessageType::SSHAgentAdd,
            x if x == SSHAgentMessageType::SSHAgentRemove as u8 => SSHAgentMessageType::SSHAgentRemove,
            x if x == SSHAgentMessageType::SSHAgentLock as u8 => SSHAgentMessageType::SSHAgentLock,
            x if x == SSHAgentMessageType::SSHAgentUnlock as u8 => SSHAgentMessageType::SSHAgentUnlock,
            x if x == SSHAgentMessageType::SSHAgentRemoveAll as u8 => SSHAgentMessageType::SSHAgentRemoveAll,
            x => return Err(SSHAgentError::InvalidMessageType(x)),
        };

        // Rest is payload
        let payload = data[5..].to_vec();

        Ok(Self {
            message_type,
            payload,
        })
    }

    fn create_response(message_type: SSHAgentMessageType, payload: Vec<u8>) -> Vec<u8> {
        let length = (payload.len() + 1) as u32;
        let mut response = Vec::with_capacity(length as usize + 4);
        
        // Add length in network byte order
        response.extend_from_slice(&length.to_be_bytes());
        // Add message type
        response.push(message_type as u8);
        // Add payload
        response.extend_from_slice(&payload);
        
        response
    }

    fn create_success_response() -> Vec<u8> {
        Self::create_response(SSHAgentMessageType::SSHAgentSuccess, vec![])
    }

    fn create_failure_response() -> Vec<u8> {
        Self::create_response(SSHAgentMessageType::SSHAgentFailure, vec![])
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    Ed25519,
}

#[derive(Clone)]
pub enum TPMProviderType {
    Windows(WindowsTPMProvider),
    Mock(MockTPMProvider),
}

impl TPMProviderType {
    pub async fn initialize(&self) -> Result<(), Box<dyn Error>> {
        match self {
            TPMProviderType::Windows(provider) => provider.initialize().await,
            TPMProviderType::Mock(provider) => provider.initialize().await,
        }
    }

    pub async fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        match self {
            TPMProviderType::Windows(provider) => provider.generate_key(key_type).await,
            TPMProviderType::Mock(provider) => provider.generate_key(key_type).await,
        }
    }

    pub async fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            TPMProviderType::Windows(provider) => provider.sign(private_key, data).await,
            TPMProviderType::Mock(provider) => provider.sign(private_key, data).await,
        }
    }
}

pub trait TPMProvider: Send + Sync {
    async fn initialize(&self) -> Result<(), Box<dyn Error>>;
    async fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;
    async fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

fn is_ntstatus_failure(status: NTSTATUS) -> bool {
    status.0 < 0
}

#[derive(Clone)]
pub struct WindowsTPMProvider {
    _context: Arc<tokio::sync::Mutex<BCRYPT_ALG_HANDLE>>,
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
            _context: Arc::new(tokio::sync::Mutex::new(provider)),
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
    async fn initialize(&self) -> Result<(), Box<dyn Error>> {
        info!("Initializing Windows TPM Provider");
        self.check_tpm_status()?;
        Ok(())
    }

    async fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        info!("Generating key for {:?}", key_type);
        match key_type {
            KeyType::Rsa2048 => generate_rsa_key(2048),
            KeyType::Rsa4096 => generate_rsa_key(4096),
            KeyType::Ed25519 => generate_ed25519_key(),
        }
    }

    async fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

#[derive(Clone)]
pub struct MockTPMProvider;

impl TPMProvider for MockTPMProvider {
    async fn initialize(&self) -> Result<(), Box<dyn Error>> {
        info!("Initializing Mock TPM Provider");
        Ok(())
    }

    async fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        info!("Generating mock key for {:?}", key_type);
        match key_type {
            KeyType::Rsa2048 | KeyType::Rsa4096 => generate_rsa_key(2048),
            KeyType::Ed25519 => generate_ed25519_key(),
        }
    }

    async fn sign(&self, _private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        info!("Performing mock signature operation");
        Ok(_data.to_vec())
    }
}

pub struct WindowsSSHAgent {
    pub tpm_provider: TPMProviderType,
    #[cfg(test)]
    pub key_store: KeyStore,
    #[cfg(not(test))]
    key_store: KeyStore,
}

impl WindowsSSHAgent {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        // Try to create WindowsTPMProvider first
        let tpm_provider = match WindowsTPMProvider::new() {
            Ok(provider) => {
                if provider.initialize().await.is_ok() {
                    info!("Successfully initialized Windows TPM Provider");
                    TPMProviderType::Windows(provider)
                } else {
                    info!("TPM initialization failed, falling back to mock provider");
                    TPMProviderType::Mock(MockTPMProvider)
                }
            }
            Err(e) => {
                info!(
                    "Could not create TPM provider ({}), falling back to mock provider",
                    e
                );
                TPMProviderType::Mock(MockTPMProvider)
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
    pub fn new_test(tpm_provider: TPMProviderType, key_store: KeyStore) -> Self {
        Self {
            tpm_provider,
            key_store,
        }
    }

    pub async fn add_key(
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

    pub async fn add_key_with_ttl(
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

    pub async fn sign_data(&mut self, public_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Find the key by its public key
        for key_info in self.list_keys() {
            if let Ok((private_key, stored_public_key)) = self.key_store.get_key(&key_info.key_id) {
                if stored_public_key == public_key {
                    return self.tpm_provider.sign(&private_key, data).await;
                }
            }
        }
        Err("No matching key found".into())
    }

    pub fn remove_key(&mut self, key_id: &str) -> Result<(), Box<dyn Error>> {
        self.key_store.remove_key(key_id)?;
        Ok(())
    }

    pub fn list_keys(&self) -> Vec<KeyInfo> {
        self.key_store.list_keys()
    }

    pub fn cleanup_expired_keys(&mut self) -> usize {
        self.key_store.cleanup_expired()
    }
}

pub struct SSHAgentServer {
    pub agent: WindowsSSHAgent,
}

impl SSHAgentServer {
    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Starting SSH Agent Server");
        
        // Create an async TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        info!("SSH Agent listening on {}", addr);

        // Main connection handling loop
        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("New connection from {}", peer_addr);
                    
                    // Clone the required data for the handler
                    let agent = Arc::new(tokio::sync::Mutex::new(self.agent.clone()));
                    
                    // Spawn a new task to handle the connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket, agent).await {
                            error!("Error handling connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        socket: tokio::net::TcpStream,
        agent: Arc<tokio::sync::Mutex<WindowsSSHAgent>>,
    ) -> Result<(), Box<dyn Error>> {
        let (mut reader, mut writer) = socket.into_split();
        let mut buffer = vec![0u8; 8192];

        loop {
            // Read data asynchronously
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                break; // Connection closed
            }

            // Process the request
            let response = {
                let mut agent = agent.lock().await;
                Self::process_request(&mut agent, &buffer[..n]).await?
            };

            // Send response asynchronously
            writer.write_all(&response).await?;
        }

        Ok(())
    }

    async fn process_request(agent: &mut WindowsSSHAgent, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let message = match SSHAgentMessage::parse(data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse SSH agent message: {}", e);
                return Ok(SSHAgentMessage::create_failure_response());
            }
        };

        match message.message_type {
            SSHAgentMessageType::SSHAgentIdentities => {
                // List all identities
                let keys = agent.list_keys();
                let mut response = Vec::new();
                
                // Number of keys (u32 in network byte order)
                response.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                
                // Add each key's information
                for key in keys {
                    if let Ok((_, public_key)) = agent.key_store.get_key(&key.key_id) {
                        // Key blob length
                        response.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
                        // Key blob
                        response.extend_from_slice(&public_key);
                        // Comment length
                        let comment = format!("{}@{}", key.key_type, key.key_id);
                        response.extend_from_slice(&(comment.len() as u32).to_be_bytes());
                        // Comment
                        response.extend_from_slice(comment.as_bytes());
                    }
                }

                Ok(SSHAgentMessage::create_response(SSHAgentMessageType::SSHAgentIdentities, response))
            }

            SSHAgentMessageType::SSHAgentSign => {
                if message.payload.len() < 8 {
                    return Ok(SSHAgentMessage::create_failure_response());
                }

                // Extract key blob and data to sign
                let key_blob_len = u32::from_be_bytes([
                    message.payload[0],
                    message.payload[1],
                    message.payload[2],
                    message.payload[3],
                ]) as usize;

                let key_blob = message.payload[4..4 + key_blob_len].to_vec();
                let data_to_sign = message.payload[4 + key_blob_len..].to_vec();

                // Sign the data
                match agent.sign_data(&key_blob, &data_to_sign).await {
                    Ok(signature) => {
                        let mut response = Vec::new();
                        response.extend_from_slice(&(signature.len() as u32).to_be_bytes());
                        response.extend_from_slice(&signature);
                        Ok(SSHAgentMessage::create_response(SSHAgentMessageType::SSHAgentSuccess, response))
                    }
                    Err(_) => Ok(SSHAgentMessage::create_failure_response()),
                }
            }

            SSHAgentMessageType::SSHAgentRemoveAll => {
                // Remove all keys
                for key in agent.list_keys() {
                    let _ = agent.remove_key(&key.key_id);
                }
                Ok(SSHAgentMessage::create_success_response())
            }

            _ => {
                error!("Unsupported SSH agent message type: {:?}", message.message_type);
                Ok(SSHAgentMessage::create_failure_response())
            }
        }
    }
}

// Update Clone implementation for WindowsSSHAgent
impl Clone for WindowsSSHAgent {
    fn clone(&self) -> Self {
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);
        
        Self {
            tpm_provider: TPMProviderType::Mock(MockTPMProvider),
            key_store: KeyStore::new(&master_key),
        }
    }
}
