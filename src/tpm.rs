use crate::key_store::{KeyInfo, KeyStore};
use log::{error, info};
use ring::{
    digest::{Context, SHA256},
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair},
};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
// These are used implicitly in the async functions
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// Windows types used for TPM operations
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptOpenAlgorithmProvider,
    BCRYPT_ALG_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_SHA256_ALGORITHM,
    // Types needed for TPM status check
    CertOpenStore,
    CERT_STORE_PROV_SYSTEM_W,
    CERT_QUERY_ENCODING_TYPE,
    CERT_OPEN_STORE_FLAGS,
};

// SSH Agent Protocol Message Types
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SSHAgentMessageType {
    SSHAgentFailure = 5,
    SSHAgentSuccess = 6,
    SSHAgentIdentities = 11,
    SSHAgentSign = 13,
    SSHAgentRemoveAll = 19,
}

// SSH Agent Protocol Error Types
#[derive(Debug, thiserror::Error)]
pub enum SSHAgentError {
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
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
    fn initialize(&self) -> impl std::future::Future<Output = Result<(), Box<dyn Error>>> + Send;
    fn generate_key(&self, key_type: KeyType) -> impl std::future::Future<Output = Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>> + Send;
    fn sign(&self, private_key: &[u8], data: &[u8]) -> impl std::future::Future<Output = Result<Vec<u8>, Box<dyn Error>>> + Send;
}

fn is_ntstatus_failure(status: NTSTATUS) -> bool {
    status.0 < 0
}

#[derive(Clone)]
pub struct WindowsTPMProvider {
    /// BCrypt algorithm provider handle.
    /// This is kept alive for the lifetime of the provider to maintain the TPM context.
    /// While it might appear unused, dropping it would close the TPM connection.
    /// Used in check_tpm_status to maintain the TPM context.
    #[allow(dead_code)]
    context: Arc<tokio::sync::Mutex<BCRYPT_ALG_HANDLE>>,
}

impl WindowsTPMProvider {
    /// Creates a new Windows TPM Provider.
    /// This initializes the BCrypt algorithm provider which is used for TPM operations.
    /// The provider handle is kept alive for the lifetime of this struct.
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
            context: Arc::new(tokio::sync::Mutex::new(provider)),
        })
    }

    /// Checks if the TPM is available and accessible.
    /// This is done by attempting to open the Windows certificate store,
    /// which requires TPM access rights.
    #[allow(unused_must_use)]
    pub fn check_tpm_status(&self) -> Result<(), Box<dyn Error>> {
        info!("Checking TPM status...");
        unsafe {
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
    fn initialize(&self) -> impl std::future::Future<Output = Result<(), Box<dyn Error>>> + Send {
        async move {
            info!("Initializing Windows TPM Provider");
            self.check_tpm_status()?;
            Ok(())
        }
    }

    fn generate_key(&self, key_type: KeyType) -> impl std::future::Future<Output = Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>> + Send {
        async move {
            info!("Generating key for {:?}", key_type);
            match key_type {
                KeyType::Rsa2048 => generate_rsa_key(2048),
                KeyType::Rsa4096 => generate_rsa_key(4096),
                KeyType::Ed25519 => generate_ed25519_key(),
            }
        }
    }

    fn sign(&self, private_key: &[u8], data: &[u8]) -> impl std::future::Future<Output = Result<Vec<u8>, Box<dyn Error>>> + Send {
        async move {
            // Try to parse as Ed25519 key first
            if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(private_key) {
                // Ed25519 signing
                let signature = key_pair.sign(data);
                info!("Successfully performed Ed25519 signing operation");
                return Ok(signature.as_ref().to_vec());
            }
            
            // If not Ed25519, try RSA
            // Create a SHA-256 context for the data to be signed
            let mut context = Context::new(&SHA256);
            context.update(data);
            let digest = context.finish();
            
            // Parse the private key as RSA
            let key_pair = RsaKeyPair::from_der(private_key)
                .map_err(|e| format!("Failed to parse RSA key: {:?}", e))?;
            
            // Sign the digest with RSA
            let mut signature = vec![0; key_pair.public().modulus_len()];
            key_pair
                .sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), digest.as_ref(), &mut signature)
                .map_err(|e| format!("Failed to sign data: {:?}", e))?;
            
            info!("Successfully performed RSA signing operation");
            Ok(signature)
        }
    }
}

fn generate_rsa_key(bits: usize) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate RSA {} key", bits);
    
    // Generate RSA key pair using the rsa crate
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    
    // Convert to DER format
    let private_key_der = private_key.to_pkcs1_der()?.as_bytes().to_vec();
    let public_key_der = public_key.to_pkcs1_der()?.as_bytes().to_vec();
    
    info!("Successfully generated RSA {} key", bits);
    Ok((private_key_der, public_key_der))
}

fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate Ed25519 key");
    
    // Use ring's secure random number generator and Ed25519 implementation
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Failed to generate Ed25519 key: {:?}", e))?;
    
    // Create the key pair from the generated bytes
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| format!("Failed to parse Ed25519 key: {:?}", e))?;
    
    // Get the public key
    let public_key = key_pair.public_key().as_ref().to_vec();
    
    info!("Successfully generated Ed25519 key");
    Ok((pkcs8_bytes.as_ref().to_vec(), public_key))
}

#[derive(Clone)]
pub struct MockTPMProvider;

impl TPMProvider for MockTPMProvider {
    fn initialize(&self) -> impl std::future::Future<Output = Result<(), Box<dyn Error>>> + Send {
        async move {
            info!("Initializing Mock TPM Provider");
            Ok(())
        }
    }

    fn generate_key(&self, key_type: KeyType) -> impl std::future::Future<Output = Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>> + Send {
        async move {
            info!("Generating mock key for {:?}", key_type);
            match key_type {
                KeyType::Rsa2048 | KeyType::Rsa4096 => generate_rsa_key(2048),
                KeyType::Ed25519 => generate_ed25519_key(),
            }
        }
    }

    fn sign(&self, private_key: &[u8], data: &[u8]) -> impl std::future::Future<Output = Result<Vec<u8>, Box<dyn Error>>> + Send {
        async move {
            info!("Performing mock signature operation");
            
            // Try to parse as Ed25519 key first
            if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(private_key) {
                let signature = key_pair.sign(data);
                info!("Successfully performed mock Ed25519 signing operation");
                return Ok(signature.as_ref().to_vec());
            }
            
            // If not Ed25519, try RSA
            let mut context = Context::new(&SHA256);
            context.update(data);
            let digest = context.finish();
            
            // Parse the private key as RSA
            let key_pair = RsaKeyPair::from_der(private_key)
                .map_err(|e| format!("Failed to parse RSA key in mock: {:?}", e))?;
            
            let mut signature = vec![0; key_pair.public().modulus_len()];
            key_pair
                .sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), digest.as_ref(), &mut signature)
                .map_err(|e| format!("Mock signing failed: {:?}", e))?;
            
            info!("Successfully performed mock RSA signing operation");
            Ok(signature)
        }
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

        // Generate a random master key using ring's secure random number generator
        let rng = SystemRandom::new();
        let mut master_key = [0u8; 32];
        rng.fill(&mut master_key)
            .map_err(|_| "Failed to generate master key")?;

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

                if 4 + key_blob_len > message.payload.len() {
                    return Ok(SSHAgentMessage::create_failure_response());
                }

                let key_blob = &message.payload[4..4 + key_blob_len];
                let data_to_sign = &message.payload[4 + key_blob_len..];

                // Sign the data
                match agent.sign_data(key_blob, data_to_sign).await {
                    Ok(signature) => {
                        let mut response = Vec::new();
                        response.extend_from_slice(&(signature.len() as u32).to_be_bytes());
                        response.extend_from_slice(&signature);
                        Ok(SSHAgentMessage::create_response(SSHAgentMessageType::SSHAgentSuccess, response))
                    }
                    Err(e) => {
                        error!("Signing failed: {}", e);
                        Ok(SSHAgentMessage::create_failure_response())
                    }
                }
            }

            SSHAgentMessageType::SSHAgentRemoveAll => {
                // Remove all keys
                for key in agent.list_keys() {
                    if let Err(e) = agent.remove_key(&key.key_id) {
                        error!("Failed to remove key {}: {}", key.key_id, e);
                    }
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

// Update Clone implementation to use ring's RNG
impl Clone for WindowsSSHAgent {
    fn clone(&self) -> Self {
        let rng = SystemRandom::new();
        let mut master_key = [0u8; 32];
        rng.fill(&mut master_key)
            .expect("Failed to generate master key for clone");
        
        Self {
            tpm_provider: TPMProviderType::Mock(MockTPMProvider),
            key_store: KeyStore::new(&master_key),
        }
    }
}
