use log::info;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use ed25519_dalek::Keypair;
use std::error::Error;
use std::sync::Arc;
use windows::Win32::Security::Cryptography::{
    BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_SHA256_ALGORITHM,
};
use windows::Win32::Foundation::NTSTATUS;
use rand_core::OsRng as CoreOsRng;

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    Ed25519,
}

pub trait TPMProvider {
    fn initialize(&self) -> Result<(), Box<dyn Error>>;
    fn generate_key(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

fn is_ntstatus_failure(status: NTSTATUS) -> bool {
    status.0 < 0
}

pub struct WindowsTPMProvider {
    _context: Arc<BCRYPT_ALG_HANDLE>,
}

impl WindowsTPMProvider {
    pub fn new() -> Result<Self, Box<dyn Error>> {
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
            return Err(format!("BCryptOpenAlgorithmProvider failed with status: {:?}", status.0).into());
        }
        Ok(Self {
            _context: Arc::new(provider),
        })
    }

    fn check_tpm_status(&self) -> Result<(), Box<dyn Error>> {
        // Implémentez ici une vérification du statut du TPM
        Ok(())
    }
}

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

    fn sign(&self, _private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        info!("Performing signature operation");
        Ok(_data.to_vec()) //Simple mock signature
    }
}

fn generate_rsa_key(bits: usize) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate RSA {} key", bits);
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    let private_key_bytes = private_key.to_pkcs1_der()?.as_ref().to_vec();
    let public_key_bytes = public_key.to_pkcs1_der()?.as_ref().to_vec();
    info!("Successfully generated RSA {} key", bits);
    Ok((private_key_bytes, public_key_bytes))
}

fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    info!("Attempting to generate Ed25519 key");
    let mut rng = CoreOsRng;
    let keypair: Keypair = Keypair::generate(&mut rng);
    let private_key_bytes = keypair.secret.to_bytes().to_vec();
    let public_key_bytes = keypair.public.to_bytes().to_vec();
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
    keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl WindowsSSHAgent {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let tpm_provider = Box::new(WindowsTPMProvider::new()?);
        tpm_provider.initialize()?;
        Ok(Self {
            tpm_provider,
            keys: Vec::new(),
        })
    }

    pub fn add_key(&mut self, private_key: Vec<u8>, public_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
        info!("Adding private key");
        self.keys.push((private_key, public_key));
        info!("Successfully added private key");
        Ok(())
    }

    pub fn sign_data(
        &self,
        public_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        for (private_key, key_public) in &self.keys {
            if key_public == public_key {
                return self.tpm_provider.sign(private_key, data);
            }
        }
        Err("No matching key found".into())
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
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
