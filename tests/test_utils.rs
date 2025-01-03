use std::error::Error;
use windows_ssh_agent::{KeyStore, KeyType, MockTPMProvider, TPMProvider, WindowsSSHAgent};

pub fn create_test_agent() -> Result<WindowsSSHAgent, Box<dyn Error>> {
    let tpm_provider = Box::new(MockTPMProvider);
    
    // Use a fixed test master key
    let master_key = [0u8; 32];
    let key_store = KeyStore::new(&master_key);
    
    Ok(WindowsSSHAgent::new_test(tpm_provider, key_store))
}

pub fn create_test_key_store() -> KeyStore {
    KeyStore::new(&[0u8; 32])
}

pub fn create_test_provider() -> Box<dyn TPMProvider> {
    Box::new(MockTPMProvider)
} 