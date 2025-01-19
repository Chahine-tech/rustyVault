use std::error::Error;
use windows_ssh_agent::{KeyStore, MockTPMProvider, WindowsSSHAgent, TPMProviderType};

pub fn create_test_agent() -> Result<WindowsSSHAgent, Box<dyn Error>> {
    let tpm_provider = TPMProviderType::Mock(MockTPMProvider);
    
    // Use a fixed test master key
    let master_key = [0u8; 32];
    let key_store = KeyStore::new(&master_key);
    
    Ok(WindowsSSHAgent::new_test(tpm_provider, key_store))
} 