use std::error::Error;
use windows_ssh_agent::{KeyType, WindowsSSHAgent, KeyStore};
mod test_utils;
use test_utils::{create_test_agent, create_test_key_store, create_test_provider};

#[test]
fn test_windows_ssh_agent_creation() -> Result<(), Box<dyn Error>> {
    let ssh_agent = create_test_agent()?;
    assert_eq!(
        ssh_agent.list_keys().len(),
        0,
        "New SSH agent should have zero keys"
    );
    Ok(())
}

#[test]
fn test_key_generation_and_addition() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = create_test_agent()?;

    let (rsa_private_key, rsa_public_key) =
        ssh_agent.tpm_provider.generate_key(KeyType::Rsa2048)?;

    ssh_agent.add_key(rsa_private_key.clone(), rsa_public_key.clone())?;
    assert_eq!(
        ssh_agent.list_keys().len(),
        1,
        "SSH agent should have one key after addition"
    );

    let (ed25519_private_key, ed25519_public_key) =
        ssh_agent.tpm_provider.generate_key(KeyType::Ed25519)?;

    ssh_agent.add_key(ed25519_private_key, ed25519_public_key)?;
    assert_eq!(
        ssh_agent.list_keys().len(),
        2,
        "SSH agent should have two keys after second addition"
    );

    Ok(())
}

#[test]
fn test_key_signing() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = create_test_agent()?;
    
    let (ed25519_private_key, ed25519_public_key) = ssh_agent
        .tpm_provider
        .generate_key(KeyType::Ed25519)?;
    
    ssh_agent.add_key(ed25519_private_key.clone(), ed25519_public_key.clone())?;

    let test_data = b"Hello, SSH Agent!";
    
    let signature = ssh_agent.sign_data(&ed25519_public_key, test_data)?;
    
    assert!(!signature.is_empty(), "Signature should not be empty");

    Ok(())
}

#[test]
fn test_sign_with_nonexistent_key() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = create_test_agent()?;

    let test_data = b"Test signing";
    let fake_public_key = vec![0, 1, 2, 3];

    let result = ssh_agent.sign_data(&fake_public_key, test_data);
    assert!(result.is_err(), "Signing with non-existent key should fail");

    Ok(())
}

#[test]
fn test_key_removal() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = create_test_agent()?;
    
    let (private_key, public_key) = ssh_agent.tpm_provider.generate_key(KeyType::Ed25519)?;
    ssh_agent.add_key(private_key, public_key)?;
    
    let key_id = ssh_agent.list_keys()[0].key_id.clone();
    assert_eq!(ssh_agent.list_keys().len(), 1, "Should have one key before removal");
    
    ssh_agent.remove_key(&key_id)?;
    assert_eq!(ssh_agent.list_keys().len(), 0, "Should have no keys after removal");
    
    Ok(())
}

#[test]
fn test_key_expiration() -> Result<(), Box<dyn Error>> {
    let tpm_provider = create_test_provider();
    let (private_key, public_key) = tpm_provider.generate_key(KeyType::Ed25519)?;
    
    // Add a key with 0 TTL (immediate expiration)
    let mut key_store = create_test_key_store();
    key_store.add_key(
        "test_key".to_string(),
        "ssh-key".to_string(),
        private_key,
        public_key,
        None,
        Some(0),
    )?;
    
    let mut ssh_agent = WindowsSSHAgent::new_test(tpm_provider, key_store);
    let cleaned = ssh_agent.cleanup_expired_keys();
    assert_eq!(cleaned, 1, "One key should have been cleaned up");
    assert_eq!(ssh_agent.list_keys().len(), 0, "No keys should remain after cleanup");
    
    Ok(())
}