use std::error::Error;
use windows_ssh_agent::{KeyType, WindowsSSHAgent};

#[test]
fn test_windows_ssh_agent_creation() -> Result<(), Box<dyn Error>> {
    let ssh_agent = WindowsSSHAgent::new()?;
    assert_eq!(
        ssh_agent.key_count(),
        0,
        "New SSH agent should have zero keys"
    );
    Ok(())
}

#[test]
fn test_key_generation_and_addition() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = WindowsSSHAgent::new()?;

    let (rsa_private_key, rsa_public_key) =
        ssh_agent.tpm_provider.generate_key(KeyType::Rsa2048)?;

    ssh_agent.add_key(rsa_private_key.clone(), rsa_public_key.clone())?;
    assert_eq!(
        ssh_agent.key_count(),
        1,
        "SSH agent should have one key after addition"
    );

    let (ed25519_private_key, ed25519_public_key) =
        ssh_agent.tpm_provider.generate_key(KeyType::Ed25519)?;

    ssh_agent.add_key(ed25519_private_key, ed25519_public_key)?;
    assert_eq!(
        ssh_agent.key_count(),
        2,
        "SSH agent should have two keys after second addition"
    );

    Ok(())
}

#[test]
fn test_key_signing() -> Result<(), Box<dyn Error>> {
    let mut ssh_agent = WindowsSSHAgent::new()?;
    
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
fn test_sign_with_nonexistent_key() {
    let ssh_agent = WindowsSSHAgent::new().unwrap();

    let test_data = b"Test signing";
    let fake_public_key = vec![0, 1, 2, 3];

    let result = ssh_agent.sign_data(&fake_public_key, test_data);
    assert!(result.is_err(), "Signing with non-existent key should fail");
}
