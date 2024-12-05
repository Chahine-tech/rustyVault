use log::{error, info};
use std::error::Error;
use windows_ssh_agent::{KeyType, SSHAgentServer, WindowsSSHAgent};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let mut ssh_agent = WindowsSSHAgent::new()?;

    info!("Generating RSA 2048 private key...");
    let (rsa_private_key, rsa_public_key) = ssh_agent
        .tpm_provider
        .generate_key(KeyType::Rsa2048)
        .map_err(|e| {
            error!("Failed to generate RSA 2048 key: {:?}", e);
            e
        })?;

    info!("Generating Ed25519 private key...");
    let (ed25519_private_key, ed25519_public_key) = ssh_agent
        .tpm_provider
        .generate_key(KeyType::Ed25519)
        .map_err(|e| {
            error!("Failed to generate Ed25519 key: {:?}", e);
            e
        })?;

    info!("Adding RSA key...");
    ssh_agent.add_key(rsa_private_key, rsa_public_key)?;

    info!("Adding Ed25519 key...");
    ssh_agent.add_key(ed25519_private_key, ed25519_public_key)?;

    let mut server = SSHAgentServer { agent: ssh_agent };

    info!("Starting SSH agent server...");
    server.start()?;

    info!("SSH Agent initialization complete");

    Ok(())
}
