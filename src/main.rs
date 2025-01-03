use log::{error, info};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows_ssh_agent::{KeyType, SSHAgentServer, WindowsSSHAgent};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting SSH Agent...");
    let mut ssh_agent = match WindowsSSHAgent::new() {
        Ok(agent) => agent,
        Err(e) => {
            error!("Failed to create SSH agent: {}", e);
            return Err(e);
        }
    };

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

    // List all keys
    info!("Current keys in store:");
    for key in ssh_agent.list_keys() {
        info!(
            "Key ID: {}, Type: {}, Created: {}, Last Used: {}",
            key.key_id, key.key_type, key.created_at, key.last_used
        );
    }

    let server = Arc::new(Mutex::new(SSHAgentServer { agent: ssh_agent }));
    let cleanup_server = Arc::clone(&server);

    // Start a background thread for key cleanup
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(3600)); // Check every hour
            if let Err(e) = std::panic::catch_unwind(|| {
                if let Ok(mut server) = cleanup_server.lock() {
                    let cleaned = server.agent.cleanup_expired_keys();
                    if cleaned > 0 {
                        info!("Cleaned up {} expired keys", cleaned);
                    }
                }
            }) {
                error!("Error in cleanup thread: {:?}", e);
            }
        }
    });

    info!("Starting SSH agent server...");
    match server.lock() {
        Ok(mut server) => server.start()?,
        Err(e) => {
            error!("Failed to acquire lock for server: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to start server",
            )));
        }
    }

    info!("SSH Agent initialization complete");

    Ok(())
}
