use colored::*;
use figlet_rs::FIGfont;
use log::{error, info};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use windows_ssh_agent::{KeyType, SSHAgentServer, WindowsSSHAgent};

fn print_banner() {
    let standard_font = FIGfont::standard().unwrap();
    let figure = standard_font.convert("TPM SSH Agent").unwrap();
    println!("\n{}", figure.to_string().bright_cyan());
    println!(
        "{}",
        "Secure SSH Agent with TPM Integration".bright_yellow()
    );
    println!("{}", "=================================".bright_yellow());
}

async fn cleanup_task(cleanup_server: Arc<tokio::sync::Mutex<SSHAgentServer>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;

        let result = async {
            let mut server = cleanup_server.lock().await;
            let cleaned = server.agent.cleanup_expired_keys();
            if cleaned > 0 {
                info!(
                    "{} {}",
                    "Cleaned up".green(),
                    format!("{} expired keys", cleaned).white()
                );
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .await;

        if let Err(e) = result {
            error!("{} {:?}", "Error in cleanup task:".red().bold(), e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    print_banner();

    info!("{}", "Starting SSH Agent...".green());
    let mut ssh_agent = match WindowsSSHAgent::new().await {
        Ok(agent) => agent,
        Err(e) => {
            error!("{} {}", "Failed to create SSH agent:".red().bold(), e);
            return Err(e);
        }
    };

    info!("{}", "Generating RSA 2048 private key...".green());
    let (rsa_private_key, rsa_public_key) = ssh_agent
        .tpm_provider
        .generate_key(KeyType::Rsa2048)
        .await
        .map_err(|e| {
            error!(
                "{} {:?}",
                "Failed to generate RSA 2048 key:".red().bold(),
                e
            );
            e
        })?;

    info!("{}", "Generating Ed25519 private key...".green());
    let (ed25519_private_key, ed25519_public_key) = ssh_agent
        .tpm_provider
        .generate_key(KeyType::Ed25519)
        .await
        .map_err(|e| {
            error!("{} {:?}", "Failed to generate Ed25519 key:".red().bold(), e);
            e
        })?;

    info!("{}", "Adding RSA key...".green());
    ssh_agent.add_key(rsa_private_key, rsa_public_key).await?;

    info!("{}", "Adding Ed25519 key...".green());
    ssh_agent
        .add_key(ed25519_private_key, ed25519_public_key)
        .await?;

    // List all keys
    println!("\n{}", "🔑 Current keys in store:".bright_yellow());
    println!("{}", "----------------------".bright_yellow());
    for key in ssh_agent.list_keys() {
        println!("{}:", "Key Details".cyan().bold());
        println!("  • ID: {}", key.key_id.to_string().white());
        println!("  • Type: {}", key.key_type.to_string().white());
        println!("  • Created: {}", key.created_at.to_string().white());
        println!("  • Last Used: {}", key.last_used.to_string().white());
    }

    let server = Arc::new(tokio::sync::Mutex::new(SSHAgentServer { agent: ssh_agent }));
    let cleanup_server = Arc::clone(&server);

    // Start the cleanup task
    tokio::spawn(cleanup_task(cleanup_server));

    info!("{}", "Starting SSH agent server...".green());

    // Handle graceful shutdown with Ctrl+C
    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        let mut server = server_clone.lock().await;
        if let Err(e) = server.start().await {
            error!("{} {:?}", "Server error:".red().bold(), e);
        }
    });

    // Wait for Ctrl+C signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("{}", "Shutting down SSH agent...".yellow());
        }
        Err(err) => {
            error!(
                "{} {:?}",
                "Unable to listen for shutdown signal:".red().bold(),
                err
            );
        }
    }

    info!("{}", "SSH Agent shutdown complete".green());
    Ok(())
}
