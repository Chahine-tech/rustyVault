use crate::cloud::{CloudError, CloudProvider};
use async_trait::async_trait;
use azure_security_keyvault::{prelude::SignatureAlgorithm, KeyvaultClient};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ring::rand::SystemRandom;
use ring::{
    digest::{Context, SHA256},
    signature::{self, Ed25519KeyPair, RsaKeyPair},
};

#[derive(Debug)]
pub struct AzureKmsProvider {
    client: KeyvaultClient,
}

impl AzureKmsProvider {
    pub fn new(client: KeyvaultClient) -> Self {
        Self { client }
    }

    pub async fn set_secret(
        &self,
        secret_name: &str,
        secret_value: &str,
    ) -> Result<(), CloudError> {
        self.client
            .secret_client()
            .set(secret_name, secret_value)
            .await
            .map_err(|e| CloudError::StorageError(e.to_string()))?;
        Ok(())
    }

    pub async fn get_secret(&self, secret_name: &str) -> Result<String, CloudError> {
        let secret = self
            .client
            .secret_client()
            .get(secret_name)
            .await
            .map_err(|e| CloudError::RetrievalError(e.to_string()))?;
        Ok(secret.value)
    }

    async fn sign_with_key(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, CloudError> {
        // Try to parse as Ed25519 key first
        if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(private_key) {
            let signature = key_pair.sign(data);
            return Ok(signature.as_ref().to_vec());
        }

        // If not Ed25519, try RSA
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();

        // Parse the private key as RSA
        let key_pair = RsaKeyPair::from_der(private_key)
            .map_err(|e| CloudError::SigningError(format!("Failed to parse RSA key: {}", e)))?;

        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                digest.as_ref(),
                &mut signature,
            )
            .map_err(|e| CloudError::SigningError(format!("Signing failed: {}", e)))?;

        Ok(signature)
    }
}

#[async_trait]
impl CloudProvider for AzureKmsProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());
        let key_b64 = BASE64.encode(key);

        self.set_secret(&key_id, &key_b64).await.map_err(|e| {
            CloudError::StorageError(format!("Failed to store key in Azure Key Vault: {}", e))
        })?;

        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let key_b64 = self
            .get_secret(id)
            .await
            .map_err(|e| CloudError::RetrievalError(e.to_string()))?;
        BASE64
            .decode(key_b64)
            .map_err(|e| CloudError::DecodingError(e.to_string()))
    }

    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        let signature = self
            .client
            .key_client()
            .sign(
                key_id,
                SignatureAlgorithm::RS256, // or appropriate algorithm
                BASE64.encode(data),       // Convert data to base64
            )
            .await
            .map_err(|e| CloudError::SigningError(e.to_string()))?;

        Ok(signature.signature)
    }
}
