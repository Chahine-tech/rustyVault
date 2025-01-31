use crate::cloud::{CloudError, CloudProvider};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client as KmsClient;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

#[derive(Debug)]
pub struct AWSProvider {
    client: KmsClient,
}

impl AWSProvider {
    pub fn new(client: KmsClient) -> Self {
        Self { client }
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        let response = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::new(data.to_vec())) // Convertir Vec<u8> en Blob
            .send()
            .await
            .map_err(|e| CloudError::EncryptionError(e.to_string()))?;

        response
            .ciphertext_blob()
            .ok_or_else(|| CloudError::EncryptionError("No ciphertext in response".to_string()))
            .map(|blob| blob.as_ref().to_vec()) // Convertir Blob en Vec<u8>
    }

    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CloudError> {
        let response = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext.to_vec())) // Convertir Vec<u8> en Blob
            .send()
            .await
            .map_err(|e| CloudError::DecryptionError(e.to_string()))?;

        response
            .plaintext()
            .ok_or_else(|| CloudError::DecryptionError("No plaintext in response".to_string()))
            .map(|text| text.as_ref().to_vec()) // Convertir Blob en Vec<u8>
    }
}

#[async_trait]
impl CloudProvider for AWSProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());
        let encrypted_key = self.encrypt(&key_id, key).await?;
        let key_b64 = BASE64.encode(encrypted_key);

        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        Err(CloudError::OperationNotSupported(
            "Key retrieval not implemented for AWS KMS".to_string(),
        ))
    }

    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        let response = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(data.to_vec())) // Convertir Vec<u8> en Blob
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPssSha256)
            .send()
            .await
            .map_err(|e| CloudError::SigningError(e.to_string()))?;

        response
            .signature()
            .ok_or_else(|| CloudError::SigningError("No signature in response".to_string()))
            .map(|sig| sig.as_ref().to_vec()) // Convertir Blob en Vec<u8>
    }
}
