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
            .plaintext(Blob::new(data.to_vec()))
            .send()
            .await
            .map_err(|e| CloudError::EncryptionError(e.to_string()))?;

        response
            .ciphertext_blob()
            .ok_or_else(|| CloudError::EncryptionError("No ciphertext in response".to_string()))
            .map(|blob| blob.as_ref().to_vec())
    }

    #[allow(dead_code)]
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CloudError> {
        let response = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext.to_vec()))
            .send()
            .await
            .map_err(|e| CloudError::DecryptionError(e.to_string()))?;

        response
            .plaintext()
            .ok_or_else(|| CloudError::DecryptionError("No plaintext in response".to_string()))
            .map(|text| text.as_ref().to_vec())
    }

    async fn get_encrypted_key(&self, key_id: &str) -> Result<Vec<u8>, CloudError> {
        // Recover encrypted key from AWS KMS
        let response = self
            .client
            .describe_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| CloudError::RetrievalError(e.to_string()))?;

        // Check that the key exists and is active
        let key_metadata = response
            .key_metadata()
            .ok_or_else(|| CloudError::RetrievalError("No key metadata in response".to_string()))?;

        // Check key status with appropriate Option management
        match key_metadata.key_state() {
            Some(state) => match state {
                aws_sdk_kms::types::KeyState::Enabled => {}
                other => {
                    return Err(CloudError::RetrievalError(format!(
                        "Key is not in enabled state: {:?}",
                        other
                    )))
                }
            },
            None => {
                return Err(CloudError::RetrievalError(
                    "Key state is not available".to_string(),
                ))
            }
        }

        // Generate a data key for this key_id
        let response = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| CloudError::RetrievalError(e.to_string()))?;

        response
            .ciphertext_blob()
            .ok_or_else(|| CloudError::RetrievalError("No ciphertext blob in response".to_string()))
            .map(|blob| blob.as_ref().to_vec())
    }
}

#[async_trait]
impl CloudProvider for AWSProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());
        let encrypted_key = self.encrypt(&key_id, key).await?;
        let _key_b64 = BASE64.encode(encrypted_key); // Prefix with underscore
        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let encrypted_key = self.get_encrypted_key(id).await?;

        match self.decrypt(id, &encrypted_key).await {
            Ok(key) => Ok(key),
            Err(e) => Err(CloudError::RetrievalError(format!(
                "Failed to decrypt key: {}",
                e
            ))),
        }
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
