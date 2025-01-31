use crate::cloud::{CloudError, CloudProvider};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use crc32c::crc32c;
use google_cloud_googleapis::cloud::kms::v1::{
    crypto_key::CryptoKeyPurpose, crypto_key_version::CryptoKeyVersionAlgorithm,
    AsymmetricSignRequest, CreateCryptoKeyRequest, CryptoKey, CryptoKeyVersionTemplate,
    DecryptRequest, EncryptRequest, GetPublicKeyRequest, ProtectionLevel,
};
use google_cloud_kms::client::Client as KmsClient;

#[derive(Debug)]
pub struct KmsProvider {
    client: KmsClient,
    key_path: String,
}

impl KmsProvider {
    pub fn new(client: KmsClient, key_path: String) -> Self {
        Self { client, key_path }
    }

    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        let plaintext_crc32c = crc32c(data) as i64;
        let request = EncryptRequest {
            name: self.key_path.clone(),
            plaintext: data.to_vec(),
            plaintext_crc32c: Some(plaintext_crc32c),
            additional_authenticated_data: Vec::new(),
            additional_authenticated_data_crc32c: None,
        };

        let response = self
            .client
            .encrypt(request, None)
            .await
            .map_err(|e| CloudError::EncryptionError(e.to_string()))?;

        Ok(response.ciphertext)
    }

    #[allow(dead_code)]
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CloudError> {
        let ciphertext_crc32c = crc32c(ciphertext) as i64;
        let request = DecryptRequest {
            name: self.key_path.clone(),
            ciphertext: ciphertext.to_vec(),
            ciphertext_crc32c: Some(ciphertext_crc32c),
            additional_authenticated_data: Vec::new(),
            additional_authenticated_data_crc32c: None,
        };

        let response = self
            .client
            .decrypt(request, None)
            .await
            .map_err(|e| CloudError::DecryptionError(e.to_string()))?;

        Ok(response.plaintext)
    }
}

#[async_trait]
impl CloudProvider for KmsProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());

        let request = CreateCryptoKeyRequest {
            parent: self.key_path.clone(),
            crypto_key_id: key_id.clone(),
            crypto_key: Some(CryptoKey {
                purpose: CryptoKeyPurpose::EncryptDecrypt as i32,
                version_template: Some(CryptoKeyVersionTemplate {
                    algorithm: CryptoKeyVersionAlgorithm::GoogleSymmetricEncryption as i32,
                    protection_level: ProtectionLevel::Hsm as i32,
                }),
                ..Default::default()
            }),
            skip_initial_version_creation: false,
        };

        self.client
            .create_crypto_key(request, None)
            .await
            .map_err(|e| CloudError::StorageError(e.to_string()))?;

        let encrypted_key = self.encrypt(key).await?;
        let _key_b64 = BASE64.encode(encrypted_key);

        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let encrypted_key = self
            .client
            .get_public_key(
                GetPublicKeyRequest {
                    name: format!("{}/cryptoKeys/{}/cryptoKeyVersions/1", self.key_path, id),
                },
                None,
            )
            .await
            .map_err(|e| CloudError::RetrievalError(e.to_string()))?
            .pem;

        let encrypted_key = BASE64
            .decode(encrypted_key)
            .map_err(|e| CloudError::DecodingError(e.to_string()))?;

        match self.decrypt(&encrypted_key).await {
            Ok(key) => Ok(key),
            Err(e) => Err(CloudError::RetrievalError(format!(
                "Failed to decrypt key: {}",
                e
            ))),
        }
    }

    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        let data_crc32c = crc32c(data) as i64;
        let request = AsymmetricSignRequest {
            name: format!(
                "{}/cryptoKeys/{}/cryptoKeyVersions/1",
                self.key_path, key_id
            ),
            data: data.to_vec(),
            data_crc32c: Some(data_crc32c),
            ..Default::default()
        };

        let response = self
            .client
            .asymmetric_sign(request, None)
            .await
            .map_err(|e| CloudError::SigningError(e.to_string()))?;

        Ok(response.signature)
    }
}
