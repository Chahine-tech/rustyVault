pub mod aws;
pub mod gcp;
pub mod azure;
mod error;

pub use error::CloudError;

#[async_trait::async_trait]
pub trait CloudProvider: Send + Sync {
    /// Store a key in the cloud provider's storage.
    /// Returns a unique identifier for the stored key.
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError>;

    /// Retrieve a key from the cloud provider's storage using its identifier.
    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError>;

    /// Sign data using a key stored in the cloud provider.
    /// The key_id should be a valid key identifier previously returned by store_key.
    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError>;
}

/// Supported cloud provider implementations
#[derive(Debug)]
pub enum CloudProviderType {
    AWS(aws::AWSProvider),
    GCP(gcp::KmsProvider), 
    Azure(azure::AzureKmsProvider),
}