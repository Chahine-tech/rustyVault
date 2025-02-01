use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use windows_ssh_agent::{CloudError, CloudProvider};

// Mock key storage for testing purposes
#[derive(Debug, Default)]
struct MockKeyStore {
    keys: HashMap<String, Vec<u8>>,
}

// AWS Provider Mock Implementation
#[derive(Debug, Default)]
struct MockAWSProvider {
    store: Arc<Mutex<MockKeyStore>>,
}

#[async_trait]
impl CloudProvider for MockAWSProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("mock_aws_key_{}", chrono::Utc::now().timestamp());
        let mut store = self.store.lock().await;
        store.keys.insert(key_id.clone(), key.to_vec());
        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let store = self.store.lock().await;
        store
            .keys
            .get(id)
            .cloned()
            .ok_or_else(|| CloudError::RetrievalError("Key not found".to_string()))
    }

    async fn sign_data(&self, _key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        // Simple bitwise NOT signature simulation
        Ok(data.iter().map(|b| !b).collect())
    }
}

// Azure Provider Mock Implementation
#[derive(Debug, Default)]
struct MockAzureProvider {
    store: Arc<Mutex<MockKeyStore>>,
}

#[async_trait]
impl CloudProvider for MockAzureProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("mock_azure_key_{}", chrono::Utc::now().timestamp());
        let mut store = self.store.lock().await;
        store.keys.insert(key_id.clone(), key.to_vec());
        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let store = self.store.lock().await;
        store
            .keys
            .get(id)
            .cloned()
            .ok_or_else(|| CloudError::RetrievalError("Key not found".to_string()))
    }

    async fn sign_data(&self, _key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        // Base64 encoded data simulation
        Ok(BASE64.encode(data).into_bytes())
    }
}

// GCP Provider Mock Implementation
#[derive(Debug, Default)]
struct MockGCPProvider {
    store: Arc<Mutex<MockKeyStore>>,
}

#[async_trait]
impl CloudProvider for MockGCPProvider {
    async fn store_key(&self, key: &[u8]) -> Result<String, CloudError> {
        let key_id = format!("mock_gcp_key_{}", chrono::Utc::now().timestamp());
        let mut store = self.store.lock().await;
        store.keys.insert(key_id.clone(), key.to_vec());
        Ok(key_id)
    }

    async fn retrieve_key(&self, id: &str) -> Result<Vec<u8>, CloudError> {
        let store = self.store.lock().await;
        store
            .keys
            .get(id)
            .cloned()
            .ok_or_else(|| CloudError::RetrievalError("Key not found".to_string()))
    }

    async fn sign_data(&self, _key_id: &str, data: &[u8]) -> Result<Vec<u8>, CloudError> {
        // Double data simulation
        Ok(data.repeat(2))
    }
}

// Test Suite
#[tokio::test]
async fn test_aws_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAWSProvider::default();

    // Test key lifecycle operations
    let test_key = b"test_aws_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Test signature generation
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert!(!signature.is_empty(), "Signature should not be empty");

    // Test error handling for non-existent key
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err(), "Should return error for non-existent key");

    Ok(())
}

#[tokio::test]
async fn test_azure_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAzureProvider::default();

    // Validate key storage and retrieval
    let test_key = b"test_azure_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Verify signature format
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert!(!signature.is_empty(), "Azure signature should not be empty");

    // Validate error case
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err(), "Azure should error on missing key");

    Ok(())
}

#[tokio::test]
async fn test_gcp_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockGCPProvider::default();

    // Test basic operations
    let test_key = b"test_gcp_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Check signature format
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert_eq!(
        signature,
        test_data.repeat(2),
        "GCP signature should be doubled data"
    );

    // Test error scenario
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err(), "GCP should return error for missing key");

    Ok(())
}

// Error Case Validation
#[tokio::test]
async fn test_error_cases() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAWSProvider::default();

    // Test invalid key retrieval
    let result = provider.retrieve_key("invalid_key").await;
    assert!(
        matches!(result, Err(CloudError::RetrievalError(_))),
        "Should return RetrievalError type"
    );

    // Test empty key storage
    let result = provider.store_key(&[]).await;
    assert!(result.is_ok(), "Should accept empty keys for storage");

    // Test signature with invalid key (mock doesn't validate keys)
    let result = provider.sign_data("invalid_key", b"test_data").await;
    assert!(
        result.is_ok(),
        "Mock implementation should accept any key ID"
    );

    Ok(())
}
