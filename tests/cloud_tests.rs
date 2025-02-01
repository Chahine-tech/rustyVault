use windows_ssh_agent::{CloudProvider, CloudError};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Structure Mock pour simuler le stockage
#[derive(Debug, Default)]
struct MockKeyStore {
    keys: HashMap<String, Vec<u8>>,
}

// Mock pour AWS
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
        // Simuler une signature simple pour les tests
        Ok(data.iter().map(|b| !b).collect())
    }
}

// Mock pour Azure
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
        // Simuler une signature simple pour les tests
        Ok(BASE64.encode(data).into_bytes())
    }
}

// Mock pour GCP
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
        // Simuler une signature simple pour les tests
        Ok(data.repeat(2))
    }
}

// Tests
#[tokio::test]
async fn test_aws_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAWSProvider::default();
    
    // Test key storage and retrieval
    let test_key = b"test_aws_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Test signing
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert!(!signature.is_empty());
    
    // Test error case
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_azure_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAzureProvider::default();
    
    // Test key storage and retrieval
    let test_key = b"test_azure_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Test signing
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert!(!signature.is_empty());
    
    // Test error case
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_gcp_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockGCPProvider::default();
    
    // Test key storage and retrieval
    let test_key = b"test_gcp_key";
    let key_id = provider.store_key(test_key).await?;
    let retrieved_key = provider.retrieve_key(&key_id).await?;
    assert_eq!(test_key.to_vec(), retrieved_key);

    // Test signing
    let test_data = b"test_data";
    let signature = provider.sign_data(&key_id, test_data).await?;
    assert!(!signature.is_empty());
    
    // Test error case
    let result = provider.retrieve_key("nonexistent_key").await;
    assert!(result.is_err());

    Ok(())
}

// Test des cas d'erreur spécifiques
#[tokio::test]
async fn test_error_cases() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockAWSProvider::default();

    // Test avec une clé invalide
    let result = provider.retrieve_key("invalid_key").await;
    assert!(matches!(result, Err(CloudError::RetrievalError(_))));

    // Test avec des données vides
    let result = provider.store_key(&[]).await;
    assert!(result.is_ok()); // Devrait accepter une clé vide

    // Test de signature avec une clé invalide
    let result = provider.sign_data("invalid_key", b"test_data").await;
    assert!(!result.is_err()); // Notre mock ne vérifie pas la validité de la clé pour la signature

    Ok(())
} 