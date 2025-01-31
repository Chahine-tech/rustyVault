use std::fmt;

#[derive(Debug)]
pub enum CloudError {
    EncryptionError(String),
    DecryptionError(String),
    SigningError(String),
    StorageError(String),
    RetrievalError(String),
    DecodingError(String),
    OperationNotSupported(String),
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CloudError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            CloudError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            CloudError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            CloudError::RetrievalError(msg) => write!(f, "Retrieval error: {}", msg),
            CloudError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            CloudError::OperationNotSupported(msg) => write!(f, "Operation not supported: {}", msg),
        }
    }
}

impl std::error::Error for CloudError {}
