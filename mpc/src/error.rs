use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    InvalidInput(String),
    InternalError(String),
    DatabaseError(String),
    SerializationError(String),
    NetworkError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

impl std::error::Error for Error {}

impl From<Error> for actix_web::Error {
    fn from(err: Error) -> Self {
        actix_web::Error::from(Box::new(err) as Box<dyn std::error::Error>)
    }
}