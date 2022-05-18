/// Wrapper Error enum used to provide a consistent [`IntoResponse`] target for
/// request handlers that return inner domain Error types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    ValidationError(String),

    #[error("Record not found.")]
    NotFoundError,

    #[error("Duplicate resource conflict.")]
    DuplicateResource,

    #[error("invalid authentication credentials")]
    InvalidAuthentication(anyhow::Error),

    #[error("Insufficient permission.")]
    InsufficientPermissionsError,

    #[error("Error processing JWT")]
    JWTError(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error("Database error")]
    SqlError(#[from] sqlx::Error),
}
