use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Error::ValidationError(s) => (StatusCode::BAD_REQUEST, s),
            Error::NotFoundError => (StatusCode::NOT_FOUND, self.to_string()),
            Error::DuplicateResource => (StatusCode::CONFLICT, self.to_string()),
            Error::InvalidAuthentication(_e) => {
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
            Error::InsufficientPermissionsError => (StatusCode::FORBIDDEN, self.to_string()),
            Error::JWTError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Error::UnexpectedError(_e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".into(),
            ),
            Error::SqlError(e) => match e {
                sqlx::Error::RowNotFound => {
                    (StatusCode::NOT_FOUND, Error::NotFoundError.to_string())
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            },
        };
        let body = Json(json!({ "error": message }));

        (status, body).into_response()
    }
}
