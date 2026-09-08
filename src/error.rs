use thiserror::Error;

#[derive(Error, Debug)]
pub enum CynError {
    #[error("feed not found at {path}")]
    FeedNotFound { path: String },

    #[error("feed is invalid: {reason}")]
    FeedInvalid { reason: String },

    #[error("feed update failed: {0}")]
    FeedUpdate(String),

    #[error("scanner error: {0}")]
    Scanner(String),

    #[error("invalid scan target: {0}")]
    InvalidTarget(String),

    #[error("result parsing error: {0}")]
    ResultParse(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}
