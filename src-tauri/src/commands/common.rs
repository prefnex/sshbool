//! Helpers shared by command modules.

use crate::error::AppError;

/// Map a local SQLite error to the IPC error type.
pub(crate) fn db(e: sqlx::Error) -> AppError {
    AppError::Db {
        engine: "sqlite".into(),
        message: e.to_string(),
    }
}
