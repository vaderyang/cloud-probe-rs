//! Error handling compatible with the original fixed-size `errbuf` convention.

use std::fmt;

/// Size of the fixed error buffer used by the C implementation.
pub const ERROR_BUFFER_SIZE: usize = 256;

/// A simple string-backed error. Mirrors the C `errbuf` mechanism where callers
/// pass a mutable 256-byte buffer that gets filled with a message on failure.
#[derive(Debug, Clone)]
pub struct Error(pub String);

impl Error {
    /// Create an error from an owned or borrowed message.
    pub fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error(format!("{e:#}"))
    }
}

/// Convenience alias for results carrying this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Write `msg` into an errbuf, truncating to `ERROR_BUFFER_SIZE` including NUL
/// on the C side. Here we simply replace the contents.
pub fn set_errbuf(errbuf: &mut String, msg: impl Into<String>) {
    *errbuf = msg.into();
}
