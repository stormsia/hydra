use std::fmt;
use std::io;

#[derive(Debug)]
pub enum JudgeError {
    Io(io::Error),
    Tls(String),
    Config(String),
    Http(String),
}

impl fmt::Display for JudgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Config(e) => write!(f, "Config error: {e}"),
            Self::Http(e) => write!(f, "HTTP error: {e}"),
        }
    }
}

impl std::error::Error for JudgeError {}

impl From<io::Error> for JudgeError {
    #[inline]
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
