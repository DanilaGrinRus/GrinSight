// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal error type for the standalone relay.
//!
//! The extracted gateway only needs I/O and request-validation failures; the
//! wallet, node and scan error variants of the upstream `flint-core` crate are
//! not part of this project. Keeping the type here (instead of pulling the whole
//! wallet error enum in) is what makes the relay wallet-free.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "ошибка ввода-вывода: {error}"),
            Self::Invalid(message) => write!(f, "неверные параметры: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
