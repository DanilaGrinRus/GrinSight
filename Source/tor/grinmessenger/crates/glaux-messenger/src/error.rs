// SPDX-License-Identifier: MIT OR Apache-2.0
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("адрес: {0}")]
    Address(String),
    #[error("криптография: {0}")]
    Crypto(String),
    #[error("конверт: {0}")]
    Envelope(String),
    #[error("хранилище: {0}")]
    Store(String),
    #[error("получатель не совпадает с адресом конверта")]
    WrongRecipient,
    #[error("срок сообщения истёк")]
    Expired,
    #[error("неподдерживаемая версия конверта: {0}")]
    Version(u8),
    #[error("подпись отправителя неверна")]
    BadSignature,
    #[error("plaintext-slatepack запрещён в мессенджере")]
    PlaintextSlatepack,
    #[error("превышена квота: {0}")]
    Quota(String),
    #[error("TTL вне допустимого диапазона: {0}")]
    BadTtl(u64),
}

pub type Result<T> = std::result::Result<T, Error>;
