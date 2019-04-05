use base64::DecodeError;
use std::io;

#[derive(Debug)]
pub enum SSHKeyParseError
{
    DecodeError(DecodeError),
    IOError(io::Error),
    NoBeginBannerFound, NoEndBannerFound,
    NoOpenSSHMagicHeader,
    UnknownKeyCipher(String),
    UnknownKDF(String), UnexpectedKDFOptions,
    InvalidNumberOfKeys(u32),
    UnknownTrailingData,
    UnknownKeyType(String),
    InvalidPublicKeyMaterial,
    PrivateKeyCorruption,
    InconsistentKeyTypes(String,String),
    InconsistentPublicKeyValue,
    InvalidPrivateKeyValue,
    InvalidPadding
}

impl From<DecodeError> for SSHKeyParseError {
    fn from(e: DecodeError) -> SSHKeyParseError {
        SSHKeyParseError::DecodeError(e)
    }
}

impl From<io::Error> for SSHKeyParseError {
    fn from(e: io::Error) -> SSHKeyParseError {
        SSHKeyParseError::IOError(e)
    }
}

#[derive(Debug)]
pub enum SSHKeyRenderError {
    IOError(io::Error),
    StringTooLong,
    BufferTooLarge
}

impl From<io::Error> for SSHKeyRenderError {
    fn from(e: io::Error) -> SSHKeyRenderError {
        SSHKeyRenderError::IOError(e)
    }
}