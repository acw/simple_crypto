use base64::DecodeError;
use ed25519::ED25519PublicImportError;
use std::io;

/// A whole pile of errors that you can get when parsing an SSH key from
/// disk or memory.
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
    InvalidPadding,
    InvalidPublicKeyType,
    BrokenPublicKeyLine,
    UnknownECDSACurve(String),
    InvalidECPointCompression
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

impl From<ED25519PublicImportError> for SSHKeyParseError {
    fn from(e: ED25519PublicImportError) -> SSHKeyParseError {
        match e {
            ED25519PublicImportError::WrongNumberOfBytes(_) =>
                SSHKeyParseError::InvalidPublicKeyMaterial,
            ED25519PublicImportError::InvalidPublicPoint =>
                SSHKeyParseError::InvalidPublicKeyMaterial,
        }
    }
}

/// A much smaller set of errors you can get when rendering an SSH key into
/// a file or memory block.
#[derive(Debug)]
pub enum SSHKeyRenderError {
    IOError(io::Error),
    StringTooLong,
    BufferTooLarge,
    IllegalECDSAKeyType(String)
}

impl From<io::Error> for SSHKeyRenderError {
    fn from(e: io::Error) -> SSHKeyRenderError {
        SSHKeyRenderError::IOError(e)
    }
}