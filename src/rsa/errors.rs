use simple_asn1::ASN1DecodeErr;
use std::io;

#[derive(Debug)]
pub enum RSAError {
    BadMessageSize,
    KeyTooSmallForHash,
    DecryptionError,
    DecryptHashMismatch,
    InvalidKey,
    RandomGenError(io::Error),
    ASN1DecodeErr(ASN1DecodeErr)
}

impl From<io::Error> for RSAError {
    fn from(e: io::Error) -> RSAError {
        RSAError::RandomGenError(e)
    }
}

impl From<ASN1DecodeErr> for RSAError {
    fn from(e: ASN1DecodeErr) -> RSAError {
        RSAError::ASN1DecodeErr(e)
    }
}


