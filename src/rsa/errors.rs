use simple_asn1::ASN1DecodeErr;
use rand;

#[derive(Debug)]
pub enum RSAError {
    BadMessageSize,
    KeyTooSmallForHash,
    DecryptionError,
    DecryptHashMismatch,
    InvalidKey,
    RandomGenError(rand::Error),
    ASN1DecodeErr(ASN1DecodeErr)
}

impl From<rand::Error> for RSAError {
    fn from(e: rand::Error) -> RSAError {
        RSAError::RandomGenError(e)
    }
}

impl From<ASN1DecodeErr> for RSAError {
    fn from(e: ASN1DecodeErr) -> RSAError {
        RSAError::ASN1DecodeErr(e)
    }
}


