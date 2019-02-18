use dsa::rfc6979::DSADecodeError;
use ecdsa::ECDSADecodeErr;
use rsa::RSAError;
use simple_asn1::{ASN1DecodeErr,ASN1EncodeErr};

/// The error type for parsing and validating an X.509 certificate.
#[derive(Debug)]
pub enum X509ParseError {
    ASN1DecodeError(ASN1DecodeErr), ASN1EncodeError(ASN1EncodeErr),
    RSAError(RSAError), DSADecodeError(DSADecodeError), ECDSADecodeError(ECDSADecodeErr),
    RSASignatureWrong, DSASignatureWrong,
    NotEnoughData,
    IllFormedName, IllFormedAttrTypeValue, IllFormedInfoBlock,
    IllFormedValidity, IllFormedCertificateInfo, IllFormedSerialNumber,
    IllFormedAlgoInfo, IllFormedKey, IllFormedEverything,
    IllegalStringValue, NoSerialNumber, InvalidDSAInfo, ItemNotFound,
    UnknownAlgorithm, InvalidRSAKey, InvalidDSAKey, InvalidSignatureData,
    InvalidSignatureHash, InvalidECDSAKey, InvalidPointForm,
    UnknownEllipticCurve,
    CompressedPointUnsupported,
    KeyNotFound,
    SignatureNotFound, SignatureVerificationFailed
}

impl From<ASN1DecodeErr> for X509ParseError {
    fn from(e: ASN1DecodeErr) -> X509ParseError {
        X509ParseError::ASN1DecodeError(e)
    }
}

impl From<ASN1EncodeErr> for X509ParseError {
    fn from(e: ASN1EncodeErr) -> X509ParseError {
        X509ParseError::ASN1EncodeError(e)
    }
}

impl From<RSAError> for X509ParseError {
    fn from(e: RSAError) -> X509ParseError {
        X509ParseError::RSAError(e)
    }
}

impl From<ECDSADecodeErr> for X509ParseError {
    fn from(e: ECDSADecodeErr) -> X509ParseError {
        X509ParseError::ECDSADecodeError(e)
    }
}

impl From<DSADecodeError> for X509ParseError {
    fn from(e: DSADecodeError) -> X509ParseError {
        X509ParseError::DSADecodeError(e)
    }
}