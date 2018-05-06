use simple_asn1::ASN1DecodeErr;
use std::io;

#[derive(Debug)]
pub enum DSAError {
    ASN1DecodeErr(ASN1DecodeErr),
    InvalidParamSize
}

impl From<ASN1DecodeErr> for DSAError {
    fn from(e: ASN1DecodeErr) -> DSAError {
        DSAError::ASN1DecodeErr(e)
    }
}

#[derive(Debug)]
pub enum DSAGenError {
    RngFailure(io::Error),
    InvalidSeedLength, InvalidPrimeLength, TooManyGenAttempts
}

impl From<io::Error> for DSAGenError {
    fn from(e: io::Error) -> DSAGenError {
        DSAGenError::RngFailure(e)
    }
}


