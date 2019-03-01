use simple_asn1::ASN1DecodeErr;
use rand;

#[derive(Debug)]
pub enum DSAError {
    RandomGenError(rand::Error),
    ASN1DecodeErr(ASN1DecodeErr)
}

impl From<rand::Error> for DSAError {
    fn from(e: rand::Error) -> DSAError {
        DSAError::RandomGenError(e)
    }
}

impl From<ASN1DecodeErr> for DSAError {
    fn from(e: ASN1DecodeErr) -> DSAError {
        DSAError::ASN1DecodeErr(e)
    }
}