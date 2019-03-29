use base64::DecodeError;
use simple_asn1::ASN1DecodeErr;
use std::io;

#[derive(Debug)]
pub enum SSHKeyParseError
{
    ASN1Error(ASN1DecodeErr),
    DecodeError(DecodeError),
    IOError(io::Error),
    NoBeginBannerFound, NoEndBannerFound,
    NoOpenSSHMagicHeader
}

impl From<ASN1DecodeErr> for SSHKeyParseError {
    fn from(e: ASN1DecodeErr) -> SSHKeyParseError {
        println!("asn1 error: {:?}", e);
        SSHKeyParseError::ASN1Error(e)
    }
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

pub enum SSHKeyRenderError {
    IOError(io::Error),
}

impl From<io::Error> for SSHKeyRenderError {
    fn from(e: io::Error) -> SSHKeyRenderError {
        SSHKeyRenderError::IOError(e)
    }
}