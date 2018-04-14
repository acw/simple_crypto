use std::io;

#[derive(Debug)]
pub enum RSAKeyGenError {
    InvalidKeySize(usize), RngFailure(io::Error)
}

impl From<io::Error> for RSAKeyGenError {
    fn from(e: io::Error) -> RSAKeyGenError {
        RSAKeyGenError::RngFailure(e)
    }
}


