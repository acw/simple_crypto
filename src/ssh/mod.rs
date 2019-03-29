mod errors;
mod frame;

pub use self::errors::SSHKeyParseError;

use cryptonum::unsigned::U192;
use dsa::{DSAPrivKey,L1024N160};
use self::frame::*;
use simple_asn1::from_der;
use std::fs::File;
use std::io;
use std::io::{Cursor,Read,Write};
use std::path::Path;

pub trait SSHKey: Sized {
    fn decode_ssh_private_key(x: &str) -> Result<Self,SSHKeyParseError>;
    fn read_ssh_private_key_file<P: AsRef<Path>>(path: P) -> Result<Self,SSHKeyParseError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::decode_ssh_private_key(&contents)
    }

    fn encode_ssh_private_key(&self) -> String;
    fn write_ssh_private_key_file<P: AsRef<Path>>(&self, path: P) -> Result<(),io::Error> {
        let mut file = File::create(path)?;
        let contents = self.encode_ssh_private_key();
        let bytes = contents.into_bytes();
        file.write_all(&bytes)?;
        file.sync_all()
    }
}


impl SSHKey for DSAPrivKey<L1024N160,U192> {
    fn decode_ssh_private_key(x: &str) -> Result<Self,SSHKeyParseError>
    {
        let bytes = parse_ssh_private_key_data(x)?;
        let mut byte_cursor = Cursor::new(bytes);

        parse_openssh_header(&mut byte_cursor)?;
        let ciphername = parse_openssh_string(&mut byte_cursor)?;
        //
        println!("bytes: {:?}", bytes);
        panic!("decode")
    }

    fn encode_ssh_private_key(&self) -> String {
        panic!("encode")
    }
}

#[cfg(test)]
#[test]
fn read_dsa_examples() {
    let test_files = ["dsa1024-1", "dsa1024-2", "dsa1024-3"];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        let privkey = DSAPrivKey::<L1024N160,U192>::read_ssh_private_key_file(path);
        assert!(privkey.is_ok());
    }
}