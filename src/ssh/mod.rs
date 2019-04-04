mod errors;
mod frame;

pub use self::errors::SSHKeyParseError;

use cryptonum::unsigned::*;
use dsa::{DSAKeyPair,DSAParameters,DSAPubKey,DSAPublicKey,DSAPrivKey,DSAPrivateKey,L1024N160};
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


impl SSHKey for DSAKeyPair<L1024N160,U1024,U192> {
    fn decode_ssh_private_key(x: &str) -> Result<Self,SSHKeyParseError>
    {
        let bytes = parse_ssh_private_key_data(x)?;
        let data_size = bytes.len() as u64;
        let mut byte_cursor = Cursor::new(bytes);

        parse_openssh_header(&mut byte_cursor)?;
        let ciphername = parse_openssh_string(&mut byte_cursor)?;
        if ciphername != "none" {
            return Err(SSHKeyParseError::UnknownKeyCipher(ciphername));
        }
        let kdfname = parse_openssh_string(&mut byte_cursor)?;
        if kdfname != "none" {
            return Err(SSHKeyParseError::UnknownKeyCipher(kdfname));
        }
        let kdfoptions = parse_openssh_buffer(&mut byte_cursor)?;
        if kdfoptions.len() > 0 {
            return Err(SSHKeyParseError::UnexpectedKDFOptions);
        }
        let numkeys = parse_openssh_u32(&mut byte_cursor)?;
        if numkeys != 1 {
            return Err(SSHKeyParseError::InvalidNumberOfKeys(numkeys));
        }
        let pubkey0 = parse_openssh_buffer(&mut byte_cursor)?;
        let privkeys = parse_openssh_buffer(&mut byte_cursor)?;
        if byte_cursor.position() < data_size {
            return Err(SSHKeyParseError::UnknownTrailingData);

        }
        // Now that we've sorted out the details at this level,
        // see if we can decode the public key
        let mut pubkey_cursor = Cursor::new(pubkey0);
        let pubkey_type = parse_openssh_string(&mut pubkey_cursor)?;
        if pubkey_type != "ssh-dss" {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }

        let pubp = parse_openssh_number(&mut pubkey_cursor)?;
        let pubq = parse_openssh_number(&mut pubkey_cursor)?;
        let pubg = parse_openssh_number(&mut pubkey_cursor)?;
        let pubparams = L1024N160::new(pubp, pubg, pubq);
        let puby: U1024 = parse_openssh_number(&mut pubkey_cursor)?;
        let pubkey = DSAPubKey::<L1024N160,U1024>::new(pubparams.clone(), puby.clone());

        // And now we can look at the private key!
        let mut privkey_cursor = Cursor::new(privkeys);
        let check1 = parse_openssh_u32(&mut privkey_cursor)?;
        let check2 = parse_openssh_u32(&mut privkey_cursor)?;
        if check1 != check2 {
            return Err(SSHKeyParseError::PrivateKeyCorruption);
        }

        let privkey_type = parse_openssh_string(&mut privkey_cursor)?;
        if privkey_type != pubkey_type {
            return Err(SSHKeyParseError::InconsistentKeyTypes(pubkey_type, privkey_type));
        }

        let privp = parse_openssh_number(&mut privkey_cursor)?;
        let privq = parse_openssh_number(&mut privkey_cursor)?;
        let privg = parse_openssh_number(&mut privkey_cursor)?;
        let privparams = L1024N160::new(privp, privg, privq);
        let privy = parse_openssh_number(&mut privkey_cursor)?;
        let privx = parse_openssh_number(&mut privkey_cursor)?;
        if (pubparams != privparams) || (puby != privy) {
            return Err(SSHKeyParseError::InconsistentPublicKeyValue);
        }

        let privkey = DSAPrivKey::<L1024N160,U192>::new(pubparams, privx);
        let comment = parse_openssh_string(&mut privkey_cursor)?;
        for (idx,byte) in privkey_cursor.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        let result = DSAKeyPair{ public: pubkey, private: privkey };
        Ok(result)
    }

    fn encode_ssh_private_key(&self) -> String {
        panic!("encode")
    }
}

#[cfg(test)]
use sha2::Sha256;

#[cfg(test)]
#[test]
fn read_dsa_examples() {
    let test_files = ["dsa1024-1", "dsa1024-2", "dsa1024-3"];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        let mkeypair = DSAKeyPair::<L1024N160,U1024,U192>::read_ssh_private_key_file(path);
        match mkeypair {
            Err(e) => assert!(false, format!("reading error: {:?}", e)),
            Ok(keypair) => {
                let buffer = [0,1,2,3,4,6,2];
                let sig = keypair.private.sign::<Sha256>(&buffer);
                assert!(keypair.public.verify::<Sha256>(&buffer, &sig));
                let buffer2 = [0,1,2,3,4,6,5];
                assert!(!keypair.public.verify::<Sha256>(&buffer2, &sig));
            }
        }
    }
}