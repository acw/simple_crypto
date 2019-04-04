mod errors;
mod frame;

pub use self::errors::{SSHKeyParseError,SSHKeyRenderError};

use cryptonum::unsigned::*;
use dsa::{DSAKeyPair,DSAParameters,DSAPubKey,DSAPublicKey,DSAPrivKey,DSAPrivateKey,L1024N160};
use self::frame::*;
use std::fs::File;
use std::io::{Cursor,Read,Write};
use std::path::Path;

pub trait SSHKey: Sized {
    fn decode_ssh_private_key(x: &str) -> Result<(Self,String),SSHKeyParseError>;
    fn read_ssh_private_key_file<P: AsRef<Path>>(path: P) -> Result<(Self,String),SSHKeyParseError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::decode_ssh_private_key(&contents)
    }

    fn encode_ssh_private_key(&self, comment: &str) -> Result<String,SSHKeyRenderError>;
    fn write_ssh_private_key_file<P: AsRef<Path>>(&self, path: P, comment: &str) -> Result<(),SSHKeyRenderError> {
        let mut file = File::create(path)?;
        let contents = self.encode_ssh_private_key(comment)?;
        let bytes = contents.into_bytes();
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
}


impl SSHKey for DSAKeyPair<L1024N160> {
    fn decode_ssh_private_key(x: &str) -> Result<(Self,String),SSHKeyParseError>
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
        let pubkey = DSAPubKey::<L1024N160>::new(pubparams.clone(), puby.clone());

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

        let privkey = DSAPrivKey::<L1024N160>::new(pubparams, privx);
        let comment = parse_openssh_string(&mut privkey_cursor)?;
        for (idx,byte) in privkey_cursor.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        let result = DSAKeyPair{ public: pubkey, private: privkey };
        Ok((result,comment))
    }

    fn encode_ssh_private_key(&self, comment: &str) -> Result<String,SSHKeyRenderError> {
        // render the public key
        let mut pubkeybin = Vec::with_capacity(4096);
        render_openssh_string(&mut pubkeybin, "ssh-dss")?;
        render_openssh_number(&mut pubkeybin, &self.public.params.p)?;
        render_openssh_number(&mut pubkeybin, &self.public.params.q)?;
        render_openssh_number(&mut pubkeybin, &self.public.params.g)?;
        render_openssh_number(&mut pubkeybin, &self.public.y)?;

        // render the private key
        let mut privkeybin = Vec::with_capacity(4096);
        render_openssh_u32(&mut privkeybin, 0xDEADBEEF)?; // FIXME: Any reason for this to be random?
        render_openssh_u32(&mut privkeybin, 0xDEADBEEF)?; // ditto
        render_openssh_string(&mut privkeybin, "ssh-dss")?;
        render_openssh_number(&mut privkeybin, &self.private.params.p)?;
        render_openssh_number(&mut privkeybin, &self.private.params.q)?;
        render_openssh_number(&mut privkeybin, &self.private.params.g)?;
        render_openssh_number(&mut privkeybin, &self.public.y)?;
        render_openssh_number(&mut privkeybin, &self.private.x)?;
        render_openssh_string(&mut privkeybin, comment)?;
        // add some padding (not quite sure why)
        let mut i = 1;
        while (privkeybin.len() % 16) != 0 {
            privkeybin.push(i);
            i += 1;
        }

        let mut binary = Vec::with_capacity(16384);
        render_openssh_header(&mut binary)?;
        render_openssh_string(&mut binary, "none")?; // ciphername
        render_openssh_string(&mut binary, "none")?; // kdfname
        render_openssh_buffer(&mut binary, &[])?; // kdfoptions
        render_openssh_u32(&mut binary, 1)?; // numkeys
        render_openssh_buffer(&mut binary, &pubkeybin)?;
        render_openssh_buffer(&mut binary, &privkeybin)?;

        Ok(render_ssh_private_key_data(&binary))
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
        let mkeypair = DSAKeyPair::<L1024N160>::read_ssh_private_key_file(path);
        match mkeypair {
            Err(e) => assert!(false, format!("reading error: {:?}", e)),
            Ok((keypair,comment)) => {
                let buffer = [0,1,2,3,4,6,2];
                let sig = keypair.private.sign::<Sha256>(&buffer);
                assert!(keypair.public.verify::<Sha256>(&buffer, &sig));
                let buffer2 = [0,1,2,3,4,6,5];
                assert!(!keypair.public.verify::<Sha256>(&buffer2, &sig));
                match keypair.encode_ssh_private_key(&comment) {
                    Err(e2) => assert!(false, format!("render error: {:?}", e2)),
                    Ok(encodedstr) => {
                        match DSAKeyPair::<L1024N160>::decode_ssh_private_key(&encodedstr) {
                            Err(e3) => assert!(false, format!("reparse error: {:?}", e3)),
                            Ok((keypair2,comment2)) => {
                                assert_eq!(keypair.public.params.p,keypair2.public.params.p,"failed to reparse key pair (p)");
                                assert_eq!(keypair.public.params.q,keypair2.public.params.q,"failed to reparse key pair (q)");
                                assert_eq!(keypair.public.params.g,keypair2.public.params.g,"failed to reparse key pair (g)");
                                assert_eq!(keypair.private.params.p,keypair2.private.params.p,"failed to reparse key pair (p)");
                                assert_eq!(keypair.private.params.q,keypair2.private.params.q,"failed to reparse key pair (q)");
                                assert_eq!(keypair.private.params.g,keypair2.private.params.g,"failed to reparse key pair (g)");
                                assert_eq!(keypair.public.y,keypair2.public.y,"failed to reparse key pair (y)");
                                assert_eq!(keypair.private.x,keypair2.private.x,"failed to reparse key pair (x)");
                                assert_eq!(comment,comment2,"failed to reparse comment");
                            }
                        }
                    }
                }
            }
        }
    }
}