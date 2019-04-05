mod dsa;
mod errors;
mod frame;

pub use self::errors::{SSHKeyParseError,SSHKeyRenderError};

use base64::{decode,encode};
use self::frame::*;
use std::fs::File;
use std::io::{Cursor,Read,Write};
use std::path::Path;
use super::KeyPair;

pub trait SSHKey: Sized + KeyPair {
    fn valid_keytype(s: &str) -> bool;

    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>;
    fn parse_ssh_private_info<I: Read>(inp: &mut I) -> Result<(Self::Private,String),SSHKeyParseError>;

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>;
    fn render_ssh_private_info<O: Write>(&self, out: &mut O, comment: &str) -> Result<(),SSHKeyRenderError>;
}

pub fn decode_ssh<KP: SSHKey>(x: &str) -> Result<(KP, String),SSHKeyParseError>
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

    let mut pubcursor = Cursor::new(pubkey0);
    let public = KP::parse_ssh_public_info(&mut pubcursor)?;
    let mut privcursor = Cursor::new(privkeys);
    let (private, comment) = KP::parse_ssh_private_info(&mut privcursor)?;

    Ok((KP::new(public, private), comment))
}

pub fn decode_ssh_pubkey<KP: SSHKey>(s: &str) -> Result<(KP::Public, String),SSHKeyParseError>
{
    let mut splitter = s.split_whitespace();

    match (splitter.next(), splitter.next(), splitter.next(), splitter.next()) {
        (Some(keytype), Some(keymaterial), Some(comment), None) => {
            if !KP::valid_keytype(keytype) {
                return Err(SSHKeyParseError::InvalidPublicKeyType);
            }

            let bytes = decode(keymaterial)?;
            let mut byte_cursor = Cursor::new(bytes);
            let key = KP::parse_ssh_public_info(&mut byte_cursor)?;

            Ok((key, comment.to_string()))
        }
        _ =>
            Err(SSHKeyParseError::BrokenPublicKeyLine)
    }
}

pub fn load_ssh_keyfile<KP,P>(path: P) -> Result<(KP, String),SSHKeyParseError>
 where
  KP: SSHKey,
  P: AsRef<Path>
{
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    decode_ssh(&contents)
}

pub fn load_ssh_pubkeys<KP,P>(path: P) -> Result<Vec<(KP::Public, String)>,SSHKeyParseError>
 where
  KP: SSHKey,
  P: AsRef<Path>
{
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut result = Vec::new();

    for line in contents.lines() {
        result.push( decode_ssh_pubkey::<KP>(line)? );
    }

    Ok(result)
}

pub fn encode_ssh<KP: SSHKey>(x: &KP, comment: &str) -> Result<String,SSHKeyRenderError>
{
    let mut pubkeybin = Vec::with_capacity(8192);
    let mut privkeybin = Vec::with_capacity(8192);
    let mut binary = Vec::with_capacity(16384);

    x.render_ssh_public_info(&mut pubkeybin)?;
    x.render_ssh_private_info(&mut privkeybin, comment)?;
    render_openssh_header(&mut binary)?;
    render_openssh_string(&mut binary, "none")?; // ciphername
    render_openssh_string(&mut binary, "none")?; // kdfname
    render_openssh_buffer(&mut binary, &[])?; // kdfoptions
    render_openssh_u32(&mut binary, 1)?; // numkeys
    render_openssh_buffer(&mut binary, &pubkeybin)?;
    render_openssh_buffer(&mut binary, &privkeybin)?;
    Ok(render_ssh_private_key_data(&binary))
}

pub fn write_ssh_keyfile<KP,P>(path: P, x: &KP, comment: &str) -> Result<(),SSHKeyRenderError>
 where
  KP: SSHKey,
  P: AsRef<Path>
{
    let mut file = File::create(path)?;
    let contents = encode_ssh(x, comment)?;
    let bytes = contents.into_bytes();
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())

}



#[cfg(test)]
use dsa::{DSAKeyPair,DSAPublicKey,DSAPrivateKey,DSAPubKey,L1024N160};
#[cfg(test)]
use sha2::Sha256;

#[cfg(test)]
#[test]
fn read_dsa_examples() {
    let test_files = ["dsa1024-1", "dsa1024-2", "dsa1024-3"];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        let mkeypair = load_ssh_keyfile(path);
        match mkeypair {
            Err(e) => assert!(false, format!("reading error: {:?}", e)),
            Ok((keypair, comment)) => {
                let buffer = [0,1,2,3,4,6,2];
                let _ : DSAKeyPair<L1024N160> = keypair;
                let sig = keypair.private.sign::<Sha256>(&buffer);
                assert!(keypair.public.verify::<Sha256>(&buffer, &sig));
                let buffer2 = [0,1,2,3,4,6,5];
                assert!(!keypair.public.verify::<Sha256>(&buffer2, &sig));
                match encode_ssh(&keypair, &comment) {
                    Err(e2) => assert!(false, format!("render error: {:?}", e2)),
                    Ok(encodedstr) => {
                        match decode_ssh(&encodedstr) {
                            Err(e3) => assert!(false, format!("reparse error: {:?}", e3)),
                            Ok((keypair2,comment2)) => {
                                let _ : DSAKeyPair<L1024N160> = keypair2;
                                assert_eq!(keypair.public.params.p,keypair2.public.params.p,"failed to reparse key pair (p)");
                                assert_eq!(keypair.public.params.q,keypair2.public.params.q,"failed to reparse key pair (q)");
                                assert_eq!(keypair.public.params.g,keypair2.public.params.g,"failed to reparse key pair (g)");
                                assert_eq!(keypair.private.params.p,keypair2.private.params.p,"failed to reparse key pair (p)");
                                assert_eq!(keypair.private.params.q,keypair2.private.params.q,"failed to reparse key pair (q)");
                                assert_eq!(keypair.private.params.g,keypair2.private.params.g,"failed to reparse key pair (g)");
                                assert_eq!(keypair.public.y,keypair2.public.y,"failed to reparse key pair (y)");
                                assert_eq!(keypair.private.x,keypair2.private.x,"failed to reparse key pair (x)");
                                assert_eq!(comment,comment2,"failed to reparse comment");
                                let ppath = format!("testdata/ssh/{}.pub",file);
                                match load_ssh_pubkeys::<DSAKeyPair<L1024N160>,String>(ppath) {
                                    Err(e4) => assert!(false, format!("pubkey error: {:?}", e4)),
                                    Ok(pubkeys) => {
                                        let _ : Vec<(DSAPubKey<L1024N160>,String)> = pubkeys;
                                        for (pubkey, comment3) in pubkeys {
                                            assert_eq!(pubkey.params.p, keypair.public.params.p, "public key check (p)");
                                            assert_eq!(pubkey.params.q, keypair.public.params.q, "public key check (q)");
                                            assert_eq!(pubkey.params.g, keypair.public.params.g, "public key check (g)");
                                            assert_eq!(pubkey.y,        keypair.public.y,        "public key check (y)");
                                            assert_eq!(comment,         comment3,                "public key check comment")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}