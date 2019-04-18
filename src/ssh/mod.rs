mod dsa;
mod ecdsa;
mod errors;
mod frame;
mod rsa;

pub use self::errors::{SSHKeyParseError,SSHKeyRenderError};

use base64::decode;
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
    fn render_ssh_private_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>;
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

    // create the public key bits
    x.render_ssh_public_info(&mut pubkeybin)?;
    // create the private key bits
    render_openssh_u32(&mut privkeybin, 0xDEADBEEF)?; // FIXME: Any reason for this to be random?
    render_openssh_u32(&mut privkeybin, 0xDEADBEEF)?; // ditto
    x.render_ssh_private_info(&mut privkeybin)?;
    render_openssh_string(&mut privkeybin, comment)?;
    // add some padding (not quite sure why)
    let mut i = comment.len();
    while (i % 16) != 0 {
        privkeybin.write(&[(i - comment.len() + 1) as u8])?;
        i += 1;
    }
    // render a bunch of the framing stuff
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
use dsa::{DSAKeyPair,DSAPublicKey,L1024N160};
#[cfg(test)]
use ecdsa::ECDSAPair;
#[cfg(test)]
use rsa::{RSAPair,RSAPublic,SIGNING_HASH_SHA256};
#[cfg(test)]
use sha2::Sha256;

#[cfg(test)]
#[test]
fn dsa_examples() {
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
                                        let _ : Vec<(DSAPublicKey<L1024N160>,String)> = pubkeys;
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

#[cfg(test)]
#[test]
fn rsa_examples() {
    let test_files = ["rsa1024-1", "rsa1024-2", "rsa1024-3",
                      "rsa2048-1", "rsa2048-2", "rsa2048-3",
                      "rsa3072-1", "rsa3072-2", "rsa3072-3",
                      "rsa4096-1", "rsa4096-2", "rsa4096-3",
                      "rsa8192-1", "rsa8192-2", "rsa8192-3"];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        let mkeypair = load_ssh_keyfile::<RSAPair,String>(path);
        match mkeypair {
            Err(e) => assert!(false, format!("reading error: {:?}", e)),
            Ok((keypair, comment)) => {
                let buffer = [0,1,2,3,4,6,2];
                let sig = keypair.sign(&SIGNING_HASH_SHA256, &buffer);
                assert!(keypair.verify(&SIGNING_HASH_SHA256, &buffer, &sig));
                match encode_ssh(&keypair, &comment) {
                    Err(e2) => assert!(false, format!("render error: {:?}", e2)),
                    Ok(encodedstr) => {
                        match decode_ssh(&encodedstr) {
                            Err(e3) => assert!(false, format!("reparse error: {:?}", e3)),
                            Ok((keypair2,comment2)) => {
                                assert_eq!(keypair,keypair2,"failed to reparse key pair");
                                assert_eq!(comment,comment2,"failed to reparse comment");
                                let ppath = format!("testdata/ssh/{}.pub",file);
                                match load_ssh_pubkeys::<RSAPair,String>(ppath) {
                                    Err(e4) => assert!(false, format!("pubkey error: {:?}", e4)),
                                    Ok(pubkeys) => {
                                        let _ : Vec<(RSAPublic,String)> = pubkeys;
                                        for (pubkey, comment3) in pubkeys {
                                            assert_eq!(pubkey,  keypair.public(), "public key check");
                                            assert_eq!(comment, comment3,         "public key check comment");
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

#[cfg(test)]
#[test]
fn ecdsa_examples() {
    let test_files = ["ecdsa256-1", "ecdsa256-2", "ecdsa256-3",
                      "ecdsa384-1", "ecdsa384-2", "ecdsa384-3",
                      "ecdsa521-1", "ecdsa521-2", "ecdsa521-3"];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        match load_ssh_keyfile::<ECDSAPair,String>(path) {
            Err(e) =>
                assert!(false, "SSH ECDSA parse error: {:?}", e),
            Ok((keypair,comment)) => {
                // first see if this roundtrips
                let buffer = vec![0,1,2,4,5,6,9];
                match keypair {
                    ECDSAPair::P192(_,_) =>
                        assert!(false, "Somehow got a P192 in read test"),
                    ECDSAPair::P224(_,_) =>
                        assert!(false, "Somehow got a P224 in read test"),
                    ECDSAPair::P256(ref pu, ref pr) => {
                        let sig = pr.sign::<Sha256>(&buffer);
                        assert!(pu.verify::<Sha256>(&buffer, &sig));
                    }
                    ECDSAPair::P384(ref pu, ref pr) => {
                        let sig = pr.sign::<Sha256>(&buffer);
                        assert!(pu.verify::<Sha256>(&buffer, &sig));
                    }
                    ECDSAPair::P521(ref pu, ref pr) => {
                        let sig = pr.sign::<Sha256>(&buffer);
                        assert!(pu.verify::<Sha256>(&buffer, &sig));
                    }
                }
                // encode this, parse it again
                match encode_ssh(&keypair, &comment) {
                    Err(e) =>
                        assert!(false, "SSH ECDSA encoding error: {:?}", e),
                    Ok(coded) => {
                       match (decode_ssh(&coded), keypair) {
                           (Err(e), _) =>
                             assert!(false, "SSSH ECDSA redecoding error: {:?}", e),
                           (Ok((ECDSAPair::P256(pu2, pr2), comment2)), ECDSAPair::P256(pu,pr)) => {
                               assert_eq!(pu, pu2, "public key mismatch");
                               assert_eq!(pr, pr2, "public key mismatch");
                               assert_eq!(comment, comment2, "comment mismatch");
                           }
                           (Ok((ECDSAPair::P384(pu2, pr2), comment2)), ECDSAPair::P384(pu,pr)) => {
                               assert_eq!(pu, pu2, "public key mismatch");
                               assert_eq!(pr, pr2, "public key mismatch");
                               assert_eq!(comment, comment2, "comment mismatch");
                           }
                           (Ok((ECDSAPair::P521(pu2, pr2), comment2)), ECDSAPair::P521(pu,pr)) => {
                               assert_eq!(pu, pu2, "public key mismatch");
                               assert_eq!(pr, pr2, "public key mismatch");
                               assert_eq!(comment, comment2, "comment mismatch");
                           }
                           _ =>
                             assert!(false, "Failed to accurately re-parse key")
                       } 
                    }
                }
            }
        }
    }
}
 