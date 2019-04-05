mod errors;
mod frame;

pub use self::errors::{SSHKeyParseError,SSHKeyRenderError};

use cryptonum::unsigned::*;
use dsa::{DSAKeyPair,DSAParameters,DSAPubKey,DSAPublicKey,DSAPrivKey,DSAPrivateKey,L1024N160};
use self::frame::*;
use std::fs::File;
use std::io::{Cursor,Read,Write};
use std::path::Path;
use super::KeyPair;

pub trait SSHKey: Sized + KeyPair {
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


impl SSHKey for DSAKeyPair<L1024N160> {
    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>
    {
        let pubkey_type = parse_openssh_string(inp)?;
        if pubkey_type != "ssh-dss" {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }
        let pubp = parse_openssh_number(inp)?;
        let pubq = parse_openssh_number(inp)?;
        let pubg = parse_openssh_number(inp)?;
        let pubparams = L1024N160::new(pubp, pubg, pubq);
        let puby: U1024 = parse_openssh_number(inp)?;
        for _ in inp.bytes() { return Err(SSHKeyParseError::UnknownTrailingData); }
        Ok(DSAPubKey::<L1024N160>::new(pubparams.clone(), puby.clone()))
    }

    fn parse_ssh_private_info<I: Read>(inp: &mut I) -> Result<(Self::Private,String),SSHKeyParseError>
    {
        let check1 = parse_openssh_u32(inp)?;
        let check2 = parse_openssh_u32(inp)?;
        if check1 != check2 {
            return Err(SSHKeyParseError::PrivateKeyCorruption);
        }
        let privkey_type = parse_openssh_string(inp)?;
        if privkey_type != "ssh-dss" {
            return Err(SSHKeyParseError::InconsistentKeyTypes("ssh-dss".to_string(), privkey_type));
        }
        let privp = parse_openssh_number(inp)?;
        let privq = parse_openssh_number(inp)?;
        let privg = parse_openssh_number(inp)?;
        let privparams = L1024N160::new(privp, privg, privq);
        let _     = parse_openssh_buffer(inp)?; // a copy of y we don't need
        let privx = parse_openssh_number(inp)?;

        let privkey = DSAPrivKey::<L1024N160>::new(privparams, privx);
        let comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        Ok((privkey,comment))
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-dss")?;
        render_openssh_number(out, &self.public.params.p)?;
        render_openssh_number(out, &self.public.params.q)?;
        render_openssh_number(out, &self.public.params.g)?;
        render_openssh_number(out, &self.public.y)
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O, comment: &str) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_u32(out, 0xDEADBEEF)?; // FIXME: Any reason for this to be random?
        render_openssh_u32(out, 0xDEADBEEF)?; // ditto
        render_openssh_string(out, "ssh-dss")?;
        render_openssh_number(out, &self.private.params.p)?;
        render_openssh_number(out, &self.private.params.q)?;
        render_openssh_number(out, &self.private.params.g)?;
        render_openssh_number(out, &self.public.y)?;
        render_openssh_number(out, &self.private.x)?;
        render_openssh_string(out, comment)?;
        // add some padding (not quite sure why)
        let mut i = comment.len();
        while (i % 16) != 0 {
            out.write(&[(i - comment.len() + 1) as u8])?;
            i += 1;
        }
        Ok(())
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
                            }
                        }
                    }
                }
            }
        }
    }
}