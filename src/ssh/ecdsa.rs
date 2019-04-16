use cryptonum::unsigned::*;
use ecdsa::{ECDSAPair,ECDSAPublic,ECCPublicKey,ECDSAPrivate,ECCPrivateKey};
use std::io::{Read,Write};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use ssh::frame::*;
use ssh::SSHKey;

impl SSHKey for ECDSAPair {
    fn valid_keytype(s: &str) -> bool {
        (s == "ssh-ecdsa") || (s == "ecdsa") || (s == "ecdsa-sha2-nistp256") ||
        (s == "ecdsa-sha2-nistp384") || (s == "ecdsa-sha2-nistp521")
    }

    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>
    {
        let pubkey_type = parse_openssh_string(inp)?;
        if !Self::valid_keytype(&pubkey_type) {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }
        // this peaks a little under the cover a bit (it'd be nice to pretend
        // that we didn't know the number format was the same as the buffer
        // one), but we need to infer what kind of key this is, and this appears
        // to be the easiest / fastest way.
        let mut ebuf = parse_openssh_buffer(inp)?;
        let mut ibuf = parse_openssh_buffer(inp)?;

        while ebuf[0] == 0 { ebuf.remove(0); }
        while ibuf[0] == 0 { ibuf.remove(0); }

        println!("ebuf: {:?}", ebuf);
        println!("ibuf: {:?}", ibuf);
        panic!("parse public info")
    }

    fn parse_ssh_private_info<I: Read>(inp: &mut I) -> Result<(Self::Private,String),SSHKeyParseError>
    {
        let check1 = parse_openssh_u32(inp)?;
        let check2 = parse_openssh_u32(inp)?;
        if check1 != check2 {
            return Err(SSHKeyParseError::PrivateKeyCorruption);
        }
        let privkey_type = parse_openssh_string(inp)?;
        if !Self::valid_keytype(&privkey_type) {
            return Err(SSHKeyParseError::InconsistentKeyTypes("ssh-rsa".to_string(), privkey_type));
        }

        let  comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        panic!("parse private_info")
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-ecdsa")?;
        panic!("render public info")
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O, comment: &str) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_u32(out, 0xDEADBEEF)?; // FIXME: Any reason for this to be random?
        render_openssh_u32(out, 0xDEADBEEF)?; // ditto
        render_openssh_string(out, "ssh-ecdsa")?;
        panic!("render private info");
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
