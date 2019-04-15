use cryptonum::unsigned::*;
use rsa::{RSAKeyPair,RSAPublicKey,RSAPrivateKey};
use std::io::{Read,Write};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use ssh::frame::*;
use ssh::SSHKey;

impl SSHKey for RSAKeyPair<U1024> {
    fn valid_keytype(s: &str) -> bool {
        (s == "ssh-rsa") || (s == "rsa")
    }

    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>
    {
        let pubkey_type = parse_openssh_string(inp)?;
        if !Self::valid_keytype(&pubkey_type) {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }
        let e = parse_openssh_number(inp)?;
        let n = parse_openssh_number(inp)?;
        Ok(RSAPublicKey::<U1024>::new(n, e))    
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
        let n = parse_openssh_number(inp)?;
        let _e: U1024 = parse_openssh_number(inp)?;
        let d = parse_openssh_number(inp)?;
        let _iqmp: U1024 = parse_openssh_number(inp)?;
        let _p: U1024 = parse_openssh_number(inp)?;
        let _q: U1024 = parse_openssh_number(inp)?;
        let comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        Ok((RSAPrivateKey::<U1024>::new(n, d), comment))
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-rsa")?;
        render_openssh_number(out, &self.public.e)?;
        render_openssh_number(out, &self.public.n)?;
        Ok(())
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O, comment: &str) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_u32(out, 0xDEADBEEF)?; // FIXME: Any reason for this to be random?
        render_openssh_u32(out, 0xDEADBEEF)?; // ditto
        render_openssh_string(out, "ssh-rsa")?;
        render_openssh_number(out, &self.public.n)?;
        render_openssh_number(out, &self.public.e)?;
        render_openssh_number(out, &self.private.d)?;
        render_openssh_number(out, &self.private.d)?;
        render_openssh_number(out, &self.private.d)?;
        render_openssh_number(out, &self.private.d)?;
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