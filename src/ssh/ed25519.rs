use ed25519::{ED25519KeyPair,ED25519Private,ED25519Public};
use std::io::{Read,Write};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use ssh::frame::*;
use ssh::SSHKey;

impl SSHKey for ED25519KeyPair {
    fn valid_keytype(s: &str) -> bool {
        (s == "ssh-ed25519")
    }

    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>
    {
        let pubkey_type = parse_openssh_string(inp)?;
        if !Self::valid_keytype(&pubkey_type) {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }
        let pubkey_bytes = parse_openssh_buffer(inp)?;
        Ok(ED25519Public::new(&pubkey_bytes)?)
    }

    fn parse_ssh_private_info<I: Read>(inp: &mut I) -> Result<(Self::Private,String),SSHKeyParseError>
    {
        let check1 = parse_openssh_u32(inp)?;
        let check2 = parse_openssh_u32(inp)?;
        if check1 != check2 {
            return Err(SSHKeyParseError::PrivateKeyCorruption);
        }
        let public = ED25519KeyPair::parse_ssh_public_info(inp)?;
        let private_bytes = parse_openssh_buffer(inp)?; 
        let private = ED25519Private::from_seed(&private_bytes[0..32]);
        let comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }
        assert_eq!(public, ED25519Public::from(&private));

        Ok((private, comment))
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-ed25519")?;
        render_openssh_buffer(out, &self.public.to_bytes())?;
        Ok(())
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        self.render_ssh_public_info(out)?;
        let mut private_bytes = self.private.to_bytes();
        private_bytes.append(&mut self.public.to_bytes());
        render_openssh_buffer(out, &private_bytes)?;
        Ok(())
    }
}