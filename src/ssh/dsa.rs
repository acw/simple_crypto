use cryptonum::unsigned::*;
use dsa::{DSAKeyPair,DSAParameters,DSAPublicKey,DSAPrivateKey,L1024N160};
use std::io::{Read,Write};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use ssh::frame::*;
use ssh::SSHKey;

impl SSHKey for DSAKeyPair<L1024N160> {
    fn valid_keytype(s: &str) -> bool {
        (s == "ssh-dss") || (s == "dss")
    }

    fn parse_ssh_public_info<I: Read>(inp: &mut I) -> Result<Self::Public,SSHKeyParseError>
    {
        let pubkey_type = parse_openssh_string(inp)?;
        if !Self::valid_keytype(&pubkey_type) {
            return Err(SSHKeyParseError::UnknownKeyType(pubkey_type));
        }
        let pubp = parse_openssh_number(inp)?;
        let pubq = parse_openssh_number(inp)?;
        let pubg = parse_openssh_number(inp)?;
        let pubparams = L1024N160::new(pubp, pubg, pubq);
        let puby: U1024 = parse_openssh_number(inp)?;
        for _ in inp.bytes() { return Err(SSHKeyParseError::UnknownTrailingData); }
        Ok(DSAPublicKey::<L1024N160>::new(pubparams.clone(), puby.clone()))
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
            return Err(SSHKeyParseError::InconsistentKeyTypes("ssh-dss".to_string(), privkey_type));
        }
        let privp = parse_openssh_number(inp)?;
        let privq = parse_openssh_number(inp)?;
        let privg = parse_openssh_number(inp)?;
        let privparams = L1024N160::new(privp, privg, privq);
        let _     = parse_openssh_buffer(inp)?; // a copy of y we don't need
        let privx = parse_openssh_number(inp)?;

        let privkey = DSAPrivateKey::<L1024N160>::new(privparams, privx);
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

    fn render_ssh_private_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-dss")?;
        render_openssh_number(out, &self.private.params.p)?;
        render_openssh_number(out, &self.private.params.q)?;
        render_openssh_number(out, &self.private.params.g)?;
        render_openssh_number(out, &self.public.y)?;
        render_openssh_number(out, &self.private.x)
   }
}
