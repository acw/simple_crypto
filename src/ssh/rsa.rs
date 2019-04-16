use cryptonum::unsigned::*;
use rsa::{RSAPair,RSAPublic,RSAPublicKey,RSAPrivate,RSAPrivateKey};
use std::io::{Read,Write};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use ssh::frame::*;
use ssh::SSHKey;

impl SSHKey for RSAPair {
    fn valid_keytype(s: &str) -> bool {
        (s == "ssh-rsa") || (s == "rsa")
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
        let mut nbuf = parse_openssh_buffer(inp)?;

        while ebuf[0] == 0 { ebuf.remove(0); }
        while nbuf[0] == 0 { nbuf.remove(0); }

        if nbuf.len() > (8192 / 8) {
            let e = U15360::from_bytes(&ebuf);
            let n = U15360::from_bytes(&nbuf);
            Ok(RSAPublic::Key15360(RSAPublicKey::<U15360>::new(n, e)))
        } else if nbuf.len() > (4096 / 8) {
            let e = U8192::from_bytes(&ebuf);
            let n = U8192::from_bytes(&nbuf);
            Ok(RSAPublic::Key8192(RSAPublicKey::<U8192>::new(n, e)))
        } else if nbuf.len() > (3072 / 8) {
            let e = U4096::from_bytes(&ebuf);
            let n = U4096::from_bytes(&nbuf);
            Ok(RSAPublic::Key4096(RSAPublicKey::<U4096>::new(n, e)))
        } else if nbuf.len() > (2048 / 8) {
            let e = U3072::from_bytes(&ebuf);
            let n = U3072::from_bytes(&nbuf);
            Ok(RSAPublic::Key3072(RSAPublicKey::<U3072>::new(n, e)))
        } else if nbuf.len() > (1024 / 8) {
            let e = U2048::from_bytes(&ebuf);
            let n = U2048::from_bytes(&nbuf);
            Ok(RSAPublic::Key2048(RSAPublicKey::<U2048>::new(n, e)))
        } else if nbuf.len() > (512 / 8) {
            let e = U1024::from_bytes(&ebuf);
            let n = U1024::from_bytes(&nbuf);
            Ok(RSAPublic::Key1024(RSAPublicKey::<U1024>::new(n, e)))
        } else {
            let e = U512::from_bytes(&ebuf);
            let n = U512::from_bytes(&nbuf);
            Ok(RSAPublic::Key512(RSAPublicKey::<U512>::new(n, e)))
        }
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

        // See the comment in the public key section.
        let mut nbuf = parse_openssh_buffer(inp)?;
        let    _ebuf = parse_openssh_buffer(inp)?;
        let mut dbuf = parse_openssh_buffer(inp)?;
        let    _iqmp = parse_openssh_buffer(inp)?;
        let    _pbuf = parse_openssh_buffer(inp)?;
        let    _qbuf = parse_openssh_buffer(inp)?;
        let  comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        while dbuf[0] == 0 { dbuf.remove(0); }
        while nbuf[0] == 0 { nbuf.remove(0); }

        if nbuf.len() > (8192 / 8) {
            let d = U15360::from_bytes(&dbuf);
            let n = U15360::from_bytes(&nbuf);
            Ok((RSAPrivate::Key15360(RSAPrivateKey::<U15360>::new(n, d)), comment))
        } else if nbuf.len() > (4096 / 8) {
            let d = U8192::from_bytes(&dbuf);
            let n = U8192::from_bytes(&nbuf);
            Ok((RSAPrivate::Key8192(RSAPrivateKey::<U8192>::new(n, d)), comment))
        } else if nbuf.len() > (3072 / 8) {
            let d = U4096::from_bytes(&dbuf);
            let n = U4096::from_bytes(&nbuf);
            Ok((RSAPrivate::Key4096(RSAPrivateKey::<U4096>::new(n, d)), comment))
        } else if nbuf.len() > (2048 / 8) {
            let d = U3072::from_bytes(&dbuf);
            let n = U3072::from_bytes(&nbuf);
            Ok((RSAPrivate::Key3072(RSAPrivateKey::<U3072>::new(n, d)), comment))
        } else if nbuf.len() > (1024 / 8) {
            let d = U2048::from_bytes(&dbuf);
            let n = U2048::from_bytes(&nbuf);
            Ok((RSAPrivate::Key2048(RSAPrivateKey::<U2048>::new(n, d)), comment))
        } else if nbuf.len() > (512 / 8) {
            let d = U1024::from_bytes(&dbuf);
            let n = U1024::from_bytes(&nbuf);
            Ok((RSAPrivate::Key1024(RSAPrivateKey::<U1024>::new(n, d)), comment))
        } else {
            let d = U512::from_bytes(&dbuf);
            let n = U512::from_bytes(&nbuf);
            Ok((RSAPrivate::Key512(RSAPrivateKey::<U512>::new(n, d)), comment))
        }
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-rsa")?;
        match self {
            RSAPair::R512(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R1024(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R2048(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R3072(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R4096(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R8192(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
            RSAPair::R15360(pbl,_) => {
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &pbl.n)?;
            }
        }
        Ok(())
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-rsa")?;
        match self {
            RSAPair::R512(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R1024(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R2048(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R3072(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R4096(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R8192(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
            RSAPair::R15360(pbl,prv) => {
                render_openssh_number(out, &pbl.n)?;
                render_openssh_number(out, &pbl.e)?;
                render_openssh_number(out, &prv.d)?;
            }
        }
        /* iqmp */ render_openssh_buffer(out, &vec![])?;
        /* p    */ render_openssh_buffer(out, &vec![])?;
        /* q    */ render_openssh_buffer(out, &vec![])?;
        Ok(())
    }
}