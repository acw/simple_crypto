use cryptonum::unsigned::*;
use ecdsa::{ECDSAPair,ECDSAPublic,ECCPublicKey,ECDSAPrivate,ECCPrivateKey};
use ecdsa::{EllipticCurve,P256,P384,P521};
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
        let curve = parse_openssh_string(inp)?;
        match curve.as_ref() {
            "nistp256" => {
                let val = parse_openssh_buffer(inp)?;
                if val[0] != 4 || val.len() != 65 {
                    return Err(SSHKeyParseError::InvalidECPointCompression);
                }
                let x = U256::from_bytes(&val[1..33]);
                let y = U256::from_bytes(&val[33..]);
                let p = P256::new_point(x, y);
                let pbl = ECCPublicKey::<P256>::new(p);
                Ok(ECDSAPublic::P256(pbl))
            }
            "nistp384" => {
                let val = parse_openssh_buffer(inp)?;
                if val[0] != 4 || val.len() != 97 {
                    return Err(SSHKeyParseError::InvalidECPointCompression);
                }
                let x = U384::from_bytes(&val[1..49]);
                let y = U384::from_bytes(&val[49..]);
                let p = P384::new_point(x, y);
                let pbl = ECCPublicKey::<P384>::new(p);
                Ok(ECDSAPublic::P384(pbl))
            }
            "nistp521" => {
                let val = parse_openssh_buffer(inp)?;
                if val[0] != 4 || val.len() != 133 {
                    return Err(SSHKeyParseError::InvalidECPointCompression);
                }
                let x = U576::from_bytes(&val[1..67]);
                let y = U576::from_bytes(&val[67..]);
                let p = P521::new_point(x, y);
                let pbl = ECCPublicKey::<P521>::new(p);
                Ok(ECDSAPublic::P521(pbl))
            }
            _ => {
                return Err(SSHKeyParseError::UnknownECDSACurve(curve))
            }
        }
    }

    fn parse_ssh_private_info<I: Read>(inp: &mut I) -> Result<(Self::Private,String),SSHKeyParseError>
    {
        let check1 = parse_openssh_u32(inp)?;
        let check2 = parse_openssh_u32(inp)?;
        if check1 != check2 {
            return Err(SSHKeyParseError::PrivateKeyCorruption);
        }
        let res = match ECDSAPair::parse_ssh_public_info(inp)? {
            ECDSAPublic::P192(_) => return Err(SSHKeyParseError::PrivateKeyCorruption),
            ECDSAPublic::P224(_) => return Err(SSHKeyParseError::PrivateKeyCorruption),
            ECDSAPublic::P256(_) => {
                let mut dbytes = parse_openssh_buffer(inp)?;
                while dbytes[0] == 0 { dbytes.remove(0); }
                assert!(dbytes.len() <= 32);
                let d = U256::from_bytes(&dbytes);
                ECDSAPrivate::P256(ECCPrivateKey::<P256>::new(d))
            }
            ECDSAPublic::P384(_) => {
                let mut dbytes = parse_openssh_buffer(inp)?;
                while dbytes[0] == 0 { dbytes.remove(0); }
                assert!(dbytes.len() <= 48);
                let d = U384::from_bytes(&dbytes);
                ECDSAPrivate::P384(ECCPrivateKey::<P384>::new(d))
            }
            ECDSAPublic::P521(_) => {
                let mut dbytes = parse_openssh_buffer(inp)?;
                while dbytes[0] == 0 { dbytes.remove(0); }
                assert!(dbytes.len() <= 66);
                let d = U576::from_bytes(&dbytes);
                ECDSAPrivate::P521(ECCPrivateKey::<P521>::new(d))
            }
        };
        let comment = parse_openssh_string(inp)?;
        for (idx,byte) in inp.bytes().enumerate() {
            if ((idx+1) as u8) != byte? {
                return Err(SSHKeyParseError::InvalidPadding);
            }
        }

        Ok((res, comment))
    }

    fn render_ssh_public_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        render_openssh_string(out, "ssh-ecdsa")?;
        match self {
            ECDSAPair::P192(_,_) =>
                return Err(SSHKeyRenderError::IllegalECDSAKeyType("P192".to_string())),
            ECDSAPair::P224(_,_) =>
                return Err(SSHKeyRenderError::IllegalECDSAKeyType("P224".to_string())),
            ECDSAPair::P256(pu,_) => {
                render_openssh_string(out, "nistp256")?;
                let mut vec = Vec::with_capacity(66);
                vec.write(&[4u8])?;
                render_number(256, &mut vec, &U256::from(pu.q.x.clone()))?;
                render_number(256, &mut vec, &U256::from(pu.q.y.clone()))?;
                render_openssh_buffer(out, &vec)?;
            }
            ECDSAPair::P384(pu,_) => {
                render_openssh_string(out, "nistp384")?;
                let mut vec = Vec::with_capacity(66);
                vec.write(&[4u8])?;
                render_number(384, &mut vec, &U384::from(pu.q.x.clone()))?;
                render_number(384, &mut vec, &U384::from(pu.q.y.clone()))?;
                render_openssh_buffer(out, &vec)?;
            }
            ECDSAPair::P521(pu,_) => {
                render_openssh_string(out, "nistp521")?;
                let mut vec = Vec::with_capacity(66);
                vec.write(&[4u8])?;
                render_number(521, &mut vec, &U576::from(pu.q.x.clone()))?;
                render_number(521, &mut vec, &U576::from(pu.q.y.clone()))?;
                render_openssh_buffer(out, &vec)?;
            }
        }
        Ok(())
    }

    fn render_ssh_private_info<O: Write>(&self, out: &mut O) -> Result<(),SSHKeyRenderError>
    {
        self.render_ssh_public_info(out)?;
        match self {
            ECDSAPair::P192(_,_) =>
                return Err(SSHKeyRenderError::IllegalECDSAKeyType("P192".to_string())),
            ECDSAPair::P224(_,_) =>
                return Err(SSHKeyRenderError::IllegalECDSAKeyType("P224".to_string())),
            ECDSAPair::P256(_,pr) => { render_openssh_u32(out, 256/8)?; render_number(256, out, &pr.d)?; }
            ECDSAPair::P384(_,pr) => { render_openssh_u32(out, 384/8)?; render_number(384, out, &pr.d)?; }
            ECDSAPair::P521(_,pr) => { render_openssh_u32(out, 528/8)?; render_number(521, out, &pr.d)?; }
        }
        Ok(())
    }
}

fn render_number<O,N>(bitlen: usize, out: &mut O, val: &N) -> Result<(),SSHKeyRenderError>
 where
  O: Write,
  N: Encoder
{
    let mut outvec = Vec::new();
    outvec.write(&val.to_bytes())?;
    while outvec.len() < ((bitlen + 7) / 8) { outvec.insert(0,0); }
    while outvec.len() > ((bitlen + 7) / 8) { outvec.remove(0);   }
    out.write(&outvec)?;
    Ok(())
}
