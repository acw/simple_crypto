use cryptonum::unsigned::*;
use num::bigint::BigUint;
use rsa::errors::RSAError;
use simple_asn1::{ASN1Block,ASN1DecodeErr};

pub trait RSAMode {
    type Barrett;
}

impl RSAMode for U512     { type Barrett = BarrettU512;   }
impl RSAMode for U1024    { type Barrett = BarrettU1024;  }
impl RSAMode for U2048    { type Barrett = BarrettU2048;  }
impl RSAMode for U3072    { type Barrett = BarrettU3072;  }
impl RSAMode for U4096    { type Barrett = BarrettU4096;  }
impl RSAMode for U8192    { type Barrett = BarrettU8192;  }
impl RSAMode for U15360   { type Barrett = BarrettU15360; }


pub fn pkcs1_pad(ident: &[u8], hash: &[u8], keylen: usize) -> Vec<u8>
{
    let mut idhash = Vec::new();
    idhash.extend_from_slice(ident);
    idhash.extend_from_slice(hash);
    let tlen = idhash.len();
    assert!(keylen > (tlen + 3));
    let mut padding = Vec::new();
    padding.resize(keylen - tlen - 3, 0xFF);
    let mut result = vec![0x00,0x01];
    result.append(&mut padding);
    result.push(0x00);
    result.append(&mut idhash);
    result
}

pub fn drop0s(a: &[u8]) -> &[u8] {
    let mut idx = 0;

    while (idx < a.len()) && (a[idx] == 0) {
        idx = idx + 1;
    }

    &a[idx..]
}

pub fn xor_vecs(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a,b)| a^b).collect()
}

pub fn decode_biguint(b: &ASN1Block) -> Result<BigUint,RSAError> {
    match b {
        &ASN1Block::Integer(_, _, ref v) => {
            match v.to_biguint() {
                Some(sn) => Ok(sn),
                _        => Err(RSAError::InvalidKey)
            }
        }
        _ =>
            Err(RSAError::ASN1DecodeErr(ASN1DecodeErr::EmptyBuffer))
    }
}


