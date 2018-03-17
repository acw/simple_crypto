use cryptonum::{CryptoNumModOps};
use num::BigUint;
use rsa::errors::RSAError;
use simple_asn1::{ASN1DecodeErr,ASN1Block};

// encoding PKCS1 stuff
pub fn pkcs1_pad(ident: &[u8], hash: &[u8], keylen: usize) -> Vec<u8> {
    let mut idhash = Vec::new();
    idhash.extend_from_slice(ident);
    idhash.extend_from_slice(hash);
    let tlen = idhash.len();
    assert!(keylen > (tlen + 3));
    let mut padding = Vec::new();
    padding.resize(keylen - tlen - 3, 0xFF);
    let mut result = vec![0x00, 0x01];
    result.append(&mut padding);
    result.push(0x00);
    result.append(&mut idhash);
    result
}

// the RSA encryption function
pub fn ep<U: CryptoNumModOps>(n: &U, e: &U, m: &U) -> U {
    m.modexp(e, n)
}

// the RSA decryption function
pub fn dp<U: CryptoNumModOps>(n: &U, d: &U, c: &U) -> U {
    c.modexp(d, n)
}

// the RSA signature generation function
pub fn sp1<U: CryptoNumModOps>(n: &U, d: &U, m: &U) -> U {
    m.modexp(d, n)
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


// the RSA signature verification function
pub fn vp1<U: CryptoNumModOps>(n: &U, e: &U, s: &U) -> U {
    s.modexp(e, n)
}

pub fn xor_vecs(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a,b)| a^b).collect()
}

