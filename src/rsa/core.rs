use num::bigint::BigUint;
use rsa::errors::RSAError;
use simple_asn1::{ASN1Block,ASN1DecodeErr};

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


