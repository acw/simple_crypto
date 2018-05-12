use cryptonum::{SCN,UCN};
use digest::{FixedOutput,Input};
use dsa::parameters::{DSAParameters,n_bits};
use dsa::rfc6979::DSASignature;
use num::BigInt;
use simple_asn1::{ASN1Block,ToASN1,ASN1EncodeErr,ASN1Class};
use std::cmp::min;
use std::ops::Rem;

/// A DSA key pair
#[derive(Clone,Debug,PartialEq)]
pub struct DSAPublic {
    pub params: DSAParameters,
    pub y: UCN
}

impl DSAPublic {
    pub fn new(params: &DSAParameters, y: UCN) -> DSAPublic {
        DSAPublic {
            params: params.clone(),
            y: y
        }
    }

    pub fn verify<Hash>(&self, m: &[u8], sig: &DSASignature) -> bool
      where Hash: Clone + Default + Input + FixedOutput
    {
        if sig.r >= self.params.q {
            return false;
        }
        if sig.s >= self.params.q {
            return false;
        }
        // w = (s')^-1 mod q;
        let w = sig.s.modinv(&self.params.q);
        // z = the leftmost min(N, outlen) bits of Hash(M').
        let mut digest = <Hash>::default();
        digest.process(m);
        let z = { let mut bytes: Vec<u8> = digest.fixed_result()
                                                 .as_slice()
                                                 .iter()
                                                 .map(|x| *x)
                                                 .collect();
                  let n = n_bits(self.params.size) / 8;
                  let len = min(n, bytes.len());
                  bytes.truncate(len);
                  UCN::from_bytes(&bytes) };
        // u1 = (zw) mod q
        let u1 = (&z * &w).reduce(&self.params.qu);
        // u2 = (rw) mod q
        let u2 = (&sig.r * &w).reduce(&self.params.qu);
        // v = (((g)^u1(y)^u2) mod p) mod q
        let v_1 = self.params.g.fastmodexp(&u1, &self.params.pu);
        let v_2 = self.y.fastmodexp(&u2, &self.params.pu);
        let v = (&v_1 * &v_2).reduce(&self.params.pu)
                             .rem(&self.params.q);
        // if v = r, then the signature is verified
        v == sig.r
    }
}

impl ToASN1 for DSAPublic {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let inty = SCN::from(self.y.clone());
        let yblock = ASN1Block::Integer(c, 0, BigInt::from(inty));
        Ok(vec![yblock])
    }
}
