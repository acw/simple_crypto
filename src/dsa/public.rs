use cryptonum::unsigned::*;
use cryptonum::signed::ModInv;
use digest::Digest;
use dsa::params::*;
use dsa::rfc6979::DSASignature;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,ToASN1};
use std::cmp::min;
use utils::TranslateNums;

pub trait DSAPublicKey {
    type Params : DSAParameters;
    type L;
    type N;

    /// Generate a new public key given the parameters and public value.
    fn new(params: Self::Params, y: Self::L) -> Self;
    /// Verify the given signature against the given message, using the
    /// appropriate hash function.
    fn verify<Hash>(&self, m: &[u8], sig: &DSASignature<Self::N>) -> bool
      where Hash: Digest;
}

pub struct DSAPubKey<Params: DSAParameters> {
    pub(crate) params: Params,
    pub(crate) y: Params::L
}

pub enum DSAPublic {
    DSAPublicL1024N160(DSAPubKey<L1024N160>),
    DSAPublicL2048N224(DSAPubKey<L2048N224>),
    DSAPublicL2048N256(DSAPubKey<L2048N256>),
    DSAPublicL3072N256(DSAPubKey<L3072N256>)
}

macro_rules! pubkey_impls {
    ($ptype: ident, $ltype: ident, $ntype: ident, $dbl: ident, $bdbl: ident) => {
        impl DSAPublicKey for DSAPubKey<$ptype>
        {
            type Params = $ptype;
            type L = $ltype;
            type N = $ntype;

            fn new(params: $ptype, y: $ltype) -> DSAPubKey<$ptype>
            {
                DSAPubKey{ params, y }
            }

            fn verify<Hash>(&self, m: &[u8], sig: &DSASignature<$ntype>) -> bool
             where Hash: Digest
            {
                if sig.r >= self.params.q {
                    return false;
                }
                if sig.s >= self.params.q {
                    return false;
                }
                // w = (s')^-1 mod q;
                if let Some(w) = sig.s.modinv(&self.params.q) {
                    // z = the leftmost min(N, outlen) bits of Hash(M').
                    let mut digest_bytes = <Hash>::digest(m).to_vec();
                    let len = min(digest_bytes.len(), $ptype::n_size() / 8);
                    digest_bytes.truncate(len);
                    let z = $ntype::from_bytes(&digest_bytes);
                    // u1 = (zw) mod q
                    let qdbl = $dbl::from(&self.params.q);
                    let u1 = $ltype::from( (&z * &w) % &qdbl );
                    // u2 = (rw) mod q
                    let u2 = $ltype::from( (&sig.r * &w) % &qdbl );
                    // v = (((g)^u1(y)^u2) mod p) mod q
                    let v_1 = self.params.g.modexp(&u1, &self.params.p);
                    let v_2 = self.y.modexp(&u2, &self.params.p);
                    let bigp = $bdbl::from(&self.params.p);
                    let v_first_mod = (v_1 * v_2) % bigp;
                    let v = $ltype::from(v_first_mod) % $ltype::from(&self.params.q);
                    // if v = r, then the signature is verified
                    return $ntype::from(v) == sig.r
                }
                
                false
            }
        }

        impl ToASN1 for DSAPubKey<$ptype> {
            type Error = ASN1EncodeErr;

            fn to_asn1_class(&self, c: ASN1Class)
                -> Result<Vec<ASN1Block>,ASN1EncodeErr>
            {
                let inty = self.y.to_num();
                let yblock = ASN1Block::Integer(c, 0, inty);
                Ok(vec![yblock])
            }
        }
    };
}

pubkey_impls!(L1024N160, U1024, U192, U384, U2048);
pubkey_impls!(L2048N224, U2048, U256, U512, U4096);
pubkey_impls!(L2048N256, U2048, U256, U512, U4096);
pubkey_impls!(L3072N256, U3072, U256, U512, U6144);

macro_rules! generate_tests {
    ( $( ($mod: ident, $params: ident, $lt: ident, $nt: ident) ),* ) => {
        $(
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::unsigned::Decoder;
            use super::*;
            use testing::run_test;
            use sha2::{Sha224,Sha256,Sha384,Sha512};

            #[test]
            fn verify() {
                let fname = format!("testdata/dsa/sign{}.test", stringify!($params));
                run_test(fname.to_string(), 9, |case| {
                    let (neg0, pbytes) = case.get("p").unwrap();
                    let (neg1, qbytes) = case.get("q").unwrap();
                    let (neg2, gbytes) = case.get("g").unwrap();
                    let (neg3, ybytes) = case.get("y").unwrap();
                    let (neg4, _bytes) = case.get("x").unwrap();
                    let (neg5, mbytes) = case.get("m").unwrap();
                    let (neg6, hbytes) = case.get("h").unwrap();
                    let (neg7, rbytes) = case.get("r").unwrap();
                    let (neg8, sbytes) = case.get("s").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 &&
                            !neg5 && !neg6 && !neg7 && !neg8);
                    let p = $lt::from_bytes(pbytes);
                    let q = $nt::from_bytes(qbytes);
                    let g = $lt::from_bytes(gbytes);
                    //let x = $lt::from_bytes(xbytes);
                    let y = $lt::from_bytes(ybytes);
                    let h = usize::from($nt::from_bytes(hbytes));
                    let r = $nt::from_bytes(rbytes);
                    let s = $nt::from_bytes(sbytes);

                    let params = $params::new(p,g,q);
                    let public = DSAPubKey::<$params>::new(params, y);
                    let sig = DSASignature::<$nt>::new(r, s);
                    match h {
                        224 => assert!(public.verify::<Sha224>(mbytes, &sig)),
                        256 => assert!(public.verify::<Sha256>(mbytes, &sig)),
                        384 => assert!(public.verify::<Sha384>(mbytes, &sig)),
                        512 => assert!(public.verify::<Sha512>(mbytes, &sig)),
                        _   => panic!("Unexpected hash {}", h)
                    }
                });
            }
        }
        )*
    }
}

generate_tests!( (DSA1024N160, L1024N160, U1024, U192),
                 (DSA2048N224, L2048N224, U2048, U256),
                 (DSA2048N256, L2048N256, U2048, U256),
                 (DSA3072N256, L3072N256, U3072, U256)
               );