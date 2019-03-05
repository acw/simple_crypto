use cryptonum::signed::*;
use cryptonum::unsigned::*;
use digest::{BlockInput,Digest,Input,FixedOutput,Reset};
use dsa::rfc6979::DSASignature;
use ecdsa::curve::{EllipticCurve,P192,P224,P256,P384,P521};
use ecdsa::point::{ECCPoint,Point};
use hmac::{Hmac,Mac};
use simple_asn1::{ASN1Block,ASN1Class,ASN1DecodeErr,ASN1EncodeErr,FromASN1,ToASN1};
use std::cmp::min;

pub struct ECCPubKey<Curve: EllipticCurve> {
    q: Point<Curve>
}

pub enum ECDSAPublic {
    ECCPublicP192(ECCPubKey<P192>),
    ECCPublicP224(ECCPubKey<P224>),
    ECCPublicP256(ECCPubKey<P256>),
    ECCPublicP384(ECCPubKey<P384>),
    ECCPublicP521(ECCPubKey<P521>),
}

pub trait ECCPublicKey {
    type Curve : EllipticCurve;
    type Unsigned;

    fn new(d: Point<Self::Curve>) -> Self;
    fn verify<Hash>(&self, m: &[u8], sig: &DSASignature<Self::Unsigned>) -> bool
      where
       Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
       Hmac<Hash>: Mac;
}

pub enum ECDSAEncodeErr {
    ASN1EncodeErr(ASN1EncodeErr),
    XValueNegative, YValueNegative
}

impl From<ASN1EncodeErr> for ECDSAEncodeErr {
    fn from(x: ASN1EncodeErr) -> ECDSAEncodeErr {
        ECDSAEncodeErr::ASN1EncodeErr(x)
    }
}

#[derive(Debug)]
pub enum ECDSADecodeErr {
    ASN1DecodeErr(ASN1DecodeErr),
    NoKeyFound,
    InvalidKeyFormat,
    InvalidKeyBlockSize
}

impl From<ASN1DecodeErr> for ECDSADecodeErr {
    fn from(x: ASN1DecodeErr) -> ECDSADecodeErr {
        ECDSADecodeErr::ASN1DecodeErr(x)
    }
}

macro_rules! public_impl {
    ($curve: ident, $un: ident, $si: ident) => {
        impl ECCPublicKey for ECCPubKey<$curve>
        {
            type Curve = $curve;
            type Unsigned = $un;

            fn new(q: Point<$curve>) -> ECCPubKey<$curve>
            {
                ECCPubKey{ q }
            }

            fn verify<Hash>(&self, m: &[u8], sig: &DSASignature<Self::Unsigned>) -> bool
              where
               Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
               Hmac<Hash>: Mac
            {
                let n = <$curve>::n();

                if sig.r.is_zero() || (sig.r >= n) {
                    return false;
                }

                if sig.s.is_zero() || (sig.s >= n) {
                    return false;
                }

                // e = the leftmost min(N, outlen) bits of Hash(M').
                let mut digest_bytes = <Hash>::digest(m).to_vec();
                let len = min(digest_bytes.len(), $curve::size() / 8);
                digest_bytes.truncate(len);

                if let Some(c) = sig.s.modinv(&n) {
                    let e = $un::from_bytes(&digest_bytes);
                    let u1 = e.modmul(&c, &n);
                    let u2 = sig.r.modmul(&c, &n);
                    let g = Point::<$curve>::default();
                    let u1i = $si::from(u1);
                    let u2i = $si::from(u2);
                    let point = Point::<$curve>::double_scalar_mult(&u1i, &g, &u2i, &self.q);
                    !point.x.is_negative() && (sig.r == $un::from(point.x))
                } else {
                    false
                }
            }
        }

        impl ToASN1 for ECCPubKey<$curve> {
            type Error = ECDSAEncodeErr;

            fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>,ECDSAEncodeErr>
            {
                if self.q.x.is_negative() {
                    return Err(ECDSAEncodeErr::XValueNegative);
                }
                if self.q.y.is_negative() {
                    return Err(ECDSAEncodeErr::YValueNegative);
                }

                let xval = $un::from(&self.q.x);
                let yval = $un::from(&self.q.y);
                let mut xbytes = xval.to_bytes();
                let mut ybytes = yval.to_bytes();
                let goalsize = ($curve::size() + 7) / 8;
                let mut target = Vec::with_capacity(1 + (goalsize * 2));

                while xbytes.len() > goalsize { xbytes.remove(0);  };
                while xbytes.len() < goalsize { xbytes.insert(0,0) };
                while ybytes.len() > goalsize { ybytes.remove(0);  };
                while ybytes.len() < goalsize { ybytes.insert(0,0) };

                target.push(4);
                target.append(&mut xbytes);
                target.append(&mut ybytes);

                let result = ASN1Block::BitString(c, 0, target.len() * 8, target);
                Ok(vec![result])
            }
        }

        impl FromASN1 for ECCPubKey<$curve> {
            type Error = ECDSADecodeErr;

            fn from_asn1(bs: &[ASN1Block]) -> Result<(ECCPubKey<$curve>,&[ASN1Block]),ECDSADecodeErr>
            {
                let (x, rest) = bs.split_first().ok_or(ECDSADecodeErr::NoKeyFound)?;
                if let ASN1Block::BitString(_, _, _, target) = x {
                    let (hdr, xy_bstr) = target.split_first().ok_or(ECDSADecodeErr::InvalidKeyFormat)?;
                    if *hdr != 4 {
                        return Err(ECDSADecodeErr::InvalidKeyFormat);
                    }
                    let goalsize = ($curve::size() + 7) / 8;
                    if xy_bstr.len() != (2 * goalsize) {
                        return Err(ECDSADecodeErr::InvalidKeyBlockSize);
                    }
                    let (xbstr, ybstr) = xy_bstr.split_at(goalsize);
                    let x = $un::from_bytes(xbstr);
                    let y = $un::from_bytes(ybstr);
                    let point = Point::<$curve>{ x: $si::from(x), y: $si::from(y) };
                    let res = ECCPubKey::<$curve>::new(point);
                    Ok((res, rest))
                } else {
                    Err(ECDSADecodeErr::InvalidKeyFormat)
                }
            }
        }
    };
}

public_impl!(P192, U192, I192);
public_impl!(P224, U256, I256);
public_impl!(P256, U256, I256);
public_impl!(P384, U384, I384);
public_impl!(P521, U576, I576);

#[cfg(test)]
use sha2::{Sha224,Sha256,Sha384,Sha512};
#[cfg(test)]
use testing::*;

macro_rules! test_impl {
    ($name: ident, $curve: ident, $un: ident, $si: ident) => {
        #[test]
        fn $name() {
            let fname = build_test_path("ecc/sign",stringify!($curve));
            run_test(fname.to_string(), 9, |case| {
                let (negd, dbytes) = case.get("d").unwrap();
                let (negk, _bytes) = case.get("k").unwrap();
                let (negx, xbytes) = case.get("x").unwrap();
                let (negy, ybytes) = case.get("y").unwrap();
                let (negm, mbytes) = case.get("m").unwrap();
                let (negh, hbytes) = case.get("h").unwrap();
                let (negr, rbytes) = case.get("r").unwrap();
                let (negs, sbytes) = case.get("s").unwrap();

                assert!(!negd && !negk && !negx && !negy &&
                        !negm && !negh && !negr && !negs);
                let _ = $un::from_bytes(dbytes);
                let x = $un::from_bytes(xbytes);
                let y = $un::from_bytes(ybytes);
                let h = $un::from_bytes(hbytes);
                let r = $un::from_bytes(rbytes);
                let s = $un::from_bytes(sbytes);

                let point = Point::<$curve>{ x: $si::from(x), y: $si::from(y) };
                let public = ECCPubKey::<$curve>::new(point);
                let sig = DSASignature::new(r, s);
                match usize::from(h) {
                    224 => assert!(public.verify::<Sha224>(mbytes, &sig)),
                    256 => assert!(public.verify::<Sha256>(mbytes, &sig)),
                    384 => assert!(public.verify::<Sha384>(mbytes, &sig)),
                    512 => assert!(public.verify::<Sha512>(mbytes, &sig)),
                    x   => panic!("Unknown hash algorithm {}", x)
                };
            });
        }
    };
}

test_impl!(p192,P192,U192,I192);
test_impl!(p224,P224,U256,I256);
test_impl!(p256,P256,U256,I256);
test_impl!(p384,P384,U384,I384);
test_impl!(p521,P521,U576,I576);