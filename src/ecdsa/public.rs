use cryptonum::signed::*;
use cryptonum::unsigned::*;
use digest::{BlockInput,Digest,Input,FixedOutput,Reset};
use dsa::rfc6979::DSASignature;
use ecdsa::curve::{EllipticCurve,P192,P224,P256,P384,P521};
use ecdsa::point::{ECCPoint,Point};
use hmac::{Hmac,Mac};
use std::cmp::min;

pub struct ECCPublic<Curve: EllipticCurve> {
    q: Point<Curve>
}

pub trait ECCPublicKey {
    type Curve : EllipticCurve;
    type Unsigned;

    fn new(d: Point<Self::Curve>) -> Self;
    fn verify<Hash>(&self, m: &[u8], sig: DSASignature<Self::Unsigned>) -> bool
      where
       Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
       Hmac<Hash>: Mac;
}

macro_rules! public_impl {
    ($curve: ident, $un: ident, $si: ident) => {
        impl ECCPublicKey for ECCPublic<$curve>
        {
            type Curve = $curve;
            type Unsigned = $un;

            fn new(q: Point<$curve>) -> ECCPublic<$curve>
            {
                ECCPublic{ q }
            }

            fn verify<Hash>(&self, m: &[u8], sig: DSASignature<Self::Unsigned>) -> bool
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
                let public = ECCPublic::<$curve>::new(point);
                let sig = DSASignature::new(r, s);
                match usize::from(h) {
                    224 => assert!(public.verify::<Sha224>(mbytes, sig)),
                    256 => assert!(public.verify::<Sha256>(mbytes, sig)),
                    384 => assert!(public.verify::<Sha384>(mbytes, sig)),
                    512 => assert!(public.verify::<Sha512>(mbytes, sig)),
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