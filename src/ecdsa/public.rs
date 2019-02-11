use cryptonum::signed::*;
use cryptonum::unsigned::*;
use digest::{BlockInput,Digest,Input,FixedOutput,Reset};
use dsa::rfc6979::{DSASignature,KIterator,bits2int};
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

impl ECCPublicKey for ECCPublic<P192>
{
    type Curve = P192;
    type Unsigned = U192;

    fn new(q: Point<P192>) -> ECCPublic<P192>
    {
        ECCPublic{ q }
    }

    fn verify<Hash>(&self, m: &[u8], sig: DSASignature<Self::Unsigned>) -> bool
      where
       Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
       Hmac<Hash>: Mac
    {
        let n = <P192>::n();

        if sig.r.is_zero() || (sig.r >= n) {
            return false;
        }

        if sig.s.is_zero() || (sig.s >= n) {
            return false;
        }

        // e = the leftmost min(N, outlen) bits of Hash(M').
        let mut digest_bytes = <Hash>::digest(m).to_vec();
        let len = min(digest_bytes.len(), P192::size() / 8);
        digest_bytes.truncate(len);

        if let Some(c) = sig.s.modinv(&n) {
            let e = U192::from_bytes(&digest_bytes);
            let u1 = e.modmul(&c, &n);
            let u2 = sig.r.modmul(&c, &n);
            let g = Point::<P192>::default();
            let u1i = I192::from(u1);
            let u2i = I192::from(u2);
            let point = Point::<P192>::double_scalar_mult(&u1i, &g, &u2i, &self.q);
            !point.x.is_negative() && (sig.r == U192::from(point.x))
        } else {
            false
        }
    }
}

#[cfg(test)]
use sha2::{Sha224,Sha256,Sha384,Sha512};
#[cfg(test)]
use testing::*;

#[test]
fn p192() {
    let fname = build_test_path("ecc/sign",stringify!(P192));
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
        let _ = U192::from_bytes(dbytes);
        let x = U192::from_bytes(xbytes);
        let y = U192::from_bytes(ybytes);
        let h = U192::from_bytes(hbytes);
        let r = U192::from_bytes(rbytes);
        let s = U192::from_bytes(sbytes);

        let point = Point::<P192>{ x: I192::from(x), y: I192::from(y) };
        let public = ECCPublic::<P192>::new(point);
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
