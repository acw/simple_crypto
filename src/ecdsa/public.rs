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