use digest::{BlockInput,FixedOutput,Input};
use digest::generic_array::ArrayLength;
use dsa::rfc6979::DSASignature;
use ecdsa::curves::EllipticCurve;
use ecdsa::math::{ECCPoint,bits2int,point_add_two_muls};
use hmac::Hmac;

#[allow(non_snake_case)]
#[derive(Clone,Debug,PartialEq)]
pub struct ECDSAPublic {
    pub(crate) curve: &'static EllipticCurve,
    pub(crate) Q: ECCPoint
}

impl ECDSAPublic {
    pub fn new(curve: &'static EllipticCurve, point: &ECCPoint)
        -> ECDSAPublic
    {
        ECDSAPublic {
            curve: curve,
            Q: point.clone()
        }
    }

    pub fn verify<Hash>(&self, m: &[u8], sig: &DSASignature) -> bool
      where
        Hash: Clone + BlockInput + Input + FixedOutput + Default,
        Hmac<Hash>: Clone,
        Hash::BlockSize: ArrayLength<u8>
    {
        let n = &self.curve.n;

        if &sig.r > n {
            return false;
        }
        if &sig.s > n {
            return false;
        }

        let c = sig.s.modinv(&n);

        let mut digest = <Hash>::default();
        digest.process(m);
        let h1: Vec<u8> = digest.fixed_result()
                                .as_slice()
                                .iter()
                                .map(|x| *x)
                                .collect();
        let h0 = bits2int(&h1, self.curve.p.bits()) % n;
        let u1 = (&h0    * &c) % n;
        let u2 = (&sig.r * &c) % n;
        let x = point_add_two_muls(&u1, &ECCPoint::default(&self.curve),
                                   &u2, &self.Q);
        let xx = x.get_x();

        if xx.is_negative() {
            return false;
        }

        (xx.value % n) == sig.r
    }
}
