use cryptonum::{SCN,UCN};
use digest::{BlockInput,FixedOutput,Input};
use digest::generic_array::ArrayLength;
use dsa::rfc6979::{DSASignature,KIterator};
use ecdsa::curves::EllipticCurve;
use ecdsa::math::{ECCPoint,bits2int};
use hmac::Hmac;

#[derive(Clone,Debug,PartialEq)]
pub struct ECDSAPrivate {
    pub(crate) curve: &'static EllipticCurve,
    pub(crate) d: UCN
}

impl ECDSAPrivate {
    pub fn new(c: &'static EllipticCurve, d: &UCN)
        -> ECDSAPrivate
    {
        ECDSAPrivate {
            curve: c,
            d: d.clone()
        }
    }

    pub fn sign<Hash>(&self, m: &[u8]) -> DSASignature
      where
        Hash: Clone + BlockInput + Input + FixedOutput + Default,
        Hmac<Hash>: Clone,
        Hash::BlockSize: ArrayLength<u8>
    {
        // This algorithm is per RFC 6979, which has a nice, relatively
        // straightforward description of how to do DSA signing.
        //
        // 1.  H(m) is transformed into an integer modulo q using the bits2int
        //     transform and an extra modular reduction:
        //
        //        h = bits2int(H(m)) mod q
        //
        //     As was noted in the description of bits2octets, the extra
        //     modular reduction is no more than a conditional subtraction.
        //
        let mut digest = <Hash>::default();
        digest.process(m);
        let n = self.curve.p.bits();
        let h1: Vec<u8> = digest.fixed_result()
                                .as_slice()
                                .iter()
                                .map(|x| *x)
                                .collect();
        let h0 = bits2int(&h1, n);
        let h = h0 % &self.curve.n;

        // 2.  A random value modulo q, dubbed k, is generated.  That value
        //     shall not be 0; hence, it lies in the [1, q-1] range.  Most
        //     of the remainder of this document will revolve around the
        //     process used to generate k.  In plain DSA or ECDSA, k should
        //     be selected through a random selection that chooses a value
        //     among the q-1 possible values with uniform probability.
        for k in KIterator::<Hash>::new(&h1, n, &self.curve.n, &self.curve.b) {
            // 3. A value r (modulo q) is computed from k and the key
            //    parameters:
            //     *  For DSA ...
            //     *  For ECDSA: the point kG is computed; its X coordinate (a
            //        member of the field over which E is defined) is converted
            //        to  an integer, which is reduced modulo q, yielding r.
            //
            //    If r turns out to be zero, a new k should be selected and r
            //    computed again (this is an utterly improbable occurrence).
            let g = ECCPoint::default(self.curve);
            let kg = g.scale(&k);
            let ni = SCN::from(self.curve.n.clone());
            let r = &kg.get_x() % &ni;
            if r.is_zero() {
                continue;
            }
            // 4.  The value s (modulo q) is computed:
            //
            //           s = (h+x*r)/k mod q
            //
            //     The pair (r, s) is the signature.
            let kinv = SCN::from(k.modinv(&ni.value));
            let s = ((SCN::from(h.clone()) + (&kg.get_x() * &r)) * &kinv) % &ni;
            if s.is_zero() {
                continue;
            }

            assert!(!r.is_negative());
            assert!(!s.is_negative());
            return DSASignature{ r: r.value, s: s.value };
        }
        panic!("The world is broken; couldn't find a k in sign().");
    }
}
