use cryptonum::signed::*;
use cryptonum::unsigned::*;
use digest::{BlockInput,Digest,Input,FixedOutput,Reset};
use dsa::rfc6979::{DSASignature,KIterator,bits2int};
use ecdsa::curve::{EllipticCurve,P192};
use ecdsa::point::{ECCPoint,Point};
use hmac::{Hmac,Mac};

pub struct ECCPrivate<Curve: EllipticCurve> {
    d: Curve::Unsigned
}

impl ECCPrivate<P192>
{
    pub fn new(d: U192) -> ECCPrivate<P192>
    {
        ECCPrivate{ d }
    }


    pub fn sign<Hash>(&self, m: &[u8]) -> DSASignature<U192>
      where
        Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
        Hmac<Hash>: Mac
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
        let h1 = <Hash>::digest(m);
        let size = <P192>::size();
        let h0: U192 = bits2int(&h1, size);
        let h = h0 % <P192>::n();

        // 2.  A random value modulo q, dubbed k, is generated.  That value
        //     shall not be 0; hence, it lies in the [1, q-1] range.  Most
        //     of the remainder of this document will revolve around the
        //     process used to generate k.  In plain DSA or ECDSA, k should
        //     be selected through a random selection that chooses a value
        //     among the q-1 possible values with uniform probability.
        for k in KIterator::<Hash,U192>::new(&h1, size, &<P192>::n(), &<P192>::b()) {
            // 3. A value r (modulo q) is computed from k and the key
            //    parameters:
            //     *  For DSA ...
            //     *  For ECDSA ...
            //
            //    If r turns out to be zero, a new k should be selected and r
            //    computed again (this is an utterly improbable occurrence).
            let g = Point::<P192>::default();
            let ki = I192::new(false, k.clone());
            let kg = g.scale(&ki);
            let n = P192::n();
            let ni = I192::from(&n);
            let ri = &kg.x % &ni;
            if ri.is_zero() {
                continue;
            }
            if ri.is_negative() {
                continue;
            }
            let r = U192::from(ri);
            // 4.  The value s (modulo q) is computed:
            //
            //           s = (h+x*r)/k mod q
            //
            //     The pair (r, s) is the signature.
            if let Some(kinv) = k.modinv(&n) {
                let xr = &self.d * &r;
                let hxr = U384::from(&h) + xr;
                let base = U192::from(hxr * U448::from(kinv));
                let s = base % n;
                return DSASignature{ r, s };
            }
        }
        panic!("The world is broken; couldn't find a k in sign().");
    }
}