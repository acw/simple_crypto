use cryptonum::UCN;
use digest::{BlockInput,FixedOutput,Input};
use digest::generic_array::ArrayLength;
use dsa::parameters::{DSAParameters,n_bits};
use dsa::rfc6979::{DSASignature,KIterator,bits2int};
use hmac::Hmac;
use std::ops::Rem;

/// A DSA private key.
#[derive(Clone,Debug,PartialEq)]
pub struct DSAPrivate {
    pub params: DSAParameters,
    pub(crate) x: UCN
}

impl DSAPrivate {
    pub fn new(params: &DSAParameters, x: UCN) -> DSAPrivate {
        DSAPrivate {
            params: params.clone(),
            x: x
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
        let n = n_bits(self.params.size);
        let h1: Vec<u8> = digest.fixed_result()
                                .as_slice()
                                .iter()
                                .map(|x| *x)
                                .collect();
        let h0 = bits2int(&h1, n);
        let h = h0.rem(&self.params.q);

        // 2.  A random value modulo q, dubbed k, is generated.  That value
        //     shall not be 0; hence, it lies in the [1, q-1] range.  Most
        //     of the remainder of this document will revolve around the
        //     process used to generate k.  In plain DSA or ECDSA, k should
        //     be selected through a random selection that chooses a value
        //     among the q-1 possible values with uniform probability.
        for k in KIterator::<Hash>::new(&h1, n, &self.params.q, &self.x) {
            // 3. A value r (modulo q) is computed from k and the key
            //    parameters:
            //     *  For DSA:
            //           r = g^k mod p mod q
            //
            //           (The exponentiation is performed modulo p, yielding a
            //           number between 0 and p-1, which is then further reduced
            //           modulo q.)
            //     *  For ECDSA ...
            //
            //    If r turns out to be zero, a new k should be selected and r
            //    computed again (this is an utterly improbable occurrence).
            let r = self.params.g.modexp(&k, &self.params.p) % &self.params.q;
            if r.is_zero() {
                continue;
            }
            // 4.  The value s (modulo q) is computed:
            //
            //           s = (h+x*r)/k mod q
            //
            //     The pair (r, s) is the signature.
            let kinv = k.modinv(&self.params.q);
            let s = ((&h + (&self.x * &r)) * &kinv) % &self.params.q;
            return DSASignature{ r: r, s: s };
        }
        panic!("The world is broken; couldn't find a k in sign().");
    }
}


