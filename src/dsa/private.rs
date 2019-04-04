use cryptonum::unsigned::*;
use cryptonum::signed::ModInv;
use digest::{BlockInput,Digest,Input,FixedOutput,Reset};
use dsa::params::*;
use dsa::rfc6979::*;
use hmac::{Hmac,Mac};

pub trait DSAPrivateKey {
    type Params;
    type L;
    type N;

    /// Generate a new private key using the given DSA parameters and private
    /// key value.
    fn new(params: Self::Params, x: Self::N) -> Self;
    /// Generate a DSA signature for the given message, using the appropriate
    /// hash included in the type invocation.
    fn sign<Hash>(&self, m: &[u8]) -> DSASignature<Self::N>
     where
      Hash: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
      Hmac<Hash>: Mac;
}

pub struct DSAPrivKey<Params: DSAParameters>
{
    pub(crate) params: Params,
    pub(crate) x: Params::N
}

pub enum DSAPrivate {
    DSA1024Private(DSAPrivKey<L1024N160>),
    DSA2048SmallPrivate(DSAPrivKey<L2048N224>),
    DSA2048Private(DSAPrivKey<L2048N256>),
    DSA3072Private(DSAPrivKey<L3072N256>)
}

macro_rules! privkey_impls {
    ($ptype: ident, $ltype: ident, $ntype: ident, $big: ident, $bigger: ident, $biggest: ident) => {
       impl DSAPrivateKey for DSAPrivKey<$ptype>
       {
           type Params = $ptype;
           type L = $ltype;
           type N = $ntype;

           fn new(params: $ptype, x: $ntype) -> DSAPrivKey<$ptype>
           {
               DSAPrivKey{ params, x }
           }

           fn sign<Hash>(&self, m: &[u8]) -> DSASignature<$ntype>
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
               let n  = $ptype::n_size();
               let h0: $ntype = bits2int(&h1, $ptype::n_size());
               let q = &self.params.q;
               let h = h0 % q;
        
               // 2.  A random value modulo q, dubbed k, is generated.  That value
               //     shall not be 0; hence, it lies in the [1, q-1] range.  Most
               //     of the remainder of this document will revolve around the
               //     process used to generate k.  In plain DSA or ECDSA, k should
               //     be selected through a random selection that chooses a value
               //     among the q-1 possible values with uniform probability.
               for k in KIterator::<Hash,$ntype>::new(&h1, n, q, &self.x) {
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
                   let bigk = $ltype::from(&k);
                   let bigr = self.params.g.modexp(&bigk, &self.params.p) % $ltype::from(q);
                   if bigr.is_zero() {
                       continue;
                   }
                   let r = $ntype::from(bigr);
                   // 4.  The value s (modulo q) is computed:
                   //
                   //           s = (h+x*r)/k mod q
                   //
                   //     The pair (r, s) is the signature.
                   if let Some(kinv) = k.modinv(&q) {
                        let xr = &self.x * &r;
                        let top = xr + $big::from(&h);
                        let left = top * $bigger::from(kinv);
                        let bigs = left % $biggest::from(q);
                        return DSASignature::new(r, $ntype::from(bigs));
                   }
               }
               panic!("The world is broken; couldn't find a k in sign().");
           }
       }
    };
}

privkey_impls!(L1024N160, U1024, U192, U384, U448, U896);
privkey_impls!(L2048N224, U2048, U256, U512, U576, U1152);
privkey_impls!(L2048N256, U2048, U256, U512, U576, U1152);
privkey_impls!(L3072N256, U3072, U256, U512, U576, U1152);

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
                    let (neg3, _bytes) = case.get("y").unwrap();
                    let (neg4, xbytes) = case.get("x").unwrap();
                    let (neg5, mbytes) = case.get("m").unwrap();
                    let (neg6, hbytes) = case.get("h").unwrap();
                    let (neg7, rbytes) = case.get("r").unwrap();
                    let (neg8, sbytes) = case.get("s").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 &&
                            !neg5 && !neg6 && !neg7 && !neg8);
                    let p = $lt::from_bytes(pbytes);
                    let q = $nt::from_bytes(qbytes);
                    let g = $lt::from_bytes(gbytes);
                    let x = $nt::from_bytes(xbytes);
                    //let y = $lt::from_bytes(ybytes);
                    let h = usize::from($nt::from_bytes(hbytes));
                    let r = $nt::from_bytes(rbytes);
                    let s = $nt::from_bytes(sbytes);

                    let params = $params::new(p,g,q);
                    let private = DSAPrivKey::<$params>::new(params, x);
                    let sig = match h {
                        224 => private.sign::<Sha224>(mbytes),
                        256 => private.sign::<Sha256>(mbytes),
                        384 => private.sign::<Sha384>(mbytes),
                        512 => private.sign::<Sha512>(mbytes),
                        _   => panic!("Unexpected hash {}", h)
                    };
                    assert_eq!(r, sig.r);
                    assert_eq!(s, sig.s);
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