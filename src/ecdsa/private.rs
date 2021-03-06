use cryptonum::signed::*;
use cryptonum::unsigned::*;
use dsa::rfc6979::{DSASignature,KIterator,bits2int};
use ecdsa::curve::{EllipticCurve,P192,P224,P256,P384,P521};
use ecdsa::point::{ECCPoint,Point};
use sha::Hash;
use std::fmt;

/// A private key for the given curve.
#[derive(PartialEq)]
pub struct ECCPrivateKey<Curve: EllipticCurve> {
    pub(crate) d: Curve::Unsigned
}

impl<Curve: EllipticCurve> fmt::Debug for ECCPrivateKey<Curve> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(),fmt::Error>
    {
        f.write_str("<ECCPrivateKey>")
    }
}

/// A generic private key.
pub enum ECDSAPrivate {
    P192(ECCPrivateKey<P192>),
    P224(ECCPrivateKey<P224>),
    P256(ECCPrivateKey<P256>),
    P384(ECCPrivateKey<P384>),
    P521(ECCPrivateKey<P521>),
}

macro_rules! generate_privates
{
    ($curve: ident, $base: ident, $sig: ident, $dbl: ident, $quad: ident) => {
        impl ECCPrivateKey<$curve>
        {
            /// Generate a new private key using the given private scalar.
            pub fn new(d: $base) -> ECCPrivateKey<$curve>
            {
                ECCPrivateKey{ d }
            }

            /// Sign the given message with the current key, using the hash provided
            /// in the type.
            pub fn sign<H: Hash + Clone>(&self, m: &[u8]) -> DSASignature<$base>
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
                let h1 = <H>::hash(m);
                let size = <$curve>::size();
                let h0: $base = bits2int(&h1, size);
                let n = <$curve>::n();
                let h = h0 % &n;
        
                // 2.  A random value modulo q, dubbed k, is generated.  That value
                //     shall not be 0; hence, it lies in the [1, q-1] range.  Most
                //     of the remainder of this document will revolve around the
                //     process used to generate k.  In plain DSA or ECDSA, k should
                //     be selected through a random selection that chooses a value
                //     among the q-1 possible values with uniform probability.
                for k in KIterator::<H,$base>::new(&h1, size, &n, &self.d) {
                    // 3. A value r (modulo q) is computed from k and the key
                    //    parameters:
                    //     *  For DSA ...
                    //     *  For ECDSA ...
                    //
                    //    If r turns out to be zero, a new k should be selected and r
                    //    computed again (this is an utterly improbable occurrence).
                    let g = Point::<$curve>::default();
                    let ki = $sig::new(false, k.clone());
                    let kg = g.scale(&ki);
                    let ni = $sig::from(&n);
                    let ri = &kg.x % &ni;
                    if ri.is_zero() {
                        continue;
                    }
                    if ri.is_negative() {
                        continue;
                    }
                    let r = $base::from(ri);
                    // 4.  The value s (modulo q) is computed:
                    //
                    //           s = (h+x*r)/k mod q
                    //
                    //     The pair (r, s) is the signature.
                    if let Some(kinv) = k.modinv(&n) {
                        let mut hxr = &self.d * &r;
                        hxr += $dbl::from(&h);
                        let base = hxr * $dbl::from(kinv);
                        let s = $base::from(base % $quad::from(n));
                        return DSASignature{ r, s };
                    }
                }
                panic!("The world is broken; couldn't find a k in sign().");
            }
        }
    }
}

generate_privates!(P192, U192, I192, U384,  U768);
generate_privates!(P224, U256, I256, U512,  U1024);
generate_privates!(P256, U256, I256, U512,  U1024);
generate_privates!(P384, U384, I384, U768,  U1536);
generate_privates!(P521, U576, I576, U1152, U2304);

/************* TESTING ********************************************************/

#[cfg(test)]
use sha::{SHA224,SHA256,SHA384,SHA512};
#[cfg(test)]
use testing::*;

#[cfg(test)]
macro_rules! sign_test_body
{
    ($name: ident, $curve: ident, $base: ident) => {
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
            let d = $base::from_bytes(dbytes);
            let _ = $base::from_bytes(xbytes);
            let _ = $base::from_bytes(ybytes);
            let h = $base::from_bytes(hbytes);
            let r = $base::from_bytes(rbytes);
            let s = $base::from_bytes(sbytes);

            let private = ECCPrivateKey::<$curve>::new(d);
            let sig = match usize::from(h) {
                        224 => private.sign::<SHA224>(mbytes),
                        256 => private.sign::<SHA256>(mbytes),
                        384 => private.sign::<SHA384>(mbytes),
                        512 => private.sign::<SHA512>(mbytes),
                        x   => panic!("Unknown hash algorithm {}", x)
            };
            assert_eq!(r, sig.r, "r signature check");
            assert_eq!(s, sig.s, "s signature check");
        });
    }
}

macro_rules! generate_tests {
    ($name: ident, $curve: ident, $base: ident) => {
        #[test]
        fn $name() {
            sign_test_body!($name, $curve, $base);
       }
    };
    (ignore $name: ident, $curve: ident, $base: ident) => {
        #[ignore]
        #[test]
        fn $name() {
            sign_test_body!($name, $curve, $base);
       }
    };
}

generate_tests!(p192_sign, P192, U192);
generate_tests!(ignore p224_sign, P224, U256);
generate_tests!(ignore p256_sign, P256, U256);
generate_tests!(ignore p384_sign, P384, U384);
generate_tests!(ignore p521_sign, P521, U576);