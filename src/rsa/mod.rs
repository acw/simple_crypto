//! A simple RSA library.
//!
//! This library performs all the standard bits and pieces that you'd expect
//! from an RSA library, and does so using only Rust. It's a bit slow at the
//! moment, but it gets the job done.
//!
//! Key generation is supported, using either the native `OsRng` or a random
//! number generator of your choice. Obviously, you should be careful to use
//! a cryptographically-sound random number generator sufficient for the
//! security level you're going for.
//!
//! Signing and verification are via standard PKCS1 padding, but can be
//! adjusted based on the exact hash you want. This library also supports
//! somewhat arbitrary signing mechanisms used by your weirder network
//! protocols. (I'm looking at you, Tor.)
//!
//! Encryption and decryption are via the OAEP mechanism, as described in
//! NIST documents.
//!
mod core;
mod errors;
mod oaep;
mod private;
mod public;
mod signing_hashes;

pub use self::errors::RSAError;
pub use self::signing_hashes::{SigningHash,
                               SIGNING_HASH_NULL,
                               SIGNING_HASH_SHA1,
                               SIGNING_HASH_SHA224,
                               SIGNING_HASH_SHA256,
                               SIGNING_HASH_SHA384,
                               SIGNING_HASH_SHA512};
pub use self::oaep::OAEPParams;
pub use self::private::{RSAPrivate, RSAPrivateKey,
                        RSA512Private, RSA1024Private, RSA2048Private,
                        RSA3072Private, RSA4096Private, RSA8192Private,
                        RSA15360Private};
pub use self::public::{RSAPublic, RSAPublicKey,
                       RSA512Public, RSA1024Public, RSA2048Public,
                       RSA3072Public, RSA4096Public, RSA8192Public,
                       RSA15360Public};

use cryptonum::signed::{EGCD,ModInv};
use cryptonum::unsigned::{CryptoNum,PrimeGen};
use cryptonum::unsigned::{U256,U512,U1024,U1536,U2048,U3072,U4096,U7680,U8192,U15360};
use rand::RngCore;
use std::ops::Sub;

fn diff<T>(a: &T, b: &T) -> T
 where
  T: Clone + PartialOrd,
  T: Sub<T,Output=T>
{
    if a > b {
        a.clone() - b.clone()
    } else {
        b.clone() - a.clone()
    }
}

macro_rules! generate_rsa_pair
{
    ($pair: ident, $pub: ident, $priv: ident, $uint: ident, $half: ident, $iterations: expr) => {
        pub struct $pair {
            pub public: $pub,
            pub private: $priv
        }

        impl $pair {
            pub fn new(pu: $pub, pr: $priv) -> $pair {
                $pair {
                    public: pu,
                    private: pr
                }
            }

            pub fn generate<G>(rng: &mut G) -> $pair
             where G: RngCore
            {
                loop {
                    let ebase = 65537u32;
                    let e = $uint::from(ebase);
                    let (p, q) = $pair::generate_pq(rng, &$half::from(ebase));
                    let one = $half::from(1u32);
                    let pminus1 = &p - &one;
                    let qminus1 = &q - &one;
                    let phi = pminus1 * qminus1;
                    let n = &p * &q;
                    if let Some(d) = e.modinv(&phi) {
                        let public = $pub::new(n.clone(), e);
                        let private = $priv::new(n, d);
                        return $pair::new(public, private);
                    }
                }
            }

            fn generate_pq<G>(rng: &mut G, e: &$half) -> ($half, $half)
             where G: RngCore
            {
                let sqrt2_32 = 6074001000u64;
                let half_bitlen = $half::bit_length();
                let minval = $half::from(sqrt2_32) << (half_bitlen - 33);
                let mindiff = $half::from(1u64) << (half_bitlen - 101);
                let p = $half::random_primef(rng, $iterations, |x| {
                    if (x >= minval) && x.gcd_is_one(e) {
                        Some(x)
                    } else {
                        None
                    }
                });

                loop {
                    let q = $half::random_primef(rng, $iterations, |x| {
                        if (x >= minval) && x.gcd_is_one(e) {
                            Some(x)
                        } else {
                            None
                        }
                    });

                    if diff(&p, &q) >= mindiff {
                        return (p, q);
                    }
                }
            }
        }
    }
}

generate_rsa_pair!(RSA512KeyPair,   RSA512Public,   RSA512Private,   U512,   U256,  7);
generate_rsa_pair!(RSA1024KeyPair,  RSA1024Public,  RSA1024Private,  U1024,  U512,  7);
generate_rsa_pair!(RSA2048KeyPair,  RSA2048Public,  RSA2048Private,  U2048,  U1024, 4);
generate_rsa_pair!(RSA3072KeyPair,  RSA3072Public,  RSA3072Private,  U3072,  U1536, 3);
generate_rsa_pair!(RSA4096KeyPair,  RSA4096Public,  RSA4096Private,  U4096,  U2048, 3);
generate_rsa_pair!(RSA8192KeyPair,  RSA8192Public,  RSA8192Private,  U8192,  U4096, 3);
generate_rsa_pair!(RSA15360KeyPair, RSA15360Public, RSA15360Private, U15360, U7680, 3);

#[cfg(test)]
mod generation {
    use quickcheck::{Arbitrary,Gen};
    use std::fmt;
    use super::*;

    impl Clone for RSA512KeyPair {
        fn clone(&self) -> RSA512KeyPair {
            RSA512KeyPair{
                public: RSA512Public {
                    n: self.public.n.clone(),
                    nu: self.public.nu.clone(),
                    e: self.public.e.clone(),
                },
                private: RSA512Private {
                    nu: self.private.nu.clone(),
                    d: self.private.d.clone()
                }
            }
        }
    }

    impl fmt::Debug for RSA512KeyPair {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("RSA512KeyPair")
             .field("n", &self.public.n)
             .field("e", &self.public.e)
             .field("d", &self.private.d)
             .finish()
        }
    }

    impl Arbitrary for RSA512KeyPair {
        fn arbitrary<G: Gen>(g: &mut G) -> RSA512KeyPair {
            RSA512KeyPair::generate(g)
        }
    }

    quickcheck! {
        fn generate_and_sign(keypair: RSA512KeyPair, msg: Vec<u8>) -> bool {
            let sig = keypair.private.sign(&SIGNING_HASH_SHA256, &msg);
            keypair.public.verify(&SIGNING_HASH_SHA256, &msg, &sig)
        }
    }
}