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

use cryptonum::signed::{ModInv};
use cryptonum::unsigned::{U256,U512,U1024,U1536,U2048,U3072,U4096,U7680,U8192,U15360};
use rand::Rng;

macro_rules! generate_rsa_pair
{
    ($pair: ident, $pub: ident, $priv: ident, $uint: ident, $half: ident) => {
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

            pub fn generate<G: Rng>(rng: &mut G) -> $pair {
                loop {
                    let e = $uint::from(65537u32);
                    let (p, q) = $pair::generate_pq(rng, &e);
                    let one: $half = $half::from(1u32);
                    let pminus1: $half = &p - &one;
                    let qminus1: $half = &q - &one;
                    let phi: $uint = pminus1 * qminus1;
                    let n = &p * &q;
                    if let Some(d) = e.modinv(&phi) {
                        let public = $pub::new(n.clone(), e);
                        let private = $priv::new(n, d);
                        return $pair::new(public, private);
                    }
                }
            }

            fn generate_pq<G: Rng>(_rng: &mut G, _e: &$uint) -> ($half, $half)
            {
                panic!("generate_pq")
            }
        }
    }
}

generate_rsa_pair!(RSA512KeyPair,   RSA512Public,   RSA512Private,   U512,   U256);
generate_rsa_pair!(RSA1024KeyPair,  RSA1024Public,  RSA1024Private,  U1024,  U512);
generate_rsa_pair!(RSA2048KeyPair,  RSA2048Public,  RSA2048Private,  U2048,  U1024);
generate_rsa_pair!(RSA3072KeyPair,  RSA3072Public,  RSA3072Private,  U3072,  U1536);
generate_rsa_pair!(RSA4096KeyPair,  RSA4096Public,  RSA4096Private,  U4096,  U2048);
generate_rsa_pair!(RSA8192KeyPair,  RSA8192Public,  RSA8192Private,  U8192,  U4096);
generate_rsa_pair!(RSA15360KeyPair, RSA15360Public, RSA15360Private, U15360, U7680);
