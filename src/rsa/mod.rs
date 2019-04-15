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

pub use self::core::RSAMode;
pub use self::errors::RSAError;
pub use self::signing_hashes::{SigningHash,
                               SIGNING_HASH_NULL,
                               SIGNING_HASH_SHA1,
                               SIGNING_HASH_SHA224,
                               SIGNING_HASH_SHA256,
                               SIGNING_HASH_SHA384,
                               SIGNING_HASH_SHA512};
pub use self::oaep::OAEPParams;
pub use self::private::{RSAPrivate, RSAPrivateKey};
pub use self::public::{RSAPublic, RSAPublicKey};
use cryptonum::signed::{EGCD,ModInv};
use cryptonum::unsigned::{CryptoNum,PrimeGen};
use cryptonum::unsigned::{U256,U512,U1024,U1536,U2048,U3072,U4096,U7680,U8192,U15360};
use rand::RngCore;
#[cfg(test)]
use std::fmt;
use std::ops::Sub;
use super::KeyPair;

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

pub struct RSAKeyPair<R: RSAMode> {
    pub public:  RSAPublicKey<R>,
    pub private: RSAPrivateKey<R>
}

#[derive(PartialEq)]
pub enum RSAPair {
    R512(RSAPublicKey<U512>,     RSAPrivateKey<U512>),
    R1024(RSAPublicKey<U1024>,   RSAPrivateKey<U1024>),
    R2048(RSAPublicKey<U2048>,   RSAPrivateKey<U2048>),
    R3072(RSAPublicKey<U3072>,   RSAPrivateKey<U3072>),
    R4096(RSAPublicKey<U4096>,   RSAPrivateKey<U4096>),
    R8192(RSAPublicKey<U8192>,   RSAPrivateKey<U8192>),
    R15360(RSAPublicKey<U15360>, RSAPrivateKey<U15360>),
}

#[cfg(test)]
impl fmt::Debug for RSAPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> 
    {
        match self {
            RSAPair::R512(_,_) => f.write_str("512-bit RSA key pair"),
            RSAPair::R1024(_,_) => f.write_str("1024-bit RSA key pair"),
            RSAPair::R2048(_,_) => f.write_str("2048-bit RSA key pair"),
            RSAPair::R3072(_,_) => f.write_str("3072-bit RSA key pair"),
            RSAPair::R4096(_,_) => f.write_str("4096-bit RSA key pair"),
            RSAPair::R8192(_,_) => f.write_str("8192-bit RSA key pair"),
            RSAPair::R15360(_,_) => f.write_str("15360-bit RSA key pair"),
        }
    }
}

impl KeyPair for RSAPair {
    type Public = RSAPublic;
    type Private = RSAPrivate;

    fn new(pu: RSAPublic, pr: RSAPrivate) -> RSAPair
    {
        match (pu, pr) {
            (RSAPublic::Key512(pbl), RSAPrivate::Key512(prv)) =>
                RSAPair::R512(pbl, prv),
            (RSAPublic::Key1024(pbl), RSAPrivate::Key1024(prv)) =>
                RSAPair::R1024(pbl, prv),
            (RSAPublic::Key2048(pbl), RSAPrivate::Key2048(prv)) =>
                RSAPair::R2048(pbl, prv),
            (RSAPublic::Key3072(pbl), RSAPrivate::Key3072(prv)) =>
                RSAPair::R3072(pbl, prv),
            (RSAPublic::Key4096(pbl), RSAPrivate::Key4096(prv)) =>
                RSAPair::R4096(pbl, prv),
            (RSAPublic::Key8192(pbl), RSAPrivate::Key8192(prv)) =>
                RSAPair::R8192(pbl, prv),
            (RSAPublic::Key15360(pbl), RSAPrivate::Key15360(prv)) =>
                RSAPair::R15360(pbl, prv),
            _ =>
                panic!("Unmatched public/private arguments to RSAPair::new()")
        }
    }
}

impl RSAPair {
    pub fn sign(&self, signhash: &SigningHash, msg: &[u8]) -> Vec<u8>
    {
        match self {
            RSAPair::R512(_,prv) => prv.sign(signhash, msg),
            RSAPair::R1024(_,prv) => prv.sign(signhash, msg),
            RSAPair::R2048(_,prv) => prv.sign(signhash, msg),
            RSAPair::R3072(_,prv) => prv.sign(signhash, msg),
            RSAPair::R4096(_,prv) => prv.sign(signhash, msg),
            RSAPair::R8192(_,prv) => prv.sign(signhash, msg),
            RSAPair::R15360(_,prv) => prv.sign(signhash, msg),
        }
    }
    
    pub fn verify(&self, signhash: &SigningHash, msg: &[u8], sig: &[u8]) -> bool
    {
        match self {
            RSAPair::R512(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R1024(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R2048(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R3072(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R4096(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R8192(pbl,_) => pbl.verify(signhash, msg, sig),
            RSAPair::R15360(pbl,_) => pbl.verify(signhash, msg, sig),
        }
    }

    pub fn public(&self) -> RSAPublic
    {
        match self {
            &RSAPair::R512(ref pbl,_)   => RSAPublic::Key512(pbl.clone()),
            &RSAPair::R1024(ref pbl,_)  => RSAPublic::Key1024(pbl.clone()),
            &RSAPair::R2048(ref pbl,_)  => RSAPublic::Key2048(pbl.clone()),
            &RSAPair::R3072(ref pbl,_)  => RSAPublic::Key3072(pbl.clone()),
            &RSAPair::R4096(ref pbl,_)  => RSAPublic::Key4096(pbl.clone()),
            &RSAPair::R8192(ref pbl,_)  => RSAPublic::Key8192(pbl.clone()),
            &RSAPair::R15360(ref pbl,_) => RSAPublic::Key15360(pbl.clone()),
        }
     }

    pub fn private(&self) -> RSAPrivate
    {
        match self {
            &RSAPair::R512(_,ref prv)   => RSAPrivate::Key512(prv.clone()),
            &RSAPair::R1024(_,ref prv)  => RSAPrivate::Key1024(prv.clone()),
            &RSAPair::R2048(_,ref prv)  => RSAPrivate::Key2048(prv.clone()),
            &RSAPair::R3072(_,ref prv)  => RSAPrivate::Key3072(prv.clone()),
            &RSAPair::R4096(_,ref prv)  => RSAPrivate::Key4096(prv.clone()),
            &RSAPair::R8192(_,ref prv)  => RSAPrivate::Key8192(prv.clone()),
            &RSAPair::R15360(_,ref prv) => RSAPrivate::Key15360(prv.clone()),
        }
     }
}

macro_rules! generate_rsa_pair
{
    ($uint: ident, $half: ident, $iterations: expr) => {
        impl KeyPair for RSAKeyPair<$uint> {
            type Public = RSAPublicKey<$uint>;
            type Private = RSAPrivateKey<$uint>;

            fn new(pu: RSAPublicKey<$uint>, pr: RSAPrivateKey<$uint>) -> RSAKeyPair<$uint> {
                RSAKeyPair {
                    public: pu,
                    private: pr
                }
            }
        }

        impl RSAKeyPair<$uint> {
            pub fn generate<G>(rng: &mut G) -> RSAKeyPair<$uint>
             where G: RngCore
            {
                loop {
                    let ebase = 65537u32;
                    let e = $uint::from(ebase);
                    let (p, q) = RSAKeyPair::<$uint>::generate_pq(rng, &$half::from(ebase));
                    let one = $half::from(1u32);
                    let pminus1 = &p - &one;
                    let qminus1 = &q - &one;
                    let phi = pminus1 * qminus1;
                    let n = &p * &q;
                    if let Some(d) = e.modinv(&phi) {
                        let public = RSAPublicKey::<$uint>::new(n.clone(), e);
                        let private = RSAPrivateKey::<$uint>::new(n, d);
                        return RSAKeyPair::<$uint>::new(public, private);
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

generate_rsa_pair!(U512,   U256,  7);
generate_rsa_pair!(U1024,  U512,  7);
generate_rsa_pair!(U2048,  U1024, 4);
generate_rsa_pair!(U3072,  U1536, 3);
generate_rsa_pair!(U4096,  U2048, 3);
generate_rsa_pair!(U8192,  U4096, 3);
generate_rsa_pair!(U15360, U7680, 3);

#[cfg(test)]
mod generation {
    use quickcheck::{Arbitrary,Gen};
    use std::fmt;
    use super::*;

    impl Clone for RSAKeyPair<U512> {
        fn clone(&self) -> RSAKeyPair<U512> {
            RSAKeyPair {
                public: RSAPublicKey {
                    n: self.public.n.clone(),
                    nu: self.public.nu.clone(),
                    e: self.public.e.clone(),
                },
                private: RSAPrivateKey {
                    nu: self.private.nu.clone(),
                    d: self.private.d.clone()
                }
            }
        }
    }

    impl fmt::Debug for RSAKeyPair<U512> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("RSA512KeyPair")
             .field("n", &self.public.n)
             .field("e", &self.public.e)
             .field("d", &self.private.d)
             .finish()
        }
    }

    impl Arbitrary for RSAKeyPair<U512> {
        fn arbitrary<G: Gen>(g: &mut G) -> RSAKeyPair<U512> {
            RSAKeyPair::<U512>::generate(g)
        }
    }

    quickcheck! {
        fn generate_and_sign(keypair: RSAKeyPair<U512>, msg: Vec<u8>) -> bool {
            let sig = keypair.private.sign(&SIGNING_HASH_SHA256, &msg);
            keypair.public.verify(&SIGNING_HASH_SHA256, &msg, &sig)
        }
    }
}