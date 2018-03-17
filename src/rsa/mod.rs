//! # An implementation of RSA.
//!
//! This module is designed to provide implementations of the core routines
//! used for asymmetric cryptography using RSA. It probably provides a bit
//! more flexibility than beginners should play with, and definitely includes
//! some capabilities largely targeted at legacy systems. New users should
//! probably stick with the stuff in the root of this crate.
mod core;
mod errors;
mod oaep;
mod private;
mod public;
mod signing_hashes;

use cryptonum::*;
use rand::{OsRng,Rng};
use std::cmp::PartialOrd;
use std::ops::*;

pub use self::errors::{RSAKeyGenError,RSAError};
pub use self::oaep::{OAEPParams};
pub use self::private::RSAPrivateKey;
pub use self::public::RSAPublicKey;
pub use self::signing_hashes::{SigningHash,
                              SIGNING_HASH_NULL,   SIGNING_HASH_SHA1,
                              SIGNING_HASH_SHA224, SIGNING_HASH_SHA256,
                              SIGNING_HASH_SHA384, SIGNING_HASH_SHA512};

/// An RSA public and private key.
#[derive(Clone,Debug,PartialEq)]
pub struct RSAKeyPair<Size>
 where
  Size: CryptoNumBase + CryptoNumSerialization
{
    pub private: RSAPrivateKey<Size>,
    pub public:  RSAPublicKey<Size>
}

impl<T> RSAKeyPair<T>
 where
  T: Clone + Sized + PartialOrd,
  T: CryptoNumBase + CryptoNumModOps + CryptoNumPrimes + CryptoNumSerialization,
  T: Sub<Output=T> + Mul<Output=T> + Shl<usize,Output=T>
{
    /// Generates a fresh RSA key pair. If you actually want to protect data,
    /// use a value greater than or equal to 2048. If you don't want to spend
    /// all day waiting for RSA computations to finish, choose a value less
    /// than or equal to 4096.
    ///
    /// This routine will use `OsRng` for entropy. If you want to use your
    /// own random number generator, use `generate_w_rng`.
    pub fn generate() -> Result<RSAKeyPair<T>,RSAKeyGenError> {
        let mut rng = OsRng::new()?;
        RSAKeyPair::<T>::generate_w_rng(&mut rng)
    }

    /// Generates a fresh RSA key pair of the given bit size. Valid bit sizes
    /// are 512, 1024, 2048, 3072, 4096, 7680, 8192, and 15360. If you
    /// actually want to protect data, use a value greater than or equal to
    /// 2048. If you don't want to spend all day waiting for RSA computations
    /// to finish, choose a value less than or equal to 4096.
    ///
    /// If you provide your own random number generator that is not `OsRng`,
    /// you should know what you're doing, and be using a cryptographically-
    /// strong RNG of your own choosing. We've warned you. Use a good one.
    /// So now it's on you.
    pub fn generate_w_rng<G: Rng>(rng: &mut G)
        -> Result<RSAKeyPair<T>,RSAKeyGenError>
    {
        let e = T::from_u32(65537);
        let len_bits = e.bit_size();
        match generate_pq(rng, &e) {
            None =>
                return Err(RSAKeyGenError::InvalidKeySize(len_bits)),
            Some((p, q)) => {
                let n = p.clone() * q.clone();
                let phi = (p - T::from_u64(1)) * (q - T::from_u64(1));
                let d = e.modinv(&phi);
                let public_key  = RSAPublicKey::new(n.clone(), e);
                let private_key = RSAPrivateKey::new(n, d);
                return Ok(RSAKeyPair{ private: private_key, public: public_key })
            }
        }
    }
}

pub fn generate_pq<'a,G,T>(rng: &mut G, e: &T) -> Option<(T,T)>
 where
  G: Rng,
  T: Clone + PartialOrd + Shl<usize,Output=T> + Sub<Output=T>,
  T: CryptoNumBase + CryptoNumPrimes + CryptoNumSerialization
{
    let bitlen = T::zero().bit_size();
    let mindiff = T::from_u8(1) << ((bitlen/2)-101);
    let minval  = T::from_u64(6074001000) << ((mindiff.bit_size()/2) - 33);
    let p = T::generate_prime(rng, 7, e, &minval);

    loop {
        let q = T::generate_prime(rng, 7, e, &minval);

        if diff(p.clone(), q.clone()) >= mindiff {
            return Some((p, q));
        }
    }
}

fn diff<T: PartialOrd + Sub<Output=T>>(a: T, b: T) -> T
{
    if a > b {
        a - b
    } else {
        b - a
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary,Gen};
    use rsa::core::{dp,ep,sp1,vp1};
    use sha2::Sha224;
    use simple_asn1::{der_decode,der_encode};
    use super::*;

    impl Arbitrary for RSAKeyPair<U512> {
        fn arbitrary<G: Gen>(g: &mut G) -> RSAKeyPair<U512> {
            RSAKeyPair::generate_w_rng(g).unwrap()
        }
    }

    // Core primitive checks
    quickcheck! {
        fn ep_dp_inversion(kp: RSAKeyPair<U512>, m: U512) -> bool {
            let realm = &m % &kp.public.n;
            let ciphertext = ep(&kp.public.n, &kp.public.e, &realm);
            let mprime = dp(&kp.private.n, &kp.private.d, &ciphertext);
            mprime == m
        }
        fn sp_vp_inversion(kp: RSAKeyPair<U512>, m: U512) -> bool {
            let realm = &m % &kp.public.n;
            let sig = sp1(&kp.private.n, &kp.private.d, &realm);
            let mprime = vp1(&kp.public.n, &kp.public.e, &sig);
            mprime == m
        }
    }

    // Public key serialization
    quickcheck! {
        fn asn1_encoding_inverts(kp: RSAKeyPair<U512>) -> bool {
            let bytes = der_encode(&kp.public).unwrap();
            let pubkey: RSAPublicKey<U512> = der_decode(&bytes).unwrap();
            (pubkey.n == kp.public.n) && (pubkey.e == kp.public.e)
        }
    }

    #[derive(Clone,Debug)]
    struct Message {
        m: Vec<u8>
    }

    impl Arbitrary for Message {
        fn arbitrary<G: Gen>(g: &mut G) -> Message {
            let len = 1 + (g.gen::<u8>() % 3);
            let mut storage = Vec::new();
            for _ in 0..len {
                storage.push(g.gen::<u8>());
            }
            Message{ m: storage }
        }
    }

    #[derive(Clone,Debug)]
    struct KeyPairAndSigHash<T>
      where
        T: CryptoNumSerialization + CryptoNumBase
    {
        kp: RSAKeyPair<T>,
        sh: &'static SigningHash
    }

    impl<T> Arbitrary for KeyPairAndSigHash<T>
      where
        T: Clone + Sized + PartialOrd,
        T: CryptoNumBase + CryptoNumModOps,
        T: CryptoNumPrimes + CryptoNumSerialization,
        T: Sub<Output=T> + Mul<Output=T> + Shl<usize,Output=T>,
        RSAKeyPair<T>: Arbitrary
    {
        fn arbitrary<G: Gen>(g: &mut G) -> KeyPairAndSigHash<T> {
            let kp = RSAKeyPair::generate_w_rng(g).unwrap();
            let size = kp.public.n.bit_size();
            let mut hashes = vec![&SIGNING_HASH_SHA1];

            if size >= 1024 {
                hashes.push(&SIGNING_HASH_SHA224);
            }

            if size >= 2048 {
                hashes.push(&SIGNING_HASH_SHA256);
            }

            if size >= 4096 {
                hashes.push(&SIGNING_HASH_SHA384);
                hashes.push(&SIGNING_HASH_SHA512);
            }

            let hash = g.choose(&hashes).unwrap().clone();
            KeyPairAndSigHash{ kp: kp, sh: hash }
        }
    }

    quickcheck! {
        fn sign_verifies(kpsh: KeyPairAndSigHash<U512>, m: Message) -> bool {
            let sig = kpsh.kp.private.sign(kpsh.sh, &m.m);
            kpsh.kp.public.verify(kpsh.sh, &m.m, &sig)
        }

        fn enc_dec_roundtrips(kp: RSAKeyPair<U512>, m: Message) -> bool {
            let oaep = OAEPParams {
                hash: Sha224::default(),
                label: "test".to_string()
            };
            let c = kp.public.encrypt(&oaep, &m.m).unwrap();
            let mp = kp.private.decrypt(&oaep, &c).unwrap();

            mp == m.m
        }
    }
}
