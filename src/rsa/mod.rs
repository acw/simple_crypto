mod core;
mod errors;
#[cfg(test)]
mod gold_tests;
mod oaep;
mod public;
mod private;
mod signing_hashes;

pub use self::public::RSAPublic;
pub use self::private::RSAPrivate;
pub use self::signing_hashes::{SigningHash,
                               SIGNING_HASH_NULL, SIGNING_HASH_SHA1,
                               SIGNING_HASH_SHA224, SIGNING_HASH_SHA256,
                               SIGNING_HASH_SHA384, SIGNING_HASH_SHA512};

use cryptonum::UCN;
use rand::{OsRng,Rng};
use self::core::{ACCEPTABLE_KEY_SIZES,generate_pq};
use self::errors::*;

#[derive(Clone,Debug)]
pub struct RSAKeyPair {
    pub public: RSAPublic,
    pub private: RSAPrivate
}

impl RSAKeyPair {
    /// Generates a fresh RSA key pair of the given bit size. Valid bit sizes
    /// are 512, 1024, 2048, 3072, 4096, 7680, 8192, and 15360. If you
    /// actually want to protect data, use a value greater than or equal to
    /// 2048. If you don't want to spend all day waiting for RSA computations
    /// to finish, choose a value less than or equal to 4096.
    ///
    /// This routine will use `OsRng` for entropy. If you want to use your
    /// own random number generator, use `generate_w_rng`.
    pub fn generate(len_bits: usize) -> Result<RSAKeyPair,RSAKeyGenError> {
        let mut rng = OsRng::new()?;
        RSAKeyPair::generate_w_rng(&mut rng, len_bits)
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
    pub fn generate_w_rng<G: Rng>(rng: &mut G, len_bits: usize)
        -> Result<RSAKeyPair,RSAKeyGenError>
    {
        let e = UCN::from(65537 as u32);

        for &(length, _) in ACCEPTABLE_KEY_SIZES.iter() {
            if length == len_bits {
                let (p, q) = generate_pq(rng, &e, len_bits);
                let n = &p * &q;
                let one = UCN::from(1 as u8);
                let phi = (p - &one) * (q - &one);
                let d = e.modinv(&phi);
                let public_key  = RSAPublic::new(n.clone(), e);
                let private_key = RSAPrivate::new(n, d);
                return Ok(RSAKeyPair{
                    private: private_key,
                    public: public_key
                })
            }
        }

        Err(RSAKeyGenError::InvalidKeySize(len_bits))
    }

}

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary,Gen};
    use rsa::core::{ep,dp,sp1,vp1};
    use super::*;

    const TEST_KEY_SIZES: [usize; 2] = [512, 1024];

    impl Arbitrary for RSAKeyPair {
        fn arbitrary<G: Gen>(g: &mut G) -> RSAKeyPair {
            let size = g.choose(&TEST_KEY_SIZES).unwrap();
            RSAKeyPair::generate_w_rng(g, *size).unwrap()
        }
    }

    quickcheck! {
        fn rsa_ep_dp_inversion(kp: RSAKeyPair, n: UCN) -> bool {
            let m = n.reduce(&kp.public.nu);
            let ciphertext = ep(&kp.public.nu, &kp.public.e, &m);
            let mprime = dp(&kp.private.nu, &kp.private.d, &ciphertext);
            mprime == m
        }
        fn rsa_sp_vp_inversion(kp: RSAKeyPair, n: UCN) -> bool {
            let m = n.reduce(&kp.public.nu);
            let sig = sp1(&kp.private.nu, &kp.private.d, &m);
            let mprime = vp1(&kp.public.nu, &kp.public.e, &sig);
            mprime == m
        }
    }
}
