mod errors;
mod generation;
#[cfg(test)]
mod gold_tests;
mod parameters;
mod public;
mod private;
mod rfc6979;

pub use self::public::DSAPublic;
pub use self::private::DSAPrivate;
pub use self::rfc6979::DSASignature;

use cryptonum::UCN;
use rand::{OsRng,Rng};
use self::errors::*;
use self::parameters::*;

/// A DSA key pair
#[derive(Clone,Debug,PartialEq)]
pub struct DSAKeyPair {
    pub private: DSAPrivate,
    pub public:  DSAPublic
}

impl DSAKeyPair {
    pub fn generate(size: DSAParameterSize)
        -> Result<DSAKeyPair,DSAGenError>
    {
        let mut rng = OsRng::new()?;
        DSAKeyPair::generate_rng(&mut rng, size)
    }

    pub fn generate_rng<G: Rng>(rng: &mut G, size: DSAParameterSize)
        -> Result<DSAKeyPair,DSAGenError>
    {
        let params = DSAParameters::generate_w_rng(rng, size)?;
        DSAKeyPair::generate_w_params_rng(rng, &params)
    }

    pub fn generate_w_params(params: &DSAParameters)
        -> Result<DSAKeyPair,DSAGenError>
    {
        let mut rng = OsRng::new()?;
        DSAKeyPair::generate_w_params_rng(&mut rng, params)
    }

    pub fn generate_w_params_rng<G: Rng>(rng: &mut G, params: &DSAParameters)
        -> Result<DSAKeyPair,DSAGenError>
    {
        // 1. N = len(q); L = len(p);
        let n = n_bits(params.size);
        // 2. If the (L,N) pair is invalid, then return an ERROR indicator,
        //    Invalid_x, and Invalid_y.
        // 3. requested_security_strength = the security strength associated
        //    with the (L, N) pair; see SP 800-57.
        // 4. Obtain a string of N+64 returned_bits from an RBG with a security
        //    strength of requested_security_strength or more. If an ERROR
        //    indication is returned, then return an ERROR indication,
        //    Invalid_x, and Invalid_y.
        let returned_bits: Vec<u8> = rng.gen_iter().take(n + 8).collect();
        // 5. Convert returned_bits to the (non-negative) integer c.
        let c = UCN::from_bytes(&returned_bits);
        // 6. x = (c mod (q-1)) + 1.
        let one = UCN::from(1 as u64);
        let x = (&c % (&params.q - &one)) + &one;
        // 7. y = g^x mod p
        let y = params.g.fastmodexp(&x, &params.pu);
        // 8. Return SUCCESS, x, and y.
        let private = DSAPrivate { params: params.clone(), x: x };
        let public  = DSAPublic  { params: params.clone(), y: y };
        Ok(DSAKeyPair {
            private: private,
            public: public
        })
    }
}
