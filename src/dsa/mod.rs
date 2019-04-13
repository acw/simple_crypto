mod errors;
mod params;
mod private;
mod public;
pub mod rfc6979;
#[cfg(test)]
mod tests;

pub use self::params::*;
pub use self::private::*;
pub use self::public::*;

use cryptonum::unsigned::*;
use rand::Rng;
use rand::distributions::Standard;
use super::KeyPair;

pub struct DSAKeyPair<P: DSAParameters>
{
    pub private: DSAPrivateKey<P>,
    pub public: DSAPublicKey<P>
}

impl<P: DSAParameters> KeyPair for DSAKeyPair<P>
{
    type Private = DSAPrivateKey<P>;
    type Public = DSAPublicKey<P>;

    fn new(public: DSAPublicKey<P>, private: DSAPrivateKey<P>) -> DSAKeyPair<P>
    {
        DSAKeyPair{ private, public }
    }
}

pub trait DSAKeyGeneration
{
    type Params;

    fn generate<G: Rng>(params: &Self::Params, rng: &mut G) -> Self;
}

macro_rules! generate_dsa_pair {
    ($ptype: ident, $ltype: ident, $ntype: ident, $nbig: ident) => {
        impl DSAKeyGeneration for DSAKeyPair<$ptype>
        {
            type Params = $ptype;

            fn generate<G: Rng>(params: &$ptype, rng: &mut G) -> Self
            {
                // 1. N = len(q); L = len(p);
                let n = $ptype::n_size();
                // 2. If the (L,N) pair is invalid, then return an ERROR indicator,
                //    Invalid_x, and Invalid_y.
                // 3. requested_security_strength = the security strength associated
                //    with the (L, N) pair; see SP 800-57.
                // 4. Obtain a string of N+64 returned_bits from an RBG with a security
                //    strength of requested_security_strength or more. If an ERROR
                //    indication is returned, then return an ERROR indication,
                //    Invalid_x, and Invalid_y.
                let returned_bits: Vec<u8> = rng.sample_iter(&Standard).take(n + 8).collect();
                // 5. Convert returned_bits to the (non-negative) integer c.
                let c = $nbig::from_bytes(&returned_bits);
                // 6. x = (c mod (q-1)) + 1.
                let one = $nbig::from(1 as u64);
                let qbig = $nbig::from(&params.q);
                let x = $ntype::from( (&c % (&qbig - &one)) + &one );
                // 7. y = g^x mod p
                let y = params.g.modexp(&$ltype::from(&x), &params.p);
                // 8. Return SUCCESS, x, and y.
                let private = DSAPrivateKey::<$ptype>::new(params.clone(), x);
                let public  = DSAPublicKey::<$ptype>::new(params.clone(), y);
                DSAKeyPair { private, public }
            }
        }
    };
}

generate_dsa_pair!(L1024N160, U1024, U192, U256);
generate_dsa_pair!(L2048N224, U2048, U256, U384);
generate_dsa_pair!(L2048N256, U2048, U256, U384);
generate_dsa_pair!(L3072N256, U3072, U256, U384);