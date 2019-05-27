mod errors;
mod params;
mod private;
mod public;
/// Support for RFC6979 signing, which provides a secure way to generate
/// signatures without the use of a random number generator. This is used
/// in DSA signing as well as in ECDSA signing, but appears here because
/// ... well, because it was written for DSA first, both historically
/// (I think) and by me.
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

/// A DSA key pair, for use in signing and signature verification. Note
/// that you probably shouldn't be using DSA any more; ECDSA or ED25519
/// are probably better options.
/// 
/// DSA key pairs are parameterized by their DSA parameters, so that
/// you can't accidentally use them in the wrong place.
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

macro_rules! generate_dsa_pair {
    ($ptype: ident, $ltype: ident, $ntype: ident, $nbig: ident) => {
        impl DSAKeyPair<$ptype>
        {
            /// Generate a DSA key pair using the given parameters and random
            /// number generator. Please make sure that the RNG you're using
            /// is suitable for key generators (look for the term "cryptographic"
            /// or "crypto strong" in its documentation, or see if it matches
            /// any of the NIST-suggested RNG algorithms).
            pub fn generate<G: Rng>(params: &$ptype, rng: &mut G) -> Self
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