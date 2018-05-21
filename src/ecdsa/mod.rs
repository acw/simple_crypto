mod curves;
#[cfg(test)]
mod gold_tests;
mod math;
mod private;
mod public;

pub use self::private::ECDSAPrivate;
pub use self::public::ECDSAPublic;

use cryptonum::UCN;
use rand::{Rng,OsRng};
use self::curves::EllipticCurve;
use self::math::ECCPoint;

#[derive(Clone,Debug,PartialEq)]
pub struct ECDSAKeyPair {
    pub private: ECDSAPrivate,
    pub public:  ECDSAPublic
}

impl ECDSAKeyPair {
    pub fn generate(params: &EllipticCurve)
        -> ECDSAKeyPair
    {
        let mut rng = OsRng::new().unwrap();
        ECDSAKeyPair::generate_w_rng(&mut rng, params)

    }

    pub fn generate_w_rng<G: Rng>(rng: &mut G, params: &EllipticCurve)
        -> ECDSAKeyPair
    {
        let one = UCN::from(1u64);
        #[allow(non_snake_case)]
        let N = params.n.bits();
        let bits_to_generate = N + 64;
        let bytes_to_generate = (bits_to_generate + 7) / 8;
        let bits: Vec<u8> = rng.gen_iter().take(bytes_to_generate).collect();
        let bits_generated = bytes_to_generate * 8;
        let mut c = UCN::from_bytes(&bits);
        c >>= bits_generated - bits_to_generate;
        let nm1 = &params.n - &one;
        let d = (c % &nm1) + &one;
        #[allow(non_snake_case)]
        let Q = ECCPoint::default(params).scale(&d);
        ECDSAKeyPair {
            private: ECDSAPrivate {
                curve: params.clone(),
                d: d
            },
            public: ECDSAPublic {
                curve: params.clone(),
                Q: Q
            }
        }
    }
}


