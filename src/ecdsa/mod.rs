//! The generation and use of ECDSA keys is pretty straightforward, compared
//! to DSA and RSA. You should be able to find what you want to do in the
//! following code snippet, as an example:
//!
//! ```rust
//! use simple_crypto::ecdsa::{ECDSAKeyPair,P384};
//! use simple_crypto::sha::SHA256;
//! 
//! // Generate a new ECDSA key for curve P384 (this is a good choice, by
//! // the way, if you're wondering which curve to use).
//! let mut rng = rand::rngs::OsRng::new().unwrap();
//! let kp = ECDSAKeyPair::<P384>::generate(&mut rng);
//! 
//! // Now that you have this key pair, you can sign and verify messages
//! // using it. For example, to sign the vector [0,1,2,3,4] with SHA256
//! // and then verify that signature, we would write: 
//! let msg = vec![0,1,2,3,4];
//! let sig = kp.private.sign::<SHA256>(&msg);
//! assert!( kp.public.verify::<SHA256>(&msg, &sig) );
//! ```

mod curve;
pub(crate) mod point;
mod private;
mod public;

use cryptonum::signed::{I192,I256,I384,I576};
use cryptonum::unsigned::{CryptoNum,Decoder};
use cryptonum::unsigned::{U192,U256,U384,U576};
use rand::Rng;
use rand::distributions::Standard;
pub use self::curve::{EllipticCurve,P192,P224,P256,P384,P521};
use self::point::{ECCPoint,Point};
pub use self::private::{ECDSAPrivate,ECCPrivateKey};
pub use self::public::{ECDSAPublic,ECCPublicKey};
pub use self::public::{ECDSADecodeErr,ECDSAEncodeErr};
use super::KeyPair;

/// An ECDSA key pair for the given curve.
pub struct ECDSAKeyPair<Curve: EllipticCurve> {
    pub public: ECCPublicKey<Curve>,
    pub private: ECCPrivateKey<Curve>
}

/// A generic ECDSA key pair that implements one of our known curves, for cases
/// when you're not sure which one you're going to have.
pub enum ECDSAPair {
    P192(ECCPublicKey<P192>,ECCPrivateKey<P192>),
    P224(ECCPublicKey<P224>,ECCPrivateKey<P224>),
    P256(ECCPublicKey<P256>,ECCPrivateKey<P256>),
    P384(ECCPublicKey<P384>,ECCPrivateKey<P384>),
    P521(ECCPublicKey<P521>,ECCPrivateKey<P521>),
}

impl KeyPair for ECDSAPair {
    type Public = ECDSAPublic;
    type Private = ECDSAPrivate;

    fn new(pu: ECDSAPublic, pr: ECDSAPrivate) -> ECDSAPair
    {
        match (pu, pr) {
            (ECDSAPublic::P192(pbl),ECDSAPrivate::P192(prv)) => ECDSAPair::P192(pbl,prv),
            (ECDSAPublic::P224(pbl),ECDSAPrivate::P224(prv)) => ECDSAPair::P224(pbl,prv),
            (ECDSAPublic::P256(pbl),ECDSAPrivate::P256(prv)) => ECDSAPair::P256(pbl,prv),
            (ECDSAPublic::P384(pbl),ECDSAPrivate::P384(prv)) => ECDSAPair::P384(pbl,prv),
            (ECDSAPublic::P521(pbl),ECDSAPrivate::P521(prv)) => ECDSAPair::P521(pbl,prv),
            _ =>
                panic!("Non-matching public/private pairs in ECDSAPair::new()")
        } 
    }
}

macro_rules! generate_impl {
    ($curve: ident, $un: ident, $si: ident) => {
        impl KeyPair for ECDSAKeyPair<$curve> {
            type Public = ECCPublicKey<$curve>;
            type Private = ECCPrivateKey<$curve>;

            fn new(public: ECCPublicKey<$curve>, private: ECCPrivateKey<$curve>) -> ECDSAKeyPair<$curve>
            {
                ECDSAKeyPair{ public, private }
            }
        }

        impl ECDSAKeyPair<$curve> {
            /// Generate a fresh ECDSA key pair for this curve, given the
            /// provided random number generator. THIS MUST BE A CRYPTO
            /// STRONG RNG. If it's not, then you're going to generate weak
            /// keys and the crypto gremlins will get you.
            pub fn generate<G: Rng>(rng: &mut G) -> ECDSAKeyPair<$curve>
            {
                loop {
                    let size = ($curve::size() + 7) / 8;
                    let random_bytes: Vec<u8> = rng.sample_iter(&Standard).take(size).collect();
                    let proposed_d = $un::from_bytes(&random_bytes);

                    if proposed_d.is_zero() {
                        continue;
                    }

                    if proposed_d >= $curve::n() {
                        continue;
                    }

                    let d = $si::from(&proposed_d);
                    let public_point = Point::<$curve>::default().scale(&d);
                    let public = ECCPublicKey::<$curve>::new(public_point);
                    let private = ECCPrivateKey::<$curve>::new(proposed_d);

                    return ECDSAKeyPair{ public, private };
                }
            }
        }
    };
}

generate_impl!(P192, U192, I192);
generate_impl!(P224, U256, I256);
generate_impl!(P256, U256, I256);
generate_impl!(P384, U384, I384);
generate_impl!(P521, U576, I576);