pub mod curve;
pub mod point;
pub mod private;
pub mod public;

use cryptonum::signed::{I192,I256,I384,I576};
use cryptonum::unsigned::{CryptoNum,Decoder};
use cryptonum::unsigned::{U192,U256,U384,U576};
use rand::Rng;
use rand::distributions::Standard;
use self::curve::{EllipticCurve,P192,P224,P256,P384,P521};
use self::point::{ECCPoint,Point};
pub use self::private::{ECCPrivateKey,ECCPrivate};
pub use self::public::{ECCPublicKey,ECCPublic};

pub trait ECDSAKeyPair<Public,Private> {
    fn generate<G: Rng>(g: &mut G) -> (Public, Private);
}

macro_rules! generate_impl {
    ($curve: ident, $un: ident, $si: ident) => {
        impl ECDSAKeyPair<ECCPublic<$curve>,ECCPrivate<$curve>> for $curve {
            fn generate<G: Rng>(rng: &mut G) -> (ECCPublic<$curve>, ECCPrivate<$curve>)
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
                    let public = ECCPublic::<$curve>::new(public_point);
                    let private = ECCPrivate::<$curve>::new(proposed_d);
                    return (public, private);
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