use ecdsa::curves::EllipticCurve;
use ecdsa::math::ECCPoint;

#[allow(non_snake_case)]
#[derive(Clone,Debug,PartialEq)]
pub struct ECDSAPublic {
    pub(crate) curve: EllipticCurve,
    pub(crate) Q: ECCPoint
}


