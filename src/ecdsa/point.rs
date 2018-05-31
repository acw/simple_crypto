use cryptonum::{SCN,UCN};
use ecdsa::curves::EllipticCurve;

#[derive(Clone,Debug,PartialEq)]
pub struct ECPoint {
    pub curve: &'static EllipticCurve,
    pub value: ECPointValue
}

#[derive(Clone,Debug,PartialEq)]
pub enum ECPointValue {
    Infinity,
    Point(SCN, SCN)
}

impl ECPoint {
    pub fn new(ec: &'static EllipticCurve, x: SCN, y: SCN) -> ECPoint {
        ECPoint {
            curve: ec,
            value: ECPointValue::Point(x, y)
        }
    }

    pub fn zero(ec: &'static EllipticCurve) -> ECPoint {
        ECPoint { curve: ec, value: ECPointValue::Infinity }
    }

    pub fn negate(&self) -> ECPoint {
        match self.value {
            ECPointValue::Infinity =>
                self.clone(),
            ECPointValue::Point(ref x, ref y) => {
                let newy = SCN::from(self.curve.get_p()) - y;
                let newv = ECPointValue::Point(x.clone(), newy);
                ECPoint{ curve: self.curve, value: newv }
            }
        }
    }

    pub fn get_x(&self) -> SCN {
        match self.value {
            ECPointValue::Infinity =>
                SCN::zero(),
            ECPointValue::Point(ref x, _) =>
                x.clone()
        }
    }

    pub fn get_y(&self) -> SCN {
        match self.value {
            ECPointValue::Infinity =>
                SCN::zero(),
            ECPointValue::Point(_, ref y) =>
                y.clone()
        }
    }

    pub fn double(&self) -> ECPoint {
        match self.value {
            ECPointValue::Infinity =>
                self.clone(),
            ECPointValue::Point(ref x, ref y) => {
                let ua = SCN::from(self.curve.get_a());
                let up = SCN::from(self.curve.get_p());
                // lambda = (3 * xp ^ 2 + a) / 2 yp
                let mut lambda = x * x;
                lambda *= SCN::from(3);
                lambda += &ua;
                let twoy = y << 1;
                lambda = lambda.divmod(&twoy, &self.curve.get_pu());
                // xr = lambda ^ 2 - 2 xp
                let mut xr = &lambda * &lambda;
                let xr_right = x << 1;
                xr -= xr_right;
                assert!(!xr.is_negative());
                xr %= &up;
                // yr = lambda (xp - xr) - yp
                let xdiff = x - &xr;
                let mut yr = &lambda * &xdiff;
                yr -= y;
                assert!(!yr.is_negative());
                yr %= up;
                //
                ECPoint {
                    curve: self.curve,
                    value: ECPointValue::Point(xr, yr)
                }
            }
        }
    }

    pub fn add(&self, other: &ECPoint) -> ECPoint {
        assert_eq!(self.curve, other.curve);
        match (&self.value, &other.value) {
            (ECPointValue::Infinity, ECPointValue::Infinity) =>
                self.clone(),
            (ECPointValue::Infinity, _) =>
                other.clone(),
            (_, ECPointValue::Infinity) =>
                self.clone(),
            (ECPointValue::Point(ref sx, ref sy),
             ECPointValue::Point(ref ox, ref oy)) => {
                let xdiff = sx - ox;
                let ydiff = sy - oy;
                let pu = self.curve.get_pu();
                let s = ydiff.divmod(&xdiff, &pu);
                let mut xr = &s * &s;
                xr -= sx;
                xr -= ox;
                xr = xr.reduce(&pu);
                let mut yr = sx - &xr;
                yr *= &s;
                yr -= sy;
                yr = yr.reduce(&pu);
                let val = ECPointValue::Point(xr, yr);
                ECPoint{ curve: self.curve, value: val }
             }
        }
    }

    pub fn scale(&self, d: &UCN) -> ECPoint {
        match self.value {
            ECPointValue::Infinity =>
                self.clone(),
            ECPointValue::Point(_, _) => {
                if d.is_zero() {
                    return ECPoint::zero(self.curve);
                }

                let mut q = self.clone();
                let i = d.bits() - 2;
                let mut mask = UCN::from(1u64) << i;

                while !mask.is_zero() {
                    q = q.double();

                    let test = d & &mask;
                    if !test.is_zero() {
                        q = q.add(&self);
                    }
                    mask >>= 1;
                }

                q
            }
        }
    }
}
// 
// pub fn bits2int(x: &[u8], qlen: usize) -> UCN {
//     let mut value = UCN::from_bytes(x);
//     let vlen = x.len() * 8;
// 
//     if vlen > qlen {
//         value >>= vlen - qlen;
//     }
// 
//     value
// }
// 
// pub fn point_add_two_muls(k1: &UCN, p1: &ECCPoint, k2: &UCN, p2: &ECCPoint)
//     -> ECCPoint
// {
//     panic!("point_add_two_muls()")
// }
// 
// #[cfg(test)]
// mod tests {
//     use super::*;
// 
//     #[test]
//     fn p256_double() {
//         let xbytes = vec![0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
//                           0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
//                           0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
//                           0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78];
//         let ybytes = vec![0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40,
//                           0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
//                           0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29,
//                           0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1];
//         let x = SCN::from(UCN::from_bytes(&xbytes));
//         let y = SCN::from(UCN::from_bytes(&ybytes));
//         let base = ECCPoint::default(&EllipticCurve::p256());
//         let res = base.double();
//         let goal = ECCPoint{ curve: base.curve,
//                              value: ECCPointValue::Point(x,y) };
//         assert_eq!(res, goal);
//     }
// 
//     #[test]
//     fn p256_add() {
//         let xbytes = vec![0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a, 0x44,
//                           0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1, 0x65,
//                           0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9, 0x85,
//                           0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7, 0xfd, 0x6c];
//         let ybytes = vec![0x87, 0x34, 0x64, 0x0c, 0x49, 0x98, 0xff, 0x7e,
//                           0x37, 0x4b, 0x06, 0xce, 0x1a, 0x64, 0xa2, 0xec,
//                           0xd8, 0x2a, 0xb0, 0x36, 0x38, 0x4f, 0xb8, 0x3d,
//                           0x9a, 0x79, 0xb1, 0x27, 0xa2, 0x7d, 0x50, 0x32];
//         let x = SCN::from(UCN::from_bytes(&xbytes));
//         let y = SCN::from(UCN::from_bytes(&ybytes));
//         let base = ECCPoint::default(&EllipticCurve::p256());
//         let res = base.add(&base.double());
//         let goal = ECCPoint{ curve: base.curve,
//                              value: ECCPointValue::Point(x,y) };
//         assert_eq!(res, goal);
//     }
// 
//     #[test]
//     fn p256_scale() {
//         let xbytes = vec![0xea, 0x68, 0xd7, 0xb6, 0xfe, 0xdf, 0x0b, 0x71,
//                           0x87, 0x89, 0x38, 0xd5, 0x1d, 0x71, 0xf8, 0x72,
//                           0x9e, 0x0a, 0xcb, 0x8c, 0x2c, 0x6d, 0xf8, 0xb3,
//                           0xd7, 0x9e, 0x8a, 0x4b, 0x90, 0x94, 0x9e, 0xe0];
//         let ybytes = vec![0x2a, 0x27, 0x44, 0xc9, 0x72, 0xc9, 0xfc, 0xe7,
//                           0x87, 0x01, 0x4a, 0x96, 0x4a, 0x8e, 0xa0, 0xc8,
//                           0x4d, 0x71, 0x4f, 0xea, 0xa4, 0xde, 0x82, 0x3f,
//                           0xe8, 0x5a, 0x22, 0x4a, 0x4d, 0xd0, 0x48, 0xfa];
//         let x = SCN::from(UCN::from_bytes(&xbytes));
//         let y = SCN::from(UCN::from_bytes(&ybytes));
//         let base = ECCPoint::default(&EllipticCurve::p256());
//         let res = base.scale(&UCN::from(9 as u64));
//         let goal = ECCPoint{ curve: base.curve,
//                              value: ECCPointValue::Point(x,y) };
//         assert_eq!(res, goal);
//     }
// }
