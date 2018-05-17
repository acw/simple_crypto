use cryptonum::{SCN,UCN};
use ecdsa::curves::EllipticCurve;

#[allow(non_snake_case)]
#[derive(Clone,Debug,PartialEq)]
pub struct ECCPoint {
    pub curve: EllipticCurve,
    pub x: SCN,
    pub y: SCN
}

impl ECCPoint {
    pub fn default(ec: &EllipticCurve) -> ECCPoint {
        ECCPoint {
            curve: ec.clone(),
            x: ec.Gx.clone(),
            y: ec.Gy.clone()
        }
    }

    pub fn double(&self) -> ECCPoint {
        let ua = SCN::from(self.curve.a.clone());
        let up = SCN::from(self.curve.p.clone());
        // lambda = (3 * xp ^ 2 + a) / 2 yp
        let xpsq = &self.x * &self.x;
        let lambda_top = &(&SCN::from(3) * &xpsq) + &ua;
        let lambda_bot = &self.y << 1;
        let lambda = lambda_top.divmod(&lambda_bot, &self.curve.p);
        // xr = lambda ^ 2 - 2 xp
        let xr_left = &lambda * &lambda;
        let xr_right = &self.x << 1;
        let xr = (xr_left - xr_right) % &up;
        // yr = lambda (xp - xr) - yp
        let xdiff = &self.x - &xr;
        let yr_left = &lambda * &xdiff;
        let yr = (&yr_left - &self.y) % &up;
        //
        ECCPoint{ curve: self.curve.clone(), x: xr, y: yr }
    }

    pub fn add(&self, other: &ECCPoint) -> ECCPoint {
        assert!(self.curve == other.curve);
        let xdiff = &self.x - &other.x;
        let ydiff = &self.y - &other.y;
        let s = ydiff.divmod(&xdiff, &self.curve.p);
        let pp = SCN::from(self.curve.p.clone());
        let xr = (&(&s * &s) - &self.x - &other.x) % &pp;
        let yr = (&s * (&self.x - &xr) - &self.y) % &pp;
        ECCPoint{ curve: self.curve.clone(), x: xr, y: yr }
    }

    pub fn scale(&self, d: &UCN) -> ECCPoint {
        assert!(!d.is_zero());
        let one = UCN::from(1u64);
        #[allow(non_snake_case)]
        let mut Q = self.clone();
        let i = d.bits() - 2;
        let mut mask = &one << i;

        while !mask.is_zero() {
            Q = Q.double();

            let test = d & &mask;
            if !test.is_zero() {
                Q = Q.add(&self);
            }
            mask >>= 1;
        }

        Q
    }
}

pub fn bits2int(x: &[u8], qlen: usize) -> UCN {
    let mut value = UCN::from_bytes(x);
    let vlen = x.len() * 8;

    if vlen > qlen {
        value >>= vlen - qlen;
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_double() {
        let xbytes = vec![0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
                          0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
                          0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
                          0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78];
        let ybytes = vec![0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40,
                          0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
                          0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29,
                          0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1];
        let x = SCN::from(UCN::from_bytes(&xbytes));
        let y = SCN::from(UCN::from_bytes(&ybytes));
        let base = ECCPoint::default(&EllipticCurve::p256());
        let res = base.double();
        let goal = ECCPoint{ curve: base.curve.clone(), x: x, y: y };
        assert_eq!(res, goal);
    }

    #[test]
    fn p256_add() {
        let xbytes = vec![0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a, 0x44,
                          0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1, 0x65,
                          0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9, 0x85,
                          0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7, 0xfd, 0x6c];
        let ybytes = vec![0x87, 0x34, 0x64, 0x0c, 0x49, 0x98, 0xff, 0x7e,
                          0x37, 0x4b, 0x06, 0xce, 0x1a, 0x64, 0xa2, 0xec,
                          0xd8, 0x2a, 0xb0, 0x36, 0x38, 0x4f, 0xb8, 0x3d,
                          0x9a, 0x79, 0xb1, 0x27, 0xa2, 0x7d, 0x50, 0x32];
        let x = SCN::from(UCN::from_bytes(&xbytes));
        let y = SCN::from(UCN::from_bytes(&ybytes));
        let base = ECCPoint::default(&EllipticCurve::p256());
        let res = base.add(&base.double());
        let goal = ECCPoint{ curve: base.curve.clone(), x: x, y: y };
        assert_eq!(res, goal);
    }

    #[test]
    fn p256_scale() {
        let xbytes = vec![0xea, 0x68, 0xd7, 0xb6, 0xfe, 0xdf, 0x0b, 0x71,
                          0x87, 0x89, 0x38, 0xd5, 0x1d, 0x71, 0xf8, 0x72,
                          0x9e, 0x0a, 0xcb, 0x8c, 0x2c, 0x6d, 0xf8, 0xb3,
                          0xd7, 0x9e, 0x8a, 0x4b, 0x90, 0x94, 0x9e, 0xe0];
        let ybytes = vec![0x2a, 0x27, 0x44, 0xc9, 0x72, 0xc9, 0xfc, 0xe7,
                          0x87, 0x01, 0x4a, 0x96, 0x4a, 0x8e, 0xa0, 0xc8,
                          0x4d, 0x71, 0x4f, 0xea, 0xa4, 0xde, 0x82, 0x3f,
                          0xe8, 0x5a, 0x22, 0x4a, 0x4d, 0xd0, 0x48, 0xfa];
        let x = SCN::from(UCN::from_bytes(&xbytes));
        let y = SCN::from(UCN::from_bytes(&ybytes));
        let base = ECCPoint::default(&EllipticCurve::p256());
        let res = base.scale(&UCN::from(9 as u64));
        let goal = ECCPoint{ curve: base.curve.clone(), x: x, y: y };
        assert_eq!(res, goal);
    }
}
