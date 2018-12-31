use cryptonum::signed::*;
use cryptonum::unsigned::*;
use ecdsa::curve::*;

pub trait ECCPoint {
    type Curve: EllipticCurve;
    type Scale;

    fn default() -> Self;
    fn negate(&self) -> Self;
    fn double(&self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn scale(&self, amt: &Self::Scale) -> Self;
}

pub struct Point<T: EllipticCurve>
{
    pub x: T::Signed,
    pub y: T::Signed
}

impl Clone for Point<P192> {
    fn clone(&self) -> Point<P192> {
        Point {
            x: self.x.clone(),
            y: self.y.clone()
        }
    }
}

impl ECCPoint for Point<P192> {
    type Curve = P192;
    type Scale = U192;

    fn default() -> Point<P192>
    {
        Point {
            x: P192::Gx(),
            y: P192::Gy()
        }
    }

    fn negate(&self) -> Point<P192>
    {
        let mut newy = I192::new(false, P192::p());
        newy -= &self.y;
        Point{ x: self.x.clone(), y: newy }
    }

    fn double(&self) -> Point<P192>
    {
        let ua = P192::a();
        let up = P192::p();
        let bigp = I384::new(false, U384::from(&up));
        // lambda = (3 * xp ^ 2 + a) / 2 yp
        let mut lambda_top = I384::from(3i64) * (&self.x * &self.x);
        lambda_top += I768::new(false, U768::from(ua));
        let mut lambda_bot = I768::from(&self.y);
        lambda_bot <<= 1;
        let lambda = I192::from(lambda_top.moddiv(&lambda_bot, &I768::from(&bigp)));
        // xr = lambda^2 - 2 xp
        let mut xr = &lambda * &lambda;
        let mut xr_right = I384::from(&self.x);
        xr_right <<= 1;
        xr -= xr_right;
        xr %= &bigp;
        let x = I192::from(xr);
        // yr = lambda (xp - xr) - yp
        let xdiff = I192::from(&self.x - &x);
        let mut yr = &lambda * &xdiff;
        yr -= I384::from(&self.y);
        let y = I192::from(&yr % &bigp);
        //
        Point{ x, y }
    }

    fn add(&self, other: &Point<P192>) -> Point<P192>
    {
        let xdiff: I256 = &self.x - &other.x;
        let ydiff: I256 = &self.y - &other.y;
        let signedp = I256::from(U256::from(P192::p()));
        let s = ydiff.moddiv(&xdiff, &signedp);
        let mut xr = &s * &s;
        xr -= I512::from(&self.x);
        xr -= I512::from(&other.x);
        let bigsignedp = I512::from(&signedp);
        xr %= &bigsignedp;
        let mut yr = I512::from(&self.x);
        yr -= &xr;
        yr *= I512::from(&s);
        yr -= I512::from(&self.y);
        yr %= &bigsignedp;
        Point{ x: I192::from(xr), y: I192::from(yr) }
    }

    fn scale(&self, d: &U192) -> Point<P192>
    {
        assert!(!d.is_zero());
        #[allow(non_snake_case)]
        let mut Q: Point<P192> = self.clone();
        let mut bit = 191;

        // Skip down until we hit a set bit
        while !d.testbit(bit as usize) {
            bit -= 1;
        }
        // drop one
        bit -= 1;
        // do the double and add algorithm
        while bit >= 0 {
            Q = Q.double();

            let test = d.testbit(bit as usize);
            if test {
                Q = Q.add(&self);
            }
            
            bit -= 1;
        }

        Q
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::*;

    #[test]
    fn p192_negate() {
        let fname = build_test_path("ecc/negate","P192");
        run_test(fname.to_string(), 4, |case| {
            let (negx, xbytes) = case.get("x").unwrap();
            let (negy, ybytes) = case.get("y").unwrap();
            let (nega, abytes) = case.get("a").unwrap();
            let (negb, bbytes) = case.get("b").unwrap();

            let x = I192::new(*negx, U192::from_bytes(xbytes));
            let y = I192::new(*negy, U192::from_bytes(ybytes));
            let a = I192::new(*nega, U192::from_bytes(abytes));
            let b = I192::new(*negb, U192::from_bytes(bbytes));
            let point = Point{ x, y };
            let dbl = point.negate();
            assert_eq!(a, dbl.x, "x equivalence");
            assert_eq!(b, dbl.y, "y equivalence");
        });
    }

    #[test]
    fn p192_double() {
        let fname = build_test_path("ecc/double","P192");
        run_test(fname.to_string(), 4, |case| {
            let (negx, xbytes) = case.get("x").unwrap();
            let (negy, ybytes) = case.get("y").unwrap();
            let (nega, abytes) = case.get("a").unwrap();
            let (negb, bbytes) = case.get("b").unwrap();

            let x = I192::new(*negx, U192::from_bytes(xbytes));
            let y = I192::new(*negy, U192::from_bytes(ybytes));
            let a = I192::new(*nega, U192::from_bytes(abytes));
            let b = I192::new(*negb, U192::from_bytes(bbytes));
            let point = Point{ x, y };
            let dbl = point.double();
            assert_eq!(a, dbl.x, "x equivalence");
            assert_eq!(b, dbl.y, "y equivalence");
        });
    }

    #[test]
    fn p192_add() {
        let fname = build_test_path("ecc/add","P192");
        run_test(fname.to_string(), 6, move |case| {
            let (negx, xbytes) = case.get("x").unwrap();
            let (negy, ybytes) = case.get("y").unwrap();
            let (negu, ubytes) = case.get("u").unwrap();
            let (negv, vbytes) = case.get("v").unwrap();
            let (nega, abytes) = case.get("a").unwrap();
            let (negb, bbytes) = case.get("b").unwrap();

            let x = I192::new(*negx, U192::from_bytes(xbytes));
            let y = I192::new(*negy, U192::from_bytes(ybytes));
            let u = I192::new(*negu, U192::from_bytes(ubytes));
            let v = I192::new(*negv, U192::from_bytes(vbytes));
            let a = I192::new(*nega, U192::from_bytes(abytes));
            let b = I192::new(*negb, U192::from_bytes(bbytes));
            let point1 = Point{ x: x, y: y };
            let point2 = Point{ x: u, y: v };
            let res = point1.add(&point2);
            assert_eq!(a, res.x, "x equivalence");
            assert_eq!(b, res.y, "y equivalence");
        });
    }

    #[test]
    fn p192_scale() {
        let fname = build_test_path("ecc/scale","P192");
        run_test(fname.to_string(), 5, |case| {
            let (negx, xbytes) = case.get("x").unwrap();
            let (negy, ybytes) = case.get("y").unwrap();
            let (negk, kbytes) = case.get("k").unwrap();
            let (nega, abytes) = case.get("a").unwrap();
            let (negb, bbytes) = case.get("b").unwrap();

            let x = I192::new(*negx, U192::from_bytes(xbytes));
            let y = I192::new(*negy, U192::from_bytes(ybytes));
            let k = U192::from_bytes(kbytes);
            let a = I192::new(*nega, U192::from_bytes(abytes));
            let b = I192::new(*negb, U192::from_bytes(bbytes));
            let point = Point{ x: x, y: y };
            let res   = point.scale(&k);
            assert_eq!(a, res.x, "x equivalence");
            assert_eq!(b, res.y, "y equivalence");
        });
    }
}