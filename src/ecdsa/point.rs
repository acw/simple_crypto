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

macro_rules! point_impl
{
    ($curve: ident, $base: ident,
     $s2: ident, $u2: ident,
     $s2p1: ident, $u2p1: ident) =>
     {
        impl Clone for Point<$curve> {
            fn clone(&self) -> Point<$curve> {
                Point {
                    x: self.x.clone(),
                    y: self.y.clone()
                }
            }
        }

        impl ECCPoint for Point<$curve> {
            type Curve = $curve;
            type Scale = $base;
        
            fn default() -> Point<$curve>
            {
                Point {
                    x: $curve::Gx(),
                    y: $curve::Gy()
                }
            }
        
            fn negate(&self) -> Point<$curve>
            {
                let mut newy = $base::new(false, $curve::p());
                newy -= &self.y;
                Point{ x: self.x.clone(), y: newy }
            }
        
            fn double(&self) -> Point<$curve>
            {
                let up = $curve::p();
                let bigp = $s2::new(false, $u2::from(&up));
                // lambda = (3 * xp ^ 2 + a) / 2 yp
                let xsquared = self.x.square();
                let mut lambda_top = &xsquared * 3u64;
                lambda_top += $s2p1::new(false, $u2p1::from($curve::a()));
                let mut lambda_bot = $s2p1::from(&self.y);
                lambda_bot <<= 1;
                let lambda = $base::from(lambda_top.moddiv(&lambda_bot, &$s2p1::from(&bigp)));
                // xr = lambda^2 - 2 xp
                let mut xr = lambda.square();
                let mut xr_right = $s2::from(&self.x);
                xr_right <<= 1;
                xr -= xr_right;
                xr %= &bigp;
                let x = $base::from(xr);
                // yr = lambda (xp - xr) - yp
                let xdiff = $base::from(&self.x - &x);
                let mut yr = &lambda * &xdiff;
                yr -= $s2::from(&self.y);
                let y = $base::from(&yr % &bigp);
                //
                Point{ x, y }
            }
        
            fn add(&self, other: &Point<$curve>) -> Point<$curve>
            {
                let mut xdiff = self.x.clone(); xdiff -= &other.x;
                let mut ydiff = self.y.clone(); ydiff -= &other.y;
                let signedp = $base::new(false, $curve::p());
                let s = ydiff.moddiv(&xdiff, &signedp);
                let mut xr = &s * &s;
                xr -= $s2::from(&self.x);
                xr -= $s2::from(&other.x);
                let bigsignedp = $s2::from(&signedp);
                xr %= &bigsignedp;
                let mut yr = $s2::from(&self.x);
                yr -= &xr;
                yr *= $s2::from(&s);
                yr -= $s2::from(&self.y);
                yr %= &bigsignedp;
                Point{ x: $base::from(xr), y: $base::from(yr) }
            }
        
            fn scale(&self, d: &$base) -> Point<$curve>
            {
                assert!(!d.is_zero());
                #[allow(non_snake_case)]
                let mut Q: Point<$curve> = self.clone();
                let mut bit = ($base::bit_length() - 1) as isize;
        
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
        
                if d.is_negative() {
                    Q.negate()
                } else {
                    Q
                }
            }
        }
    }
}

point_impl!(P192, I192, I384,  U384,  I448,  U448);
point_impl!(P224, I256, I512,  U512,  I576,  U576);
point_impl!(P256, I256, I512,  U512,  I576,  U576);
point_impl!(P384, I384, I768,  U768,  I832,  U832);
point_impl!(P521, I576, I1152, U1152, I1216, U1216);

macro_rules! point_tests
{
    ($curve: ident, $lcurve: ident, $stype: ident, $utype: ident) => {
        #[cfg(test)]
        mod $lcurve {
            use super::*;
            use testing::*;

            #[test]
            fn negate() {
                let fname = build_test_path("ecc/negate",stringify!($curve));
                run_test(fname.to_string(), 4, |case| {
                    let (negx, xbytes) = case.get("x").unwrap();
                    let (negy, ybytes) = case.get("y").unwrap();
                    let (nega, abytes) = case.get("a").unwrap();
                    let (negb, bbytes) = case.get("b").unwrap();

                    let x = $stype::new(*negx, $utype::from_bytes(xbytes));
                    let y = $stype::new(*negy, $utype::from_bytes(ybytes));
                    let a = $stype::new(*nega, $utype::from_bytes(abytes));
                    let b = $stype::new(*negb, $utype::from_bytes(bbytes));
                    let point = Point::<$curve>{ x, y };
                    let dbl = point.negate();
                    assert_eq!(a, dbl.x, "x equivalence");
                    assert_eq!(b, dbl.y, "y equivalence");
                });
            }

            #[test]
            fn double() {
                let fname = build_test_path("ecc/double",stringify!($curve));
                run_test(fname.to_string(), 4, |case| {
                    let (negx, xbytes) = case.get("x").unwrap();
                    let (negy, ybytes) = case.get("y").unwrap();
                    let (nega, abytes) = case.get("a").unwrap();
                    let (negb, bbytes) = case.get("b").unwrap();

                    let x = $stype::new(*negx, $utype::from_bytes(xbytes));
                    let y = $stype::new(*negy, $utype::from_bytes(ybytes));
                    let a = $stype::new(*nega, $utype::from_bytes(abytes));
                    let b = $stype::new(*negb, $utype::from_bytes(bbytes));
                    let point = Point::<$curve>{ x, y };
                    let dbl = point.double();
                    assert_eq!(a, dbl.x, "x equivalence");
                    assert_eq!(b, dbl.y, "y equivalence");
                });
            }

            #[test]
            fn add() {
                let fname = build_test_path("ecc/add",stringify!($curve));
                run_test(fname.to_string(), 6, move |case| {
                    let (negx, xbytes) = case.get("x").unwrap();
                    let (negy, ybytes) = case.get("y").unwrap();
                    let (negu, ubytes) = case.get("u").unwrap();
                    let (negv, vbytes) = case.get("v").unwrap();
                    let (nega, abytes) = case.get("a").unwrap();
                    let (negb, bbytes) = case.get("b").unwrap();

                    let x = $stype::new(*negx, $utype::from_bytes(xbytes));
                    let y = $stype::new(*negy, $utype::from_bytes(ybytes));
                    let u = $stype::new(*negu, $utype::from_bytes(ubytes));
                    let v = $stype::new(*negv, $utype::from_bytes(vbytes));
                    let a = $stype::new(*nega, $utype::from_bytes(abytes));
                    let b = $stype::new(*negb, $utype::from_bytes(bbytes));
                    let point1 = Point::<$curve>{ x: x, y: y };
                    let point2 = Point::<$curve>{ x: u, y: v };
                    let res = point1.add(&point2);
                    assert_eq!(a, res.x, "x equivalence");
                    assert_eq!(b, res.y, "y equivalence");
                });
            }

            #[test]
            fn scale() {
                let fname = build_test_path("ecc/scale",stringify!($curve));
                run_test(fname.to_string(), 5, |case| {
                    let (negx, xbytes) = case.get("x").unwrap();
                    let (negy, ybytes) = case.get("y").unwrap();
                    let (negk, kbytes) = case.get("k").unwrap();
                    let (nega, abytes) = case.get("a").unwrap();
                    let (negb, bbytes) = case.get("b").unwrap();

                    let x = $stype::new(*negx, $utype::from_bytes(xbytes));
                    let y = $stype::new(*negy, $utype::from_bytes(ybytes));
                    let k = $stype::new(*negk, $utype::from_bytes(kbytes));
                    let a = $stype::new(*nega, $utype::from_bytes(abytes));
                    let b = $stype::new(*negb, $utype::from_bytes(bbytes));
                    let point = Point::<$curve>{ x: x, y: y };
                    let res   = point.scale(&k);
                    assert_eq!(a, res.x, "x equivalence");
                    assert_eq!(b, res.y, "y equivalence");
                });
            }
        }
    }
}

point_tests!(P192, p192, I192, U192);
point_tests!(P224, p224, I256, U256);
point_tests!(P256, p256, I256, U256);
point_tests!(P384, p384, I384, U384);
point_tests!(P521, p521, I576, U576);