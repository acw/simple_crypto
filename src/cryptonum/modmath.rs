use cryptonum::addition::UnsafeAdd;
use cryptonum::basetypes::*;
use cryptonum::barrett::*;
use cryptonum::signed::*;

pub trait ModAdd<T2> {
    fn modadd(&mut self, y: &Self, m: &T2);
}

pub trait ModMul<T> {
    fn modmul(&mut self, x: &Self, m: &T);
}

pub trait ModSquare<T> {
    fn modsq(&mut self, m: &T);
}

pub trait ModExp<T> {
    fn modexp(&self, e: &Self, m: &T) -> Self;
}

pub trait ModInv
 where Self: Sized
{
    fn modinv(&self, phi: Self) -> Option<Self>;
}

macro_rules! generate_modmath_funs
{
    ($name: ident, $big: ident, $dbl: ident, $bar: ident, $size: expr) => {
        impl ModAdd<$big> for $name {
            fn modadd(&mut self, y: &$name, m: &$big) {
                let mut base = &self.clone() + y;
                if &base > m {
                    base -= m;
                    if &base > m {
                        base -= m;
                    }
                }
                self.values.copy_from_slice(&base.values[0..$size/64]);
            }
        }

        impl ModMul<$name> for $name {
            fn modmul(&mut self, x: &$name, m: &$name) {
                let mulres      = (self as &$name) * &x;
                let bigm        = $dbl::from(m);
                let (_, bigres) = mulres.divmod(&bigm);
                self.values.copy_from_slice(&bigres.values[0..$size/64]);
            }
        }

        impl ModMul<$bar> for $name {
            fn modmul(&mut self, x: &$name, m: &$bar) {
                let mut mulres = (self as &$name) * &x;
                let     bigres = m.reduce(&mut mulres);
                self.values.copy_from_slice(&bigres.values[0..$size/64]);
            }
         }

        impl ModSquare<$name> for $name {
            fn modsq(&mut self, m: &$name) {
                let bigsquare = self.square();
                let bigm      = $dbl::from(m);
                let (_, res)  = bigsquare.divmod(&bigm);
                self.values.copy_from_slice(&res.values[0..$size/64]);
            }
        }

        impl ModSquare<$bar> for $name {
            fn modsq(&mut self, m: &$bar) {
                let bigsquare = self.square();
                let bigres    = m.reduce(&bigsquare);
                self.values.copy_from_slice(&bigres.values[0..$size/64]);
            }
        }

        impl<T> ModExp<T> for $name
            where $name: ModMul<T> + ModSquare<T>
        {
            #[inline]
            fn modexp(&self, ine: &$name, m: &T) -> $name {
                // S <- g
                let mut s = self.clone();
                // A <- 1
                let mut a = $name::from(1u64);
                // We do a quick skim through and find the highest index that
                // actually has a value in it.
                let mut e = ine.clone();
                // While e != 0 do the following:
                while e.values.iter().any(|x| *x != 0) {
                    // If e is odd then A <- A * S
                    if e.values[0] & 1 != 0 {
                        a.modmul(&s, m);
                    }
                    // e <- floor(e / 2)
                    let mut carry = 0;
                    e.values.iter_mut().rev().for_each(|x| {
                        let new_carry = *x & 1;
                        *x = (*x >> 1) | (carry << 63);
                        carry = new_carry;
                    });
                    // If e != 0 then S <- S * S
                    s.modsq(m);
                }
                // Return A
                a
            }
        }

        impl ModInv for $name {
            fn modinv(&self, phi: $name)
                -> Option<$name>
            {
                let (_, _d, v) = self.egcd(phi);

                if v != Signed::new(false, $name::from(1u64)) {
                    return None;
                }

                panic!("modinv stuff")
            }
        }

        impl $name {
            fn egcd(&self, rhs: $name)
                -> (Signed<$name>, Signed<$name>, Signed<$name>)
            {
                println!("---------------------------------------------------");
                // INPUT: two positive integers x and y.
                let mut x = Signed::new(false, self.clone());
                let mut y = Signed::new(false, rhs);
                // OUTPUT: integers a, b, and v such that ax + by = v,
                //         where v = gcd(x, y).
                // 1. g←1.
                let mut gshift = 0;
                // 2. While x and y are both even, do the following: x←x/2,
                //    y←y/2, g←2g.
                while x.is_even() && y.is_even() {
                    x >>= 1;
                    y >>= 1;
                    gshift += 1;
                }
                // 3. u←x, v←y, A←1, B←0, C←0, D←1.
                let mut u: Signed<$name> = x.clone();
                let mut v: Signed<$name> = y.clone();
                #[allow(non_snake_case)]
                let mut A: Signed<$name> = Signed::new(false, $name::from(1u64));
                #[allow(non_snake_case)]
                let mut B: Signed<$name> = Signed::new(false, $name::zero());
                #[allow(non_snake_case)]
                let mut C: Signed<$name> = Signed::new(false, $name::zero());
                #[allow(non_snake_case)]
                let mut D: Signed<$name> = Signed::new(false, $name::from(1u64));
                loop {
                    println!("START");
                    println!("u:    {}{:X}", pos_space(&u), u);
                    println!("v:    {}{:X}", pos_space(&v), v);
                    println!("A:    {}{:X}", pos_space(&A), A);
                    println!("B:    {}{:X}", pos_space(&B), B);
                    println!("C:    {}{:X}", pos_space(&C), C);
                    println!("D:    {}{:X}", pos_space(&D), D);
                    // 4. While u is even do the following:
                    while u.is_even() {
                        // 4.1 u←u/2.
                        u >>= 1;
                        // 4.2 If A≡B≡0 (mod 2) then A←A/2, B←B/2; otherwise,
                        //     A←(A + y)/2, B←(B − x)/2.
                        if A.is_even() && B.is_even() {
                            A >>= 1;
                            B >>= 1;
                        } else {
                            let mut big_A: Signed<$big> = &A + &y;
                            big_A >>= 1;
                            A = Signed::new(big_A.negative, $name::from(&big_A.value));
                            B -= &x;
                            B >>= 1;
                        }
                    }
                    println!("AFTER 4");
                    println!("u:    {}{:X}", pos_space(&u), u);
                    println!("v:    {}{:X}", pos_space(&v), v);
                    println!("A:    {}{:X}", pos_space(&A), A);
                    println!("B:    {}{:X}", pos_space(&B), B);
                    println!("C:    {}{:X}", pos_space(&C), C);
                    println!("D:    {}{:X}", pos_space(&D), D);
                    // 5. While v is even do the following:
                    while v.is_even() {
                        // 5.1 v←v/2.
                        v >>= 1;
                        // 5.2 If C ≡ D ≡ 0 (mod 2) then C←C/2, D←D/2; otherwise,
                        //     C←(C + y)/2, D←(D − x)/2.
                        if C.is_even() && D.is_even() {
                            C >>= 1;
                            D >>= 1;
                        } else {
                            C = C.unsafe_add(&y);
                            C >>= 1;
                            D -= &x;
                            D >>= 1;
                        }
                    }
                    println!("AFTER 5");
                    println!("u:    {}{:X}", pos_space(&u), u);
                    println!("v:    {}{:X}", pos_space(&v), v);
                    println!("A:    {}{:X}", pos_space(&A), A);
                    println!("B:    {}{:X}", pos_space(&B), B);
                    println!("C:    {}{:X}", pos_space(&C), C);
                    println!("D:    {}{:X}", pos_space(&D), D);
                    // 6. If u≥v then u←u−v, A←A−C,B←B−D;
                    //       otherwise,v←v−u, C←C−A, D←D−B.
                    if u >= v {
                        u -= &v;
                        A -= &C;
                        B -= &D;
                    } else {
                        v -= &u;
                        C -= &A;
                        D -= &B;
                    }
                    // 7. If u = 0, then a←C, b←D, and return(a, b, g · v);
                    //        otherwise, go to step 4.
                    println!("AFTER 6");
                    println!("u:    {}{:X}", pos_space(&u), u);
                    println!("v:    {}{:X}", pos_space(&v), v);
                    println!("A':   {}{:X}", pos_space(&A), A);
                    println!("B':   {}{:X}", pos_space(&B), B);
                    println!("C':   {}{:X}", pos_space(&C), C);
                    println!("D':   {}{:X}", pos_space(&D), D);
                    if u.is_zero() {
                        return (C, D, v << gshift);
                    }
                }
            }
        }
    }
}

generate_modmath_funs!(U192,   U256,   U384,   BarrettU192,   192);
generate_modmath_funs!(U256,   U320,   U512,   BarrettU256,   256);
generate_modmath_funs!(U384,   U448,   U768,   BarrettU384,   384);
generate_modmath_funs!(U512,   U576,   U1024,  BarrettU512,   512);
generate_modmath_funs!(U1024,  U1088,  U2048,  BarrettU1024,  1024);
generate_modmath_funs!(U2048,  U2112,  U4096,  BarrettU2048,  2048);
generate_modmath_funs!(U3072,  U3136,  U6144,  BarrettU3072,  3072);
generate_modmath_funs!(U4096,  U4160,  U8192,  BarrettU4096,  4096);
generate_modmath_funs!(U8192,  U8256,  U16384, BarrettU8192,  8192);
generate_modmath_funs!(U15360, U15424, U30720, BarrettU15360, 15360);

macro_rules! generate_tests {
    ( $( ($name:ident, $barrett: ident, $bigger: ident, $dbl: ident) ),* ) => {
        #[cfg(test)]
        mod addition {
            use cryptonum::encoding::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modadd{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, cbytes) = case.get("c").unwrap();
                        let (neg3, mbytes) = case.get("m").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let m = $bigger::from_bytes(mbytes);
                        let c = $name::from_bytes(cbytes);
                        a.modadd(&b, &m);
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod multiplication {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modmul{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, cbytes) = case.get("c").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let m = $name::from_bytes(mbytes);
                        let c = $name::from_bytes(cbytes);
                        a.modmul(&b, &m);
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod barrett_multiplication {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/barrett_mul{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 6, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();
                        let (neg4, kbytes) = case.get("k").unwrap();
                        let (neg5, ubytes) = case.get("u").unwrap();

                        assert!(!neg0&&!neg1&&!neg2&&!neg3&&!neg4&&!neg5);
                        let mut a  = $name::from_bytes(abytes);
                        let     b  = $name::from_bytes(bbytes);
                        let     m  = $bigger::from_bytes(mbytes);
                        let     r  = $name::from_bytes(rbytes);
                        let     k  = $name::from_bytes(kbytes);
                        let     u  = $bigger::from_bytes(ubytes);
                        let     mu = $barrett{ k: k.values[0] as usize, m:m, mu:u };
                        a.modmul(&b, &mu);
                        assert_eq!(a, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod modsq {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modsq{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 5, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();

                        assert!(!neg0&&!neg2&&!neg3);
                        let mut a  = $name::from_bytes(abytes);
                        let     m  = $name::from_bytes(mbytes);
                        let     r  = $name::from_bytes(rbytes);
                        a.modsq(&m);
                        assert_eq!(a, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod barrett_squaring {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modsq{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 5, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();
                        let (neg4, kbytes) = case.get("k").unwrap();
                        let (neg5, ubytes) = case.get("u").unwrap();

                        assert!(!neg0&&!neg2&&!neg3&&!neg4&&!neg5);
                        let mut a  = $name::from_bytes(abytes);
                        let     m  = $bigger::from_bytes(mbytes);
                        let     r  = $name::from_bytes(rbytes);
                        let     k  = $name::from_bytes(kbytes);
                        let     u  = $bigger::from_bytes(ubytes);
                        let     mu = $barrett{ k: k.values[0] as usize, m:m, mu:u };
                        a.modsq(&mu);
                        assert_eq!(a, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod modexp {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                #[ignore]
                fn $name() {
                    let fname = format!("tests/math/modexp{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 6, |case| {
                        let (neg0, bbytes) = case.get("b").unwrap();
                        let (neg1, ebytes) = case.get("e").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();

                        assert!(!neg0&&!neg1&&!neg2&&!neg3);
                        let b  = $name::from_bytes(bbytes);
                        let e  = $name::from_bytes(ebytes);
                        let m  = $name::from_bytes(mbytes);
                        let r  = $name::from_bytes(rbytes);
                        let me = b.modexp(&e, &m);
                        assert_eq!(me, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod barrett_exponentiation {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modexp{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 6, |case| {
                        let (neg0, bbytes) = case.get("b").unwrap();
                        let (neg1, ebytes) = case.get("e").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();
                        let (neg4, kbytes) = case.get("k").unwrap();
                        let (neg5, ubytes) = case.get("u").unwrap();

                        assert!(!neg0&&!neg1&&!neg2&&!neg3&&!neg4&&!neg5);
                        let b  = $name::from_bytes(bbytes);
                        let e  = $name::from_bytes(ebytes);
                        let m  = $bigger::from_bytes(mbytes);
                        let r  = $name::from_bytes(rbytes);
                        let k  = $name::from_bytes(kbytes);
                        let u  = $bigger::from_bytes(ubytes);
                        let mu = $barrett{ k: k.values[0] as usize, m:m, mu:u };
                        let me = b.modexp(&e, &mu);
                        assert_eq!(me, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod egcd {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/egcd{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (nega, abytes) = case.get("a").unwrap();
                        let (negb, bbytes) = case.get("b").unwrap();
                        let (negg, gbytes) = case.get("g").unwrap();

                        assert!(!nega && !negb);
                        let a  = $name::from_bytes(abytes);
                        let b  = $name::from_bytes(bbytes);
                        let ug = $dbl::from_bytes(gbytes);
                        let g  = Signed::new(*negg, ug.clone());

                        let (mys, myt, myg) = a.egcd(b.clone());
                        let mybigg = Signed::new(g.negative, $dbl::from(&myg.value));
                        println!("mybigg: {}{:X}", pos_space(&mybigg), mybigg.value);
                        println!("g     : {}{:X}", pos_space(&g), g.value);
                        assert_eq!(mybigg, g);
                        let part1: $dbl = &mys.value * &a;
                        let part2: $dbl = &myt.value * &b;
                        let mut spart1 = Signed::new(mys.negative, part1);
                        let spart2 = Signed::new(myt.negative, part2);
                        spart1 -= &spart2;
                        println!("spart1: {}{:X}", pos_space(&spart1), spart1);
                        println!("spart1: {}{:X}", pos_space(&spart2), spart2);
                        assert_eq!(spart1, g);
                    });
                }
            )*
        }
    }
}

generate_tests!((U192,   BarrettU192,   U256,   U384),
                (U256,   BarrettU256,   U320,   U512),
                (U384,   BarrettU384,   U448,   U768),
                (U512,   BarrettU512,   U576,   U1024),
                (U1024,  BarrettU1024,  U1088,  U2048),
                (U2048,  BarrettU2048,  U2112,  U4096),
                (U3072,  BarrettU3072,  U3136,  U6144),
                (U4096,  BarrettU4096,  U4160,  U8192),
                (U8192,  BarrettU8192,  U8256,  U16384),
                (U15360, BarrettU15360, U15424, U30720));

//generate_tests!((U192,   I192,   BarrettU192,   U256),
//                (U256,   I256,   BarrettU256,   U320),
//                (U384,   I384,   BarrettU384,   U448),
//                (U512,   I512,   BarrettU512,   U576),
//                (U1024,  I1024,  BarrettU1024,  U1088),
//                (U2048,  I2048,  BarrettU2048,  U2112),
//                (U3072,  I3072,  BarrettU3072,  U3136),
//                (U4096,  I4096,  BarrettU4096,  U4160),
//                (U8192,  I8192,  BarrettU8192,  U8256),
//                (U15360, I15360, BarrettU15360, U15424));
fn pos_space<T>(x: &Signed<T>) -> &'static str {
    if !x.negative {
        return " ";
    }
    ""
}
