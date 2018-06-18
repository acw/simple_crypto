use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::addition::{ModAdd,raw_addition};
use cryptonum::comparison::{bignum_cmp,bignum_ge};
use cryptonum::division::divmod;
use cryptonum::exponentiation::ModExp;
use cryptonum::multiplication::{ModMul,raw_multiplication};
use cryptonum::squaring::{ModSquare,raw_square};
use cryptonum::subtraction::raw_subtraction;
use std::cmp::{Ordering,min};
use std::fmt;

macro_rules! generate_barrett_implementations {
    ($bname: ident, $name: ident, $size: expr) => {
        pub struct $bname {
            pub(crate) k:  usize,
            pub(crate) m:  [u64; $size/32],
            pub(crate) mu: [u64; $size/32]
        }

        impl fmt::Debug for $bname {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, stringify!($bname))?;
                write!(f, "{{ ")?;
                for x in self.mu.iter() {
                    write!(f, "{:X} ", *x)?;
                }
                write!(f, "}} ")
            }
        }

        impl PartialEq for $bname {
            fn eq(&self, rhs: &$bname) -> bool {
                for (left, right) in rhs.mu.iter().zip(rhs.mu.iter()) {
                    if *left != *right {
                        return false;
                    }
                }
                true
            }
        }

        impl $bname {
            pub fn new(m: &$name) -> $bname {
                let mut b      = [0; ($size/32) + 1];
                let mut widerm = [0; ($size/32) + 1];
                let mut quot   = [0; ($size/32) + 1];
                let mut remndr = [0; ($size/32) + 1];
                let mut result = $bname{ k: 0,
                                         m: [0; $size/32],
                                         mu: [0; $size/32] };

                for (idx, val) in m.values.iter().enumerate() {
                    let x = *val;
                    widerm[idx] = x;
                    result.m[idx] = x;
                    if x != 0 { result.k = idx; }
                }
                result.k += 1;
                b[result.k*2] = 1;
                divmod(&b, &widerm, &mut quot, &mut remndr);
                for (idx, val) in result.mu.iter_mut().enumerate() { *val = quot[idx]; }
                result
            }

            pub fn reduce(&self, x: &mut $name) {
                assert!(self.reduce_ok(&x));
                // 1. q1←⌊x/bk−1⌋, q2←q1 · μ, q3←⌊q2/bk+1⌋.
                let mut q1 = [0; $size/32];
                shiftr(&x.values, self.k - 1, &mut q1);
                let mut q2 = [0; $size/16];
                raw_multiplication(&q1, &self.mu, &mut q2);
                let mut q3 = [0; $size/16];
                shiftr(&q2, self.k + 1,&mut q3);
                // 2. r1←x mod bk+1, r2←q3 · m mod bk+1, r←r1 − r2.
                let mut r = [0; $size/16];
                let copylen = min(self.k+1, x.values.len());
                for i in 0..copylen { r[i] = x.values[i]; }
                let mut r2big = [0; $size/8];
                let mut mwider = [0; $size/16];
                for i in 0..$size/32 { mwider[i] = self.m[i]; }
                raw_multiplication(&q3, &mwider, &mut r2big);
                let mut r2 = [0; $size/16];
                for i in 0..self.k+1 { r2[i] = r2big[i]; }
                let went_negative = !bignum_ge(&r, &r2);
                raw_subtraction(&mut r, &r2);
                // 3. If r<0 then r←r+bk+1.
                if went_negative {
                    let mut bk1 = [0; $size/32];
                    bk1[self.k+1] = 1;
                    raw_addition(&mut r, &bk1);
                }
                // 4. While r≥m do: r←r−m.
                while bignum_cmp(&r, &mwider) == Ordering::Greater {
                    raw_subtraction(&mut r, &mwider);
                }
                // Copy it over.
                for (idx, val) in x.values.iter_mut().enumerate() {
                    *val = r[idx];
                }
            }

            pub fn reduce_ok(&self, x: &$name) -> bool {
                for i in self.k*2 .. x.values.len() {
                    if x.values[i] != 0 {
                        return false
                    }
                }
                true
            }
        }

        impl ModAdd<$bname> for $name {
            fn modadd(&mut self, y: &$name, m: &$bname) {
                let carry = raw_addition(&mut self.values, &y.values);
                let msized = &m.m[0..$size/64];
                if carry > 0 {
                    let mut left = [0; $size/64 + 1];
                    (&mut left[0..$size/64]).copy_from_slice(&self.values);
                    left[$size/64] = carry;
                    let mut right = [0; $size/64 + 1];
                    (&mut right[0..$size/64]).copy_from_slice(msized);
                    raw_subtraction(&mut left, &right);
                    for i in 0..self.values.len() {
                        self.values[i] = left[i];
                    }
                }
                if bignum_ge(&self.values, msized) {
                    raw_subtraction(&mut self.values, msized);
                }
            }
        }

        impl ModMul<$bname> for $name {
            fn modmul(&mut self, x: &$name, m: &$bname) {
                let mut mulres = [0; $size/32];
                raw_multiplication(&self.values, &x.values, &mut mulres);
                // 1. q1←⌊x/bk−1⌋, q2←q1 · μ, q3←⌊q2/bk+1⌋.
                let mut q1 = [0; $size/32];
                shiftr(&mulres, m.k - 1, &mut q1);
                let mut q2 = [0; $size/16];
                raw_multiplication(&q1, &m.mu, &mut q2);
                let mut q3 = [0; $size/16];
                shiftr(&q2, m.k + 1, &mut q3);
                // 2. r1←x mod bk+1, r2←q3 · m mod bk+1, r←r1 − r2.
                let mut r = [0; $size/16];
                let copylen = min(m.k + 1, mulres.len());
                for i in 0..copylen { r[i] = mulres[i]; }
                let mut r2big = [0; $size/8];
                let mut mwider = [0; $size/16];
                for i in 0..$size/32 { mwider[i] = m.m[i]; }
                raw_multiplication(&q3, &mwider, &mut r2big);
                let mut r2 = [0; $size/16];
                for i in 0..m.k+1 { r2[i] = r2big[i]; }
                let went_negative = !bignum_ge(&r, &r2);
                raw_subtraction(&mut r, &r2);
                // 3. If r<0 then r←r+bk+1.
                if went_negative {
                    let mut bk1 = [0; $size/32];
                    bk1[m.k + 1] = 1;
                    raw_addition(&mut r, &bk1);
                }
                // 4. While r≥m do: r←r−m.
                while bignum_cmp(&r, &mwider) == Ordering::Greater {
                    raw_subtraction(&mut r, &mwider);
                }
                // Copy it over.
                for (idx, val) in self.values.iter_mut().enumerate() {
                    *val = r[idx];
                }
            }
        }

        impl ModSquare<$bname> for $name {
            fn modsq(&mut self, m: &$bname) {
                let mut sqres = [0; $size/32];
                raw_square(&self.values, &mut sqres);
                // 1. q1←⌊x/bk−1⌋, q2←q1 · μ, q3←⌊q2/bk+1⌋.
                let mut q1 = [0; $size/32];
                shiftr(&sqres, m.k - 1, &mut q1);
                let mut q2 = [0; $size/16];
                raw_multiplication(&q1, &m.mu, &mut q2);
                let mut q3 = [0; $size/16];
                shiftr(&q2, m.k + 1, &mut q3);
                // 2. r1←x mod bk+1, r2←q3 · m mod bk+1, r←r1 − r2.
                let mut r = [0; $size/16];
                let copylen = min(m.k + 1, sqres.len());
                for i in 0..copylen { r[i] = sqres[i]; }
                let mut r2big = [0; $size/8];
                let mut mwider = [0; $size/16];
                for i in 0..$size/32 { mwider[i] = m.m[i]; }
                raw_multiplication(&q3, &mwider, &mut r2big);
                let mut r2 = [0; $size/16];
                for i in 0..m.k+1 { r2[i] = r2big[i]; }
                let went_negative = !bignum_ge(&r, &r2);
                raw_subtraction(&mut r, &r2);
                // 3. If r<0 then r←r+bk+1.
                if went_negative {
                    let mut bk1 = [0; $size/32];
                    bk1[m.k + 1] = 1;
                    raw_addition(&mut r, &bk1);
                }
                // 4. While r≥m do: r←r−m.
                while bignum_cmp(&r, &mwider) == Ordering::Greater {
                    raw_subtraction(&mut r, &mwider);
                }
                // Copy it over.
                for (idx, val) in self.values.iter_mut().enumerate() {
                    *val = r[idx];
                }
            }
        }

        impl ModExp<$bname> for $name {
            fn modexp(&mut self, e: &$name, m: &$bname) {
                // S <- g
                let mut s = self.clone();
                m.reduce(&mut s);
                // A <- 1
                for val in self.values.iter_mut() { *val = 0; }
                self.values[0] = 1;
                // We do a quick skim through and find the highest index that
                // actually has a value in it.
                let mut highest_digit = 0;
                for (idx, val) in e.values.iter().enumerate() {
                    if *val != 0 {
                        highest_digit = idx;
                    }
                }
                // While e != 0 do the following:
                //   If e is odd then A <- A * S
                //   e <- floor(e / 2)
                //   If e != 0 then S <- S * S
                for i in 0..highest_digit+1 {
                    let mut mask = 1;

                    while mask != 0 {
                        if e.values[i] & mask != 0 {
                            self.modmul(&s, m);
                        }
                        mask <<= 1;
                        s.modsq(m);
                    }
                }
                // Return A
            }
        }
    };
}

fn shiftr(x: &[u64], amt: usize, dest: &mut [u64])
{
    for i in amt..x.len() {
        dest[i-amt] = x[i];
    }
}


generate_barrett_implementations!(BarrettU192,   U192,  192);
generate_barrett_implementations!(BarrettU256,   U256,  256);
generate_barrett_implementations!(BarrettU384,   U384,  384);
generate_barrett_implementations!(BarrettU512,   U512,  512);
generate_barrett_implementations!(BarrettU576,   U576,  576);
generate_barrett_implementations!(BarrettU1024,  U1024, 1024);
generate_barrett_implementations!(BarrettU2048,  U2048, 2048);
generate_barrett_implementations!(BarrettU3072,  U3072, 3072);
generate_barrett_implementations!(BarrettU4096,  U4096, 4096);
generate_barrett_implementations!(BarrettU8192,  U8192, 8192);
generate_barrett_implementations!(BarrettU15360, U15360,15360);

macro_rules! generate_tests {
    ( $( ($bname: ident, $name:ident, $size:expr) ),* ) => {
        #[cfg(test)]
        mod generation {
            use cryptonum::encoding::{Decoder,raw_decoder};
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/barrett_gen{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, mbytes) = case.get("m").unwrap();
                        let (neg1, ubytes) = case.get("u").unwrap();
                        let (neg2, kbytes) = case.get("k").unwrap();

                        assert!(!neg0 && !neg1 && !neg2);
                        let m = $name::from_bytes(mbytes);
                        let mut kbig = [0; 1];
                        raw_decoder(&kbytes, &mut kbig);
                        let mut u = $bname{ k: kbig[0] as usize,
                                            m: [0; $size/32],
                                            mu: [0; $size/32]};
                        raw_decoder(&mbytes, &mut u.m);
                        raw_decoder(&ubytes, &mut u.mu);
                        let r = $bname::new(&m);
                        assert_eq!(u,r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod reduction {
            use cryptonum::encoding::{Decoder,raw_decoder};
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/barrett_reduce{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 5, |case| {
                        let (neg0, mbytes) = case.get("m").unwrap();
                        let (neg1, ubytes) = case.get("u").unwrap();
                        let (neg2, kbytes) = case.get("k").unwrap();
                        let (neg3, xbytes) = case.get("x").unwrap();
                        let (neg4, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4);
                        let mut kbig = [0; 1];
                        raw_decoder(&kbytes, &mut kbig);
                        let mut u = $bname{ k: kbig[0] as usize,
                                            m: [0; $size/32],
                                            mu: [0; $size/32]};
                        raw_decoder(&mbytes, &mut u.m);
                        raw_decoder(&ubytes, &mut u.mu);
                        let mut x = $name::from_bytes(&xbytes);
                        let r = $name::from_bytes(&rbytes);
                        u.reduce(&mut x);
                        assert_eq!(x, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod modadd {
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
                        let m = $name::from_bytes(mbytes);
                        let mu = $bname::new(&m);
                        let c = $name::from_bytes(cbytes);
                        a.modadd(&b, &mu);
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod modmul {
            use cryptonum::encoding::Decoder;
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
                        let (neg2, cbytes) = case.get("c").unwrap();
                        let (neg3, mbytes) = case.get("m").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let m = $name::from_bytes(mbytes);
                        let mu = $bname::new(&m);
                        let c = $name::from_bytes(cbytes);
                        a.modmul(&b, &mu);
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod modexp {
            use cryptonum::encoding::{Decoder,raw_decoder};
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/bmodexp{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 6, |case| {
                        let (neg0, bbytes) = case.get("b").unwrap();
                        let (neg1, ebytes) = case.get("e").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, kbytes) = case.get("k").unwrap();
                        let (neg4, ubytes) = case.get("u").unwrap();
                        let (neg5, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 &&
                                !neg3 && !neg4 && !neg5);
                        let mut b = $name::from_bytes(bbytes);
                        let e = $name::from_bytes(ebytes);
                        let mut kbig = [0; 1];
                        raw_decoder(&kbytes, &mut kbig);
                        let mut u = $bname{ k: kbig[0] as usize,
                                            m: [0; $size/32],
                                            mu: [0; $size/32] };
                        raw_decoder(&mbytes, &mut u.m);
                        raw_decoder(&ubytes, &mut u.mu);
                        let r = $name::from_bytes(rbytes);
                        b.modexp(&e, &u);
                        assert_eq!(b, r);
                    });
                }
            )*
        }
    }
}

generate_tests!((BarrettU192,   U192,   192),
                (BarrettU256,   U256,   256),
                (BarrettU384,   U384,   384),
                (BarrettU512,   U512,   512),
                (BarrettU576,   U576,   576),
                (BarrettU1024,  U1024,  1024),
                (BarrettU2048,  U2048,  2048),
                (BarrettU3072,  U3072,  3072),
                (BarrettU4096,  U4096,  4096),
                (BarrettU8192,  U8192,  8192),
                (BarrettU15360, U15360, 15360));
