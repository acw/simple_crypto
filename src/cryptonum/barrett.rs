use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::addition::raw_addition;
use cryptonum::comparison::{bignum_cmp,bignum_ge};
use cryptonum::division::divmod;
use cryptonum::multiplication::raw_multiplication;
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
                printvar("x", &x.values);
                printvar("m", &self.m);
                printvar("u", &self.mu);
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
        }
    };
}

fn printvar(name: &'static str, val: &[u64]) {
    print!("{}: 0x", name);
    for x in val.iter().rev() {
        print!("{:016X}", *x);
    }
    println!("");
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