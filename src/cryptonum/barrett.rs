use cryptonum::addition::UnsafeAdd;
use cryptonum::basetypes::*;
use std::cmp::min;

macro_rules! generate_barretts {
    ($bname:ident,$name:ident,$big:ident,$bg2:ident,$dbl:ident,$size:expr) =>
    {
        #[derive(Debug,PartialEq)]
        pub struct $bname {
            pub(crate) k: usize,
            pub(crate) m: $big,
            pub(crate) mu: $big
        }

        impl $bname {
            pub fn new(m: &$name) -> $bname {
                // Step #1: Figure out k
                let mut k = 0;
                for i in 0..$size/64 {
                    if m.values[i] != 0 {
                        k = i;
                    }
                }
                k += 1;
                // Step #2: Compute b
                let mut b = $bg2::zero();
                b.values[2*k] = 1;
                // Step #3: Divide b by m.
                let bigm = $bg2::from(m);
                let (quot, _) = b.divmod(&bigm);
                let resm = $big::from(m);
                let mu = $big::from(&quot);
                // Done!
                $bname{ k: k, m: resm, mu: mu }
            }

            pub fn ok_for_reduce(&self, x: &$dbl) -> bool {
                for i in self.k*2 .. x.values.len() {
                    if x.values[i] != 0 {
                        return false
                    }
                }
                true
            }

            pub fn reduce(&self, x: &$dbl) -> $name {
                assert!(self.ok_for_reduce(x));
                let     m2: $bg2  = $bg2::from(&self.m);
                // 1. q1←⌊x/bk−1⌋, q2←q1 · μ, q3←⌊q2/bk+1⌋.
                let     q1: $big  = x.shiftr(self.k - 1);
                let     q2: $bg2  = q1.unsafe_mul(&self.mu);
                let     q3: $big  = q2.check_shiftr(self.k + 1);
                // 2. r1←x mod bk+1, r2←q3 · m mod bk+1, r←r1 − r2.
                let mut r:  $bg2  = x.mask(self.k + 1);
                let mut r2: $bg2  = q3.unsafe_mul(&self.m);
                r2.mask_inplace(self.k + 1);
                let went_negative = &r < &r2;
                r -= &r2;
                // 3. If r<0 then r←r+bk+1.
                if went_negative {
                    let mut bk1 = $bg2::zero();
                    bk1.values[self.k+1] = 1;
                    r = r.unsafe_add(&bk1);
                }
                // 4. While r≥m do: r←r−m.
                while &r > &m2 {
                    r -= &m2;
                }
                // Done!
                $name::from(&r)
            }
        }

        impl $dbl {
            fn shiftr(&self, x: usize) -> $big {
                let mut res = $big::zero();
                for i in 0..self.values.len()-x {
                    if i >= res.values.len() {
                        assert_eq!(self.values[i+x], 0);
                    } else {
                        res.values[i] = self.values[i+x];
                    }
                }
                res
            }

            fn mask(&self, len: usize) -> $bg2 {
                let mut res = $bg2::zero();
                let     copylen = min(len, self.values.len());
                for i in 0..copylen {
                    res.values[i] = self.values[i];
                }
                res
            }
        }

        impl $big {
            fn unsafe_mul(&self, rhs: &$big) -> $bg2 {
                let mut w = $bg2::zero();
                let len = rhs.values.len();

                for i in 0..len {
                    let mut carry = 0;
                    for j in 0..len {
                        if i+j >= w.values.len() {
                            continue;
                        }
                        let old = w.values[i+j] as u128;
                        let x128 = self.values[j] as u128;
                        let y128 = rhs.values[i] as u128;
                        let uv = old + (x128 * y128) + carry;
                        w.values[i+j] = uv as u64;
                        carry = uv >> 64;
                    }
                    if i+len < w.values.len() {
                        w.values[i+len] = carry as u64;
                    }
                }

                w
            }
        }

        impl $bg2 {
            fn check_shiftr(&self, x: usize) -> $big {
                let mut res = $big::zero();

                for i in 0..self.values.len()-x {
                    if i >= res.values.len() {
                        assert_eq!(self.values[i+x], 0);
                    } else {
                        res.values[i] = self.values[i+x];
                    }
                }
                res
            }

            fn mask_inplace(&mut self, len: usize) {
                let dellen = min(len, self.values.len());
                for i in dellen..self.values.len() {
                    self.values[i] = 0;
                }
            }
        }
    }
}

generate_barretts!(BarrettU192,   U192,   U256,   U448,   U384,     192);
generate_barretts!(BarrettU256,   U256,   U320,   U576,   U512,     256);
generate_barretts!(BarrettU384,   U384,   U448,   U832,   U768,     384);
generate_barretts!(BarrettU512,   U512,   U576,   U1088,  U1024,    512);
generate_barretts!(BarrettU576,   U576,   U640,   U1216,  U1152,    576);
generate_barretts!(BarrettU1024,  U1024,  U1088,  U2112,  U2048,   1024);
generate_barretts!(BarrettU2048,  U2048,  U2112,  U4160,  U4096,   2048);
generate_barretts!(BarrettU3072,  U3072,  U3136,  U6208,  U6144,   3072);
generate_barretts!(BarrettU4096,  U4096,  U4160,  U8256,  U8192,   4096);
generate_barretts!(BarrettU8192,  U8192,  U8256,  U16448, U16384,  8192);
generate_barretts!(BarrettU15360, U15360, U15424, U30784, U30720, 15360);

macro_rules! generate_tests {
    ( $( ($bname:ident,$name:ident,$big:ident,$dbl:ident,$size:expr) ),* ) => {
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
                        let u = $big::from_bytes(ubytes);
                        let mut kbig = [0; 1];
                        raw_decoder(&kbytes, &mut kbig);
                        let k = kbig[0] as usize;
                        let r = $bname::new(&m);
                        assert_eq!(k,r.k);
                        assert_eq!(u,r.mu);
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
                        let m = $big::from_bytes(mbytes);
                        let u = $big::from_bytes(ubytes);
                        let mut kbig = [0; 1];
                        raw_decoder(&kbytes, &mut kbig);
                        let k = kbig[0] as usize;
                        let x = $dbl::from_bytes(xbytes);
                        let r = $name::from_bytes(rbytes);
                        let bu = $bname{ k: k, m: m, mu: u };
                        let r2 = bu.reduce(&x);
                        assert_eq!(r, r2);
                    });
                }
            )*
        }
    }
}

generate_tests!((BarrettU192,   U192,   U256,   U384,   192),
                (BarrettU256,   U256,   U320,   U512,   256),
                (BarrettU384,   U384,   U448,   U768,   384),
                (BarrettU512,   U512,   U576,   U1024,  512),
                (BarrettU576,   U576,   U640,   U1152,  576),
                (BarrettU1024,  U1024,  U1088,  U2048,  1024),
                (BarrettU2048,  U2048,  U2112,  U4096,  2048),
                (BarrettU3072,  U3072,  U3136,  U6144,  3072),
                (BarrettU4096,  U4096,  U4160,  U8192,  4096),
                (BarrettU8192,  U8192,  U8256,  U16384, 8192),
                (BarrettU15360, U15360, U15424, U30720, 15360));
