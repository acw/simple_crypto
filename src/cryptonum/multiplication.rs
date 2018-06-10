use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::division::divmod;
use std::ops::{Mul,MulAssign};

pub trait ModMul<T=Self> {
    fn modmul(&mut self, x: &Self, m: &T);
}

// This is algorithm 14.12 from "Handbook of Applied Cryptography"
pub fn raw_multiplication(x: &[u64], y: &[u64], w: &mut [u64])
{
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len() * 2, w.len());

    // clear out the destination array, because we're going to use it as a
    // temporary
    for i in 0..w.len() {
        w[i] = 0;
    }

    for i in 0..y.len() {
        let mut carry = 0;
        for j in 0..x.len() {
            let old = w[i+j] as u128;
            let x128 = x[j] as u128;
            let y128 = y[i] as u128;
            let uv = old + (x128 * y128) + carry;
            w[i+j] = uv as u64;
            carry = uv >> 64;
        }
        w[i+x.len()] = carry as u64;
    }
}

macro_rules! generate_multipliers
{
    ($name: ident, $size: expr) => {
        impl MulAssign for $name {
            fn mul_assign(&mut self, rhs: $name) {
                let mut result = [0; $size/32];
                raw_multiplication(&self.values, &rhs.values, &mut result);
                for i in 0..self.values.len() {
                    self.values[i] = result[i];
                }
            }
        }
        impl<'a> MulAssign<&'a $name> for $name {
            fn mul_assign(&mut self, rhs: &$name) {
                let mut result = [0; $size/32];
                raw_multiplication(&self.values, &rhs.values, &mut result);
                for i in 0..self.values.len() {
                    self.values[i] = result[i];
                }
            }
        }
        impl Mul for $name {
            type Output = $name;

            fn mul(self, rhs: $name) -> $name {
                let mut result = self.clone();
                result.mul_assign(rhs);
                result
            }
        }
        impl<'a> Mul<&'a $name> for $name {
            type Output = $name;

            fn mul(self, rhs: &$name) -> $name {
                let mut result = self.clone();
                result.mul_assign(rhs);
                result
            }
        }
        impl<'a,'b> Mul<&'a $name> for &'b $name {
            type Output = $name;

            fn mul(self, rhs: &$name) -> $name {
                let mut result = self.clone();
                result.mul_assign(rhs);
                result
            }
        }

        impl ModMul for $name {
            fn modmul(&mut self, x: &$name, m: &$name) {
                let mut mulres = Vec::with_capacity(2 * self.values.len());
                mulres.resize(2 * self.values.len(), 0);
                raw_multiplication(&self.values, &x.values, &mut mulres);
                let mut widerm = Vec::with_capacity(mulres.len());
                widerm.extend_from_slice(&m.values);
                widerm.resize(mulres.len(), 0);
                let mut dead   = Vec::with_capacity(widerm.len());
                dead.resize(widerm.len(), 0);
                let mut answer = Vec::with_capacity(widerm.len());
                answer.resize(widerm.len(), 0);
                divmod(&mulres, &widerm, &mut dead, &mut answer);
                for i in 0..answer.len() {
                    if i < self.values.len() {
                        self.values[i] = answer[i];
                    } else {
                        assert_eq!(answer[i], 0);
                    }
                }
            }
        }
    }
}

generate_multipliers!(U192,     192);
generate_multipliers!(U256,     256);
generate_multipliers!(U384,     384);
generate_multipliers!(U512,     512);
generate_multipliers!(U576,     576);
generate_multipliers!(U1024,   1024);
generate_multipliers!(U2048,   2048);
generate_multipliers!(U3072,   3072);
generate_multipliers!(U4096,   4096);
generate_multipliers!(U8192,   8192);
generate_multipliers!(U15360, 15360);

macro_rules! generate_tests {
    ( $( $name:ident ),* ) => {
        #[cfg(test)]
        mod normal {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/multiplication{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, cbytes) = case.get("c").unwrap();

                        assert!(!neg0 && !neg1 && !neg2);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let c = $name::from_bytes(cbytes);
                        assert_eq!(&a * &b, c);
                        a *= b;
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod expanding {
            use cryptonum::encoding::{Decoder,raw_decoder};
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/expandingmul{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, cbytes) = case.get("c").unwrap();

                        assert!(!neg0 && !neg1 && !neg2);
                        let a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let mut c = Vec::with_capacity(a.values.len() * 2);
                        c.resize(a.values.len() * 2, 0);
                        raw_decoder(&cbytes, &mut c);
                        let mut r = Vec::with_capacity(c.len());
                        r.resize(c.len(), 0);
                        raw_multiplication(&a.values, &b.values, &mut r);
                        assert_eq!(c, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod slow_modular {
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
    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048, U3072, U4096, U8192, U15360);