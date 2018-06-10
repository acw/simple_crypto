use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::comparison::bignum_ge;
use cryptonum::subtraction::raw_subtraction;
use std::ops::{Add,AddAssign};

pub fn raw_addition(x: &mut [u64], y: &[u64]) -> u64 {
    assert_eq!(x.len(), y.len());

    let     xiter = x.iter_mut();
    let     yiter = y.iter();
    let mut carry = 0;

    for (x, y) in xiter.zip(yiter) {
        let bigger = (*x as u128) + (*y as u128) + carry;
        carry      = bigger >> 64;
        *x         = bigger as u64;
    }

    carry as u64
}

pub trait ModAdd<T=Self> {
    fn modadd(&mut self, y: &Self, m: &T);
}

macro_rules! generate_adders
{
    ($name: ident) => {
        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: $name) {
                raw_addition(&mut self.values, &rhs.values);
            }
        }
        impl<'a> AddAssign<&'a $name> for $name {
            fn add_assign(&mut self, rhs: &$name) {
                raw_addition(&mut self.values, &rhs.values);
            }
        }
        impl Add for $name {
            type Output = $name;

            fn add(self, other: $name) -> $name {
                let mut result = $name{ values: self.values };
                result.add_assign(other);
                result
            }
        }
        impl<'a> Add<&'a $name> for $name {
            type Output = $name;

            fn add(self, other: &$name) -> $name {
                let mut result = $name{ values: self.values };
                result.add_assign(other);
                result
            }
        }
        impl<'a,'b> Add<&'a $name> for &'b $name {
            type Output = $name;

            fn add(self, other: &$name) -> $name {
                let mut result = $name{ values: self.values };
                result.add_assign(other);
                result
            }
        }
        impl ModAdd for $name {
            fn modadd(&mut self, y: &$name, m: &$name) {
                let carry = raw_addition(&mut self.values, &y.values);
                if carry > 0 {
                    let mut left = Vec::with_capacity(self.values.len() + 1);
                    for x in self.values.iter() { left.push(*x) }
                    left.push(carry);
                    let mut right = Vec::with_capacity(self.values.len() + 1);
                    for x in m.values.iter() { right.push(*x) }
                    right.push(0);
                    raw_subtraction(&mut left, &right);
                    for i in 0..self.values.len() {
                        self.values[i] = left[i];
                    }
                }
                if bignum_ge(&self.values, &m.values) {
                    raw_subtraction(&mut self.values, &m.values);
                }
            }
        }
    }
}

generate_adders!(U192);
generate_adders!(U256);
generate_adders!(U384);
generate_adders!(U512);
generate_adders!(U576);
generate_adders!(U1024);
generate_adders!(U2048);
generate_adders!(U3072);
generate_adders!(U4096);
generate_adders!(U8192);
generate_adders!(U15360);

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
                    let fname = format!("tests/math/addition{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, cbytes) = case.get("c").unwrap();
        
                        assert!(!neg0 && !neg1 && !neg2);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let c = $name::from_bytes(cbytes);
                        assert_eq!(&a + &b, c);
                        a += b;
                        assert_eq!(a, c);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod slow_modular {
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
                        let c = $name::from_bytes(cbytes);
                        a.modadd(&b, &m);
                        assert_eq!(a, c);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048, U3072, U4096, U8192, U15360);