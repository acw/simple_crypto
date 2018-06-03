use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use std::ops::{Mul,MulAssign};

// This is algorithm 14.12 from "Handbook of Applied Cryptography"
fn raw_multiplication(x: &[u64], y: &[u64], w: &mut [u64])
{
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len() * 2, w.len());

    // clear out the destination array, because we're going to use it as a
    // temporary
    for i in 0..w.len() {
        w[i] = 0;
    }

    for i in 0..y.len() { // this may legitimately be off by one
        let mut carry = 0;
        for j in 0..x.len() { // ditto
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

#[cfg(test)]
use cryptonum::Decoder;
#[cfg(test)]
use testing::run_test;

macro_rules! generate_tests {
    ($name: ident, $testname: ident) => (
        #[test]
        #[allow(non_snake_case)]
        fn $testname() {
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
    );

    ($name: ident, $testname: ident, $dblname: ident, $doubletest: ident) => (
        generate_tests!($name, $testname);
        #[test]
        #[allow(non_snake_case)]
        fn $doubletest() {
            let fname = format!("tests/math/expandingmul{}.test",
                                stringify!($name));
            run_test(fname.to_string(), 3, |case| {
                let (neg0, abytes) = case.get("a").unwrap();
                let (neg1, bbytes) = case.get("b").unwrap();
                let (neg2, cbytes) = case.get("c").unwrap();

                assert!(!neg0 && !neg1 && !neg2);
                let a = $name::from_bytes(abytes);
                let b = $name::from_bytes(bbytes);
                let c = $dblname::from_bytes(cbytes);
                let mut r = $dblname::new();
                raw_multiplication(&a.values, &b.values, &mut r.values);
                assert_eq!(c, r);
            });
        }
    )
}

generate_tests!(U192,u192,U384,expandingU384);
generate_tests!(U256,u256,U512,expandingU512);
generate_tests!(U384,u384);
generate_tests!(U512,u512,U1024,expandingU1024);
generate_tests!(U576,u576);
generate_tests!(U1024,u1024,U2048,expandingU2048);
generate_tests!(U2048,u2048,U4096,expandingU4096);
generate_tests!(U3072,u3072);
generate_tests!(U4096,u4096,U8192,expandingU8192);
generate_tests!(U8192,u8192);
generate_tests!(U15360,u15360);