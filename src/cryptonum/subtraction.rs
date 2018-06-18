use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::addition::raw_addition;
use std::ops::{Sub,SubAssign};

#[inline(always)]
pub fn raw_subtraction(x: &mut [u64], y: &[u64])
{
    assert_eq!(x.len(), y.len());

    let mut negatedy = Vec::with_capacity(y.len());
    for val in y.iter() {
        negatedy.push(!*val);
    }

    let mut one = Vec::with_capacity(y.len());
    one.resize(y.len(), 0);
    one[0] = 1;

    raw_addition(&mut negatedy, &one);
    raw_addition(x, &negatedy);
} 

macro_rules! generate_subbers
{
    ($name: ident) => {
        impl SubAssign for $name {
            fn sub_assign(&mut self, rhs: $name) {
                raw_subtraction(&mut self.values, &rhs.values);
            }
        }
        impl<'a> SubAssign<&'a $name> for $name {
            fn sub_assign(&mut self, rhs: &$name) {
                raw_subtraction(&mut self.values, &rhs.values);
            }
        }
        impl Sub for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> $name {
                let mut result = $name{ values: self.values };
                raw_subtraction(&mut result.values, &rhs.values);
                result
            }
        }
        impl<'a> Sub<&'a $name> for $name {
            type Output = $name;

            fn sub(self, rhs: &$name) -> $name {
                let mut result = $name{ values: self.values };
                raw_subtraction(&mut result.values, &rhs.values);
                result
            }
        }
        impl<'a,'b> Sub<&'a $name> for &'b $name {
            type Output = $name;

            fn sub(self, rhs: &$name) -> $name {
                let mut result = (*self).clone();
                raw_subtraction(&mut result.values, &rhs.values);
                result
            }
        }
    }
}

generate_subbers!(U192);
generate_subbers!(U256);
generate_subbers!(U384);
generate_subbers!(U512);
generate_subbers!(U576);
generate_subbers!(U1024);
generate_subbers!(U2048);
generate_subbers!(U3072);
generate_subbers!(U4096);
generate_subbers!(U8192);
generate_subbers!(U15360);

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
                    let fname = format!("tests/math/subtraction{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, cbytes) = case.get("c").unwrap();
        
                        assert!(!neg0 && !neg1 && !neg2);
                        let mut a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let c = $name::from_bytes(cbytes);
                        assert_eq!(&a - &b, c);
                        a -= b;
                        assert_eq!(a, c);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048, U3072, U4096, U8192, U15360);