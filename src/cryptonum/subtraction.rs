use cryptonum::basetypes::*;
use std::ops::{Sub,SubAssign};

macro_rules! generate_subbers
{
    ($name: ident, $size: expr) => {
        impl<'a> SubAssign<&'a $name> for $name {
            fn sub_assign(&mut self, rhs: &$name) {
                // negate the right hand size
                let mut negatedy: $name = rhs.clone();
                for i in 0..$size/64 {
                    negatedy.values[i] = !negatedy.values[i];
                }
                // add one
                let mut bigger = 1 + (negatedy.values[0] as u128);
                let mut carry  = bigger >> 64;
                negatedy.values[0] = bigger as u64;
                for i in 1..$size/64 {
                    bigger = carry + (negatedy.values[i] as u128);
                    negatedy.values[i] = bigger as u64;
                    carry = bigger >> 64;
                }
                // then add it to ourselves
                carry = 0;
                for i in 0..$size/64 {
                    let x128 = self.values[i] as u128;
                    let y128 = negatedy.values[i] as u128;
                    bigger = x128 + y128 + carry;
                    carry = bigger >> 64;
                    self.values[i] = bigger as u64;
                }
            }
        }

        impl SubAssign for $name {
            fn sub_assign(&mut self, rhs: $name) {
                self.sub_assign(&rhs);
            }
        }

        impl<'a,'b> Sub<&'b $name> for &'a $name {
            type Output = $name;

            fn sub(self, rhs: &$name) -> $name {
                let mut res = self.clone();
                res -= rhs;
                res
            }
        }

        impl Sub for $name {
            type Output = $name;

            fn sub(mut self, rhs: $name) -> $name {
                self -= rhs;
                self
            }
        }
    }
}

generate_subbers!(U192,     192);
generate_subbers!(U256,     256);
generate_subbers!(U320,     320); // this is just for expansion
generate_subbers!(U384,     384);
generate_subbers!(U448,     448); // this is just for expansion
generate_subbers!(U512,     512);
generate_subbers!(U576,     576);
generate_subbers!(U640,     640); // this is just for expansion
generate_subbers!(U768,     768); // this is just for expansion
generate_subbers!(U832,     832); // this is just for Barrett
generate_subbers!(U896,     896); // this is just for Barrett
generate_subbers!(U1024,   1024);
generate_subbers!(U1088,   1088); // this is just for expansion
generate_subbers!(U1152,   1152); // this is just for expansion
generate_subbers!(U1216,   1216); // this is just for Barrett
generate_subbers!(U1536,   1536); // this is just for expansion
generate_subbers!(U1664,   1664); // this is just for Barrett
generate_subbers!(U2048,   2048);
generate_subbers!(U2112,   2112); // this is just for expansion
generate_subbers!(U2176,   2176); // this is just for Barrett
generate_subbers!(U2304,   2304); // this is just for expansion
generate_subbers!(U2432,   2432); // this is just for Barrett
generate_subbers!(U3072,   3072);
generate_subbers!(U3136,   3136); // this is just for expansion
generate_subbers!(U4096,   4096);
generate_subbers!(U4160,   4160); // this is just for expansion
generate_subbers!(U4224,   4224); // this is just for Barrett
generate_subbers!(U6144,   6144); // this is just for expansion
generate_subbers!(U6208,   6208); // this is just for Barrett
generate_subbers!(U7680,   7680);
generate_subbers!(U8192,   8192);
generate_subbers!(U8256,   8256); // this is just for expansion
generate_subbers!(U8320,   8320); // this is just for Barrett
generate_subbers!(U12288, 12288); // this is just for expansion
generate_subbers!(U12416, 12416); // this is just for Barrett
generate_subbers!(U15360, 15360);
generate_subbers!(U15424, 15424); // this is just for expansion
generate_subbers!(U16384, 16384); // this is just for expansion
generate_subbers!(U16448, 16448); // this is just for Barrett
generate_subbers!(U16512, 16512); // this is just for Barrett
generate_subbers!(U30720, 30720); // this is just for expansion
generate_subbers!(U30784, 30784); // this is just for Barrett
generate_subbers!(U32768, 32768); // this is just for expansion
generate_subbers!(U32896, 32896); // this is just for Barrett
generate_subbers!(U61440, 61440); // this is just for expansion
generate_subbers!(U61568, 61568); // this is just for Barrett

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
                        a -= &b;
                        assert_eq!(a, c);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360);
