use cryptonum::basetypes::*;
use std::ops::{Shl,ShrAssign};

macro_rules! generate_shifts
{
    ($num: ident, $size: expr) => {
        impl ShrAssign<usize> for $num {
            fn shr_assign(&mut self, amt: usize) {
                let digits = amt / 64;
                let bits   = amt % 64;

                let mut carry = 0;
                let mask = !(0xFFFFFFFFFFFFFFFF << bits);
                let copy = self.values.clone();
                let shift = (64 - bits) as u32;

                for (idx, val) in self.values.iter_mut().enumerate().rev() {
                    let target = idx + digits;
                    let base = if target >= ($size/64) { 0 } else { copy[target] };
                    let (new_carry, _) = (base & mask).overflowing_shl(shift);
                    *val = (base >> bits) | carry;
                    carry = new_carry;
                }
            }
        }

        impl Shl<usize> for $num {
            type Output = $num;

            fn shl(mut self, amt: usize) -> $num {
                let digits = amt / 64;
                let bits   = amt % 64;

                let mut carry = 0;
                let     copy  = self.values.clone();
                let     shift = 64 - bits;

                for (idx, val) in self.values.iter_mut().enumerate() {
                    let base = if idx >= digits { copy[idx - digits] } else { 0 };
                    let new_carry = if shift == 64 { 0 } else { base >> shift };
                    *val = (base << bits) | carry;
                    carry = new_carry;
                }

                self
            }
        }
    }
}

generate_shifts!(U192,     192);
generate_shifts!(U256,     256);
generate_shifts!(U320,     320); // this is just for expansion
generate_shifts!(U384,     384);
generate_shifts!(U448,     448); // this is just for expansion
generate_shifts!(U512,     512);
generate_shifts!(U576,     576);
generate_shifts!(U640,     640); // this is just for expansion
generate_shifts!(U768,     768); // this is just for expansion
generate_shifts!(U832,     832); // this is just for Barrett
generate_shifts!(U896,     896); // this is just for Barrett
generate_shifts!(U1024,   1024);
generate_shifts!(U1088,   1088); // this is just for expansion
generate_shifts!(U1152,   1152); // this is just for expansion
generate_shifts!(U1216,   1216); // this is just for Barrett
generate_shifts!(U1536,   1536); // this is just for expansion
generate_shifts!(U1664,   1664); // this is just for Barrett
generate_shifts!(U2048,   2048);
generate_shifts!(U2112,   2112); // this is just for expansion
generate_shifts!(U2176,   2176); // this is just for Barrett
generate_shifts!(U2304,   2304); // this is just for expansion
generate_shifts!(U2432,   2432); // this is just for Barrett
generate_shifts!(U3072,   3072);
generate_shifts!(U3136,   3136); // this is just for expansion
generate_shifts!(U4096,   4096);
generate_shifts!(U4160,   4160); // this is just for expansion
generate_shifts!(U4224,   4224); // this is just for Barrett
generate_shifts!(U6144,   6144); // this is just for expansion
generate_shifts!(U6208,   6208); // this is just for Barrett
generate_shifts!(U7680,   7680); // Useful for RSA key generation
generate_shifts!(U7744,   7744); // Addition on previous
generate_shifts!(U8192,   8192);
generate_shifts!(U8256,   8256); // this is just for expansion
generate_shifts!(U8320,   8320); // this is just for Barrett
generate_shifts!(U12288, 12288); // this is just for expansion
generate_shifts!(U12416, 12416); // this is just for Barrett
generate_shifts!(U15360, 15360);
generate_shifts!(U15424, 15424); // this is just for expansion
generate_shifts!(U16384, 16384); // this is just for expansion
generate_shifts!(U16448, 16448); // this is just for Barrett
generate_shifts!(U16512, 16512); // this is just for Barrett
generate_shifts!(U30720, 30720); // this is just for expansion
generate_shifts!(U30784, 30784); // this is just for Barrett
generate_shifts!(U32768, 32768); // this is just for expansion
generate_shifts!(U32896, 32896); // this is just for Barrett
generate_shifts!(U61440, 61440); // this is just for expansion
generate_shifts!(U61568, 61568); // this is just for Barrett

macro_rules! generate_tests {
    ( $( $name:ident ), * ) => {
        #[cfg(test)]
        mod left {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/shift{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg3, lbytes) = case.get("l").unwrap();
                        assert!(!neg0 && !neg1 && !neg3);
                        let a    = $name::from_bytes(abytes);
                        let bigb = $name::from_bytes(bbytes);
                        let b    = usize::from(bigb);
                        let l    = $name::from_bytes(lbytes);
                        let res  = a << b;
                        assert_eq!(res, l);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod right {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/shift{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, bbytes) = case.get("b").unwrap();
                        let (neg2, rbytes) = case.get("r").unwrap();
                        assert!(!neg0 && !neg1 && !neg2);
                        let mut a    = $name::from_bytes(abytes);
                        let     bigb = $name::from_bytes(bbytes);
                        let     b    = usize::from(bigb);
                        let     r    = $name::from_bytes(rbytes);
                        a >>= b;
                        assert_eq!(a, r);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048, U3072,
                U4096, U8192, U15360);
