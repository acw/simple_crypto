use cryptonum::basetypes::*;
use std::ops::Add;

pub trait UnsafeAdd {
    fn unsafe_add(self, other: &Self) -> Self;
}

macro_rules! generate_adders
{
    ($name: ident, $size: expr) => {
        impl UnsafeAdd for $name {
            fn unsafe_add(self, other: &$name) -> $name {
                let mut result = $name::zero();
                let mut carry = 0;

                for i in 0..$size/64 {
                    let x128 = self.values[i] as u128;
                    let y128 = other.values[i] as u128;
                    let bigger = x128 + y128 + carry;
                    carry = bigger >> 64;
                    result.values[i] = bigger as u64;
                }

                result
            }
        }

    };
    ($name: ident, $bigger: ident, $size: expr) => {
        generate_adders!($name, $size);

        impl<'a,'b> Add<&'a $name> for &'b $name {
            type Output = $bigger;

            fn add(self, other: &$name) -> $bigger {
                let mut result = $bigger::zero();
                let mut carry  = 0;

                for i in 0..$size/64 {
                    let x128 = self.values[i] as u128;
                    let y128 = other.values[i] as u128;
                    let bigger = x128 + y128 + carry;
                    carry = bigger >> 64;
                    result.values[i] = bigger as u64;
                }
                result.values[$size/64] = carry as u64;

                result
            }
        }

        impl Add<$name> for $name {
            type Output = $bigger;

            fn add(self, other: $name) -> $bigger {
                &self + &other
            }
        }
    }
}

generate_adders!(U192,   U256,   192);
generate_adders!(U256,   U320,   256);
generate_adders!(U384,   U448,   384);
generate_adders!(U512,   U576,   512);
generate_adders!(U576,   U640,   576);
generate_adders!(U1024,  U1088,  1024);
generate_adders!(U2048,  U2112,  2048);
generate_adders!(U3072,  U3136,  3072);
generate_adders!(U4096,  U4160,  4096);
generate_adders!(U7680,  U7744,  7680);
generate_adders!(U8192,  U8256,  8192);
generate_adders!(U15360, U15424, 15360);

generate_adders!(U320,    320);
generate_adders!(U448,    448);
generate_adders!(U768,    768);
generate_adders!(U832,    832);
generate_adders!(U1088,  1088);
generate_adders!(U1216,  1216);
generate_adders!(U2112,  2112);
generate_adders!(U3136,  3136);
generate_adders!(U4160,  4160);
generate_adders!(U6144,  6144);
generate_adders!(U6208,  6208);
generate_adders!(U8256,  8256);
generate_adders!(U15424, 15424);
generate_adders!(U16384, 16384);
generate_adders!(U16448, 16448);
generate_adders!(U30720, 30720);
generate_adders!(U30784, 30784);

macro_rules! generate_tests {
    ( $( ($name:ident, $bigger: ident) ),* ) => {
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
                        let a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let c = $bigger::from_bytes(cbytes);
                        assert_eq!(&a + &b, c);
                    });
                }
            )*
        }
    }
}

generate_tests!((U192,   U256),
                (U256,   U320),
                (U384,   U448),
                (U512,   U576),
                (U576,   U640),
                (U1024,  U1088),
                (U2048,  U2112),
                (U3072,  U3136),
                (U4096,  U4160),
                (U8192,  U8256),
                (U15360, U15424));
