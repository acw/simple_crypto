use cryptonum::basetypes::*;
use std::ops::Mul;

macro_rules! generate_multipliers
{
    ($name: ident, $bigger: ident, $size: expr) => {
        impl<'a,'b> Mul<&'a $name> for &'b $name {
            type Output = $bigger;

            fn mul(self, rhs: &$name) -> $bigger {
                let mut w = $bigger::zero();
                let len = $size/64;

                for i in 0..len {
                    let mut carry = 0;
                    for j in 0..len {
                        let old = w.values[i+j] as u128;
                        let x128 = self.values[j] as u128;
                        let y128 = rhs.values[i] as u128;
                        let uv = old + (x128 * y128) + carry;
                        w.values[i+j] = uv as u64;
                        carry = uv >> 64;
                    }
                    w.values[i+len] = carry as u64;
                }

                w
            }
        }
    }
}

generate_multipliers!(U192,   U384,     192);
generate_multipliers!(U256,   U512,     256);
generate_multipliers!(U384,   U768,     384);
generate_multipliers!(U448,   U896,     448);
generate_multipliers!(U512,   U1024,    512);
generate_multipliers!(U576,   U1152,    576);
generate_multipliers!(U768,   U1536,    768);
generate_multipliers!(U832,   U1664,    832);
generate_multipliers!(U1024,  U2048,   1024);
generate_multipliers!(U1088,  U2176,   1088);
generate_multipliers!(U1152,  U2304,   1152);
generate_multipliers!(U1216,  U2432,   1216);
generate_multipliers!(U1536,  U3072,   1536);
generate_multipliers!(U2048,  U4096,   2048);
generate_multipliers!(U2112,  U4224,   2112);
generate_multipliers!(U3072,  U6144,   3072);
generate_multipliers!(U4096,  U8192,   4096);
generate_multipliers!(U4160,  U8320,   4160);
generate_multipliers!(U6144,  U12288,  6144);
generate_multipliers!(U6208,  U12416,  6208);
generate_multipliers!(U7680,  U15360,  7680);
generate_multipliers!(U8192,  U16384,  8192);
generate_multipliers!(U8256,  U16512,  8256);
generate_multipliers!(U15360, U30720, 15360);
generate_multipliers!(U16384, U32768, 16384);
generate_multipliers!(U16448, U32896, 16448);
generate_multipliers!(U30720, U61440, 30720);
generate_multipliers!(U30784, U61568, 30784);

macro_rules! generate_tests {
    ( $( ($name:ident, $bigger:ident) ),* ) => {
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
                        let a = $name::from_bytes(abytes);
                        let b = $name::from_bytes(bbytes);
                        let c = $bigger::from_bytes(cbytes);
                        assert_eq!(&a * &b, c);
                    });
                }
            )*
        }

    }
}

generate_tests!((U192,   U384),
                (U256,   U512),
                (U384,   U768),
                (U512,   U1024),
                (U576,   U1152),
                (U1024,  U2048),
                (U2048,  U4096),
                (U3072,  U6144),
                (U4096,  U8192),
                (U8192,  U16384),
                (U15360, U30720));
