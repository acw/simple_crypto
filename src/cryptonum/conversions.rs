use cryptonum::basetypes::*;
use cryptonum::encoding::Encoder;
use num::bigint::BigUint;
use num::{FromPrimitive,ToPrimitive};

macro_rules! generate_basetype_froms
{
    ($name: ident) => {
        generate_basetype_from!($name,    u8);
        generate_basetype_from!($name,   u16);
        generate_basetype_from!($name,   u32);
        generate_basetype_from!($name,   u64);
        generate_basetype_from!($name, usize);

        impl From<u128> for $name {
            fn from(x: u128) -> $name {
                let mut base = $name::zero();
                base.values[0] = x as u64;
                base.values[1] = (x >> 64) as u64;
                base
            }
        }

        impl From<BigUint> for $name {
            fn from(mut x: BigUint) -> $name {
                let mut res = $name::zero();
                let mask = BigUint::from_u64(0xFFFFFFFFFFFFFFFF).unwrap();

                for digit in res.values.iter_mut() {
                    *digit = (&x & &mask).to_u64().unwrap();
                    x >>= 64;
                }

                res
            }
        }

        impl From<$name> for BigUint {
            fn from(x: $name) -> BigUint {
                let bytes: Vec<u8> = x.to_bytes();
                BigUint::from_bytes_be(&bytes)
            }
        }
    }
}

macro_rules! generate_basetype_from
{
    ($name: ident, $basetype: ident) => {
        impl From<$basetype> for $name {
            fn from(x: $basetype) -> $name {
                let mut base = $name::zero();
                base.values[0] = x as u64;
                base
            }
        }

        impl From<$name> for $basetype {
            fn from(x: $name) -> $basetype {
                x.values[0] as $basetype
            }
        }
    }
}

macro_rules! convert_from_smaller
{
    ($name: ident, $smalltype: ident) => {
        impl<'a> From<&'a $smalltype> for $name {
            fn from(x: &$smalltype) -> $name {
                let mut base = $name::zero();
                for (idx, val) in x.values.iter().enumerate() {
                    base.values[idx] = *val;
                }
                base
            }
        }

        impl From<$smalltype> for $name {
            fn from(x: $smalltype) -> $name {
                let mut base = $name::zero();
                for (idx, val) in x.values.iter().enumerate() {
                    base.values[idx] = *val;
                }
                base
            }
        }
    }
}

macro_rules! convert_from_larger
{
    ($name: ident, $bigtype: ident) => {
        impl<'a> From<&'a $bigtype> for $name {
            fn from(x: &$bigtype) -> $name {
                let mut base = $name::zero();
                for i in 0..base.values.len() {
                    base.values[i] = x.values[i];
                }
                base
            }
        }
    }
}

macro_rules! convert_bignums
{
    ($smaller: ident, $bigger: ident) => {
        convert_from_smaller!($bigger, $smaller);
        convert_from_larger!($smaller, $bigger);
    }
}

macro_rules! expand_bignums
{
    ($smaller: ident, $bigger: ident $(, $rest: ident)* ) => {
        convert_bignums!($smaller, $bigger);
        expand_bignums!($smaller, $($rest),*);
    };
    ($smaller: ident, $(,)*) => {};
    () => {}
}

macro_rules! exhaustive_expansion
{
    () => {};
    ($last: ident) => {
        generate_basetype_froms!($last);
    };
    ($smallest: ident $(, $other: ident)*) => {
        generate_basetype_froms!($smallest);
        expand_bignums!($smallest, $($other),*);
        exhaustive_expansion!($($other),*);
    };
}

exhaustive_expansion!(U192,   U256,   U320,   U384,   U448,   U512,   U576,
                      U640,   U768,   U832,   U896,   U1024,  U1088,  U1152,
                      U1216,  U1536,  U1664,  U2048,  U2112,  U2176,  U2304,
                      U2432,  U3072,  U3136,  U4096,  U4224,  U4160,  U6144,
                      U6208,  U7680,  U7744,  U8192,  U8256,  U8320,  U12288,
                      U12416, U15360, U15424, U16384, U16448, U16512, U30720,
                      U30784, U32768, U32896, U61440, U61568);
