use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};

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
                let mut base = $name::new();
                base.values[0] = x as u64;
                base.values[1] = (x >> 64) as u64;
                base
            }
        }

    }
}

macro_rules! generate_basetype_from
{
    ($name: ident, $basetype: ident) => {
        impl From<$basetype> for $name {
            fn from(x: $basetype) -> $name {
                let mut base = $name::new();
                base.values[0] = x as u64;
                base
            }
        }
    }
}

macro_rules! convert_from_smaller
{
    ($name: ident, $smalltype: ident) => {
        impl From<$smalltype> for $name {
            fn from(x: $smalltype) -> $name {
                let mut base = $name::new();
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
        impl From<$bigtype> for $name {
            fn from(x: $bigtype) -> $name {
                let mut base = $name::new();
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
    ($bigger: ident, $smaller: ident) => {
        convert_from_smaller!($bigger, $smaller);
        convert_from_larger!($smaller, $bigger);
    }
}

generate_basetype_froms!(U192);
generate_basetype_froms!(U256);
generate_basetype_froms!(U384);
generate_basetype_froms!(U512);
generate_basetype_froms!(U576);
generate_basetype_froms!(U1024);
generate_basetype_froms!(U2048);
generate_basetype_froms!(U3072);
generate_basetype_froms!(U4096);
generate_basetype_froms!(U8192);
generate_basetype_froms!(U15360);

convert_bignums!(U256,   U192);
convert_bignums!(U384,   U192);
convert_bignums!(U512,   U192);
convert_bignums!(U576,   U192);
convert_bignums!(U1024,  U192);
convert_bignums!(U2048,  U192);
convert_bignums!(U3072,  U192);
convert_bignums!(U4096,  U192);
convert_bignums!(U8192,  U192);
convert_bignums!(U15360, U192);

convert_bignums!(U384,   U256);
convert_bignums!(U512,   U256);
convert_bignums!(U576,   U256);
convert_bignums!(U1024,  U256);
convert_bignums!(U2048,  U256);
convert_bignums!(U3072,  U256);
convert_bignums!(U4096,  U256);
convert_bignums!(U8192,  U256);
convert_bignums!(U15360, U256);

convert_bignums!(U512,   U384);
convert_bignums!(U576,   U384);
convert_bignums!(U1024,  U384);
convert_bignums!(U2048,  U384);
convert_bignums!(U3072,  U384);
convert_bignums!(U4096,  U384);
convert_bignums!(U8192,  U384);
convert_bignums!(U15360, U384);

convert_bignums!(U576,   U512);
convert_bignums!(U1024,  U512);
convert_bignums!(U2048,  U512);
convert_bignums!(U3072,  U512);
convert_bignums!(U4096,  U512);
convert_bignums!(U8192,  U512);
convert_bignums!(U15360, U512);

convert_bignums!(U1024,  U576);
convert_bignums!(U2048,  U576);
convert_bignums!(U3072,  U576);
convert_bignums!(U4096,  U576);
convert_bignums!(U8192,  U576);
convert_bignums!(U15360, U576);

convert_bignums!(U2048,  U1024);
convert_bignums!(U3072,  U1024);
convert_bignums!(U4096,  U1024);
convert_bignums!(U8192,  U1024);
convert_bignums!(U15360, U1024);

convert_bignums!(U3072,  U2048);
convert_bignums!(U4096,  U2048);
convert_bignums!(U8192,  U2048);
convert_bignums!(U15360, U2048);

convert_bignums!(U4096,  U3072);
convert_bignums!(U8192,  U3072);
convert_bignums!(U15360, U3072);

convert_bignums!(U8192,  U4096);
convert_bignums!(U15360, U4096);

convert_bignums!(U15360, U8192);