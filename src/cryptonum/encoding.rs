use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};

pub trait Decoder {
    fn from_bytes(x: &[u8]) -> Self;
}

pub(crate) fn raw_decoder(input: &[u8], output: &mut [u64])
{
    let mut item = 0;
    let mut shift = 0;
    let mut idx = 0;

    for v in input.iter().rev() {
        item |= (*v as u64) << shift;
        shift += 8;
        if shift == 64 {
            shift = 0;
            output[idx] = item;
            idx += 1;
            item = 0;
        }
    }
    if item != 0 {
        output[idx] = item;
    }
}

macro_rules! generate_decoder {
    ($name: ident) => {
        impl Decoder for $name {
            fn from_bytes(x: &[u8]) -> $name {
                let mut res = $name::new();
                raw_decoder(x, &mut res.values);
                res
            }
        }
    }
}

generate_decoder!(U192);
generate_decoder!(U256);
generate_decoder!(U384);
generate_decoder!(U512);
generate_decoder!(U576);
generate_decoder!(U1024);
generate_decoder!(U2048);
generate_decoder!(U3072);
generate_decoder!(U4096);
generate_decoder!(U8192);
generate_decoder!(U15360);