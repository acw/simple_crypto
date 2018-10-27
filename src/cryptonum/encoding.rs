use cryptonum::basetypes::*;

pub trait Decoder {
    fn from_bytes(x: &[u8]) -> Self;
}

pub trait Encoder {
    fn to_bytes(&self) -> Vec<u8>;
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
                let mut res = $name::zero();
                raw_decoder(x, &mut res.values);
                res
            }
        }
    }
}

macro_rules! generate_encoder {
    ($name: ident) => {
        impl Encoder for $name {
            fn to_bytes(&self) -> Vec<u8> {
                let mut res = Vec::with_capacity(self.values.len() * 8);
                for v in self.values.iter().rev() {
                    let val = *v;
                    res.push( (val >> 56) as u8);
                    res.push( (val >> 48) as u8);
                    res.push( (val >> 40) as u8);
                    res.push( (val >> 32) as u8);
                    res.push( (val >> 24) as u8);
                    res.push( (val >> 16) as u8);
                    res.push( (val >>  8) as u8);
                    res.push( (val >>  0) as u8);
                }
                res
            }
        }
    }
}

macro_rules! generate_codec
{
    ($name: ident) => {
        generate_decoder!($name);
        generate_encoder!($name);
    }
}

generate_codec!(U192);
generate_codec!(U256);
generate_codec!(U320); // this is just for expansion
generate_codec!(U384);
generate_codec!(U448); // this is just for expansion
generate_codec!(U512);
generate_codec!(U576);
generate_codec!(U640); // this is just for expansion
generate_codec!(U768); // this is just for expansion
generate_codec!(U832); // this is just for expansion
generate_codec!(U896); // this is just for expansion
generate_codec!(U1024);
generate_codec!(U1088); // this is just for expansion
generate_codec!(U1152); // this is just for expansion
generate_codec!(U1216); // this is just for expansion
generate_codec!(U1536); // this is just for expansion
generate_codec!(U1664); // this is just for expansion
generate_codec!(U2048);
generate_codec!(U2112); // this is just for expansion
generate_codec!(U2176); // this is just for expansion
generate_codec!(U2304); // this is just for expansion
generate_codec!(U2432); // this is just for expansion
generate_codec!(U3072);
generate_codec!(U3136); // this is just for expansion
generate_codec!(U4224); // this is just for expansion
generate_codec!(U4096);
generate_codec!(U4160); // this is just for expansion
generate_codec!(U6144); // this is just for expansion
generate_codec!(U6208); // this is just for expansion
generate_codec!(U7680);
generate_codec!(U7744);
generate_codec!(U8192);
generate_codec!(U8256); // this is just for expansion
generate_codec!(U8320); // this is just for expansion
generate_codec!(U12288); // this is just for expansion
generate_codec!(U12416); // this is just for expansion
generate_codec!(U15360);
generate_codec!(U15424); // this is just for expansion
generate_codec!(U16384); // this is just for expansion
generate_codec!(U16448); // this is just for expansion
generate_codec!(U16512); // this is just for expansion
generate_codec!(U30720); // this is just for expansion
generate_codec!(U30784); // this is just for expansion
generate_codec!(U32768); // this is just for expansion
generate_codec!(U32896); // this is just for expansion
generate_codec!(U61440); // this is just for expansion
generate_codec!(U61568); // this is just for expansion

macro_rules! generate_tests
{
    ( $( ($name: ident, $num: ident, $size: expr) ),* ) => {
        $(
            #[cfg(test)]
            mod $name {
                use cryptonum::basetypes::{CryptoNum,$num};
                use cryptonum::encoding::{Decoder,Encoder};
                use quickcheck::{Arbitrary,Gen};

                #[derive(Clone,Debug)]
                struct MyBuffer {
                    x: Vec<u8>
                }

                impl Arbitrary for $num {
                    fn arbitrary<G: Gen>(g: &mut G) -> $num {
                        let mut res = $num::zero();

                        for v in res.values.iter_mut() {
                            *v = g.gen::<u64>();
                        }
                        res
                    }
                }

                impl Arbitrary for MyBuffer {
                    fn arbitrary<G: Gen>(g: &mut G) -> MyBuffer {
                        let     len = $size / 8;
                        let mut res = Vec::with_capacity(len);

                        for _ in 0..len {
                            res.push(g.gen::<u8>());
                        }
                        MyBuffer{ x: res }
                    }
                }

                quickcheck! {
                    fn i2o2i(x: $num) -> bool {
                        let bstr = x.to_bytes();
                        let x2   = $num::from_bytes(&bstr);
                        x == x2
                    }

                    fn o2i2o(x: MyBuffer) -> bool {
                        let val = $num::from_bytes(&x.x);
                        let x2  = val.to_bytes();
                        x.x == x2
                    }
                }
            }
        )*
    }
}

generate_tests!((u192,   U192,     192),
                (u256,   U256,     256),
                (u320,   U320,     320),  // this is just for expansion
                (u384,   U384,     384),
                (u448,   U448,     448),  // this is just for expansion
                (u512,   U512,     512),
                (u576,   U576,     576),
                (u640,   U640,     640),  // this is just for expansion
                (u768,   U768,     768),  // this is just for expansion
                (u832,   U832,     832),  // this is just for Barrett
                (u896,   U896,     896),  // this is just for Barrett
                (u1024,  U1024,   1024),
                (u1088,  U1088,   1088),  // this is just for expansion
                (u1152,  U1152,   1152),  // this is just for expansion
                (u1216,  U1216,   1216),  // this is just for Barrett
                (u1536,  U1536,   1536),  // this is just for expansion
                (u1664,  U1664,   1664),  // this is just for Barrett
                (u2048,  U2048,   2048),
                (u2112,  U2112,   2112),  // this is just for expansion
                (u2176,  U2176,   2176),  // this is just for Barrett
                (u2304,  U2304,   2304),  // this is just for expansion
                (u2432,  U2432,   2432),  // this is just for Barrett
                (u3072,  U3072,   3072),
                (u3136,  U3136,   3136),  // this is just for expansion
                (u4096,  U4096,   4096),
                (u4160,  U4160,   4160),  // this is just for expansion
                (u4224,  U4224,   4224),  // this is just for Barrett
                (u6144,  U6144,   6144),  // this is just for expansion
                (u6208,  U6208,   6208),  // this is just for Barrett
                (u7680,  U7680,   7680),
                (u7744,  U7744,   7744),
                (u8192,  U8192,   8192),
                (u8256,  U8256,   8256),  // this is just for expansion
                (u8320,  U8320,   8320),  // this is just for Barrett
                (u12288, U12288, 12288),  // this is just for expansion
                (u12416, U12416, 12416),  // this is just for Barrett
                (u15360, U15360, 15360),
                (u15424, U15424, 15424),  // this is just for expansion
                (u16384, U16384, 16384),  // this is just for expansion
                (u16448, U16448, 16448),  // this is just for Barrett
                (u16512, U16512, 16512),  // this is just for Barrett
                (u30720, U30720, 30720),  // this is just for expansion
                (u30784, U30784, 30784),  // this is just for Barrett
                (u32768, U32768, 32768),  // this is just for expansion
                (u32896, U32896, 32896),  // this is just for Barrett
                (u61440, U61440, 61440),  // this is just for expansion
                (u61568, U61568, 61568)); // this is just for Barrett
