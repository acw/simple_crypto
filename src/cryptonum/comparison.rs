use cryptonum::basetypes::*;
use std::cmp::{Ord,Ordering};

macro_rules! generate_compares
{
    ($name: ident, $size: expr) => {
        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                for i in 0..($size/64) {
                    if self.values[i] != other.values[i] {
                        return false;
                    }
                }
                true
            }
        }

        impl Eq for $name {}

        impl Ord for $name {
            fn cmp(&self, other: &$name) -> Ordering {
                let mut i = (($size / 64) - 1) as isize;

                while i >= 0 {
                    let iu = i as usize;
                    match self.values[iu].cmp(&other.values[iu]) {
                        Ordering::Greater => return Ordering::Greater,
                        Ordering::Less    => return Ordering::Less,
                        Ordering::Equal   => i -= 1
                    }
                }

                Ordering::Equal
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
    }
}

generate_compares!(U192,     192);
generate_compares!(U256,     256);
generate_compares!(U320,     320); // this is just for expansion
generate_compares!(U384,     384);
generate_compares!(U448,     448); // this is just for expansion
generate_compares!(U512,     512);
generate_compares!(U576,     576);
generate_compares!(U640,     640); // this is just for expansion
generate_compares!(U768,     768); // this is just for expansion
generate_compares!(U832,     832); // this is just for Barrett
generate_compares!(U896,     896); // this is just for Barrett
generate_compares!(U1024,   1024);
generate_compares!(U1088,   1088); // this is just for expansion
generate_compares!(U1152,   1152); // this is just for expansion
generate_compares!(U1216,   1216); // this is just for Barrett
generate_compares!(U1536,   1536); // this is just for expansion
generate_compares!(U1664,   1664); // this is just for Barrett
generate_compares!(U2048,   2048);
generate_compares!(U2112,   2112); // this is just for expansion
generate_compares!(U2176,   2176); // this is just for Barrett
generate_compares!(U2304,   2304); // this is just for expansion
generate_compares!(U2432,   2432); // this is just for Barrett
generate_compares!(U3072,   3072);
generate_compares!(U3136,   3136); // this is just for expansion
generate_compares!(U4096,   4096);
generate_compares!(U4160,   4160); // this is just for expansion
generate_compares!(U4224,   4224); // this is just for Barrett
generate_compares!(U6144,   6144); // this is just for expansion
generate_compares!(U6208,   6208); // this is just for Barrett
generate_compares!(U7680,   7680);
generate_compares!(U7744,   7744);
generate_compares!(U8192,   8192);
generate_compares!(U8256,   8256); // this is just for expansion
generate_compares!(U8320,   8320); // this is just for Barrett
generate_compares!(U12288, 12288); // this is just for expansion
generate_compares!(U12416, 12416); // this is just for Barrett
generate_compares!(U15360, 15360);
generate_compares!(U15424, 15424); // this is just for expansion
generate_compares!(U16384, 16384); // this is just for expansion
generate_compares!(U16448, 16448); // this is just for Barrett
generate_compares!(U16512, 16512); // this is just for Barrett
generate_compares!(U30720, 30720); // this is just for expansion
generate_compares!(U30784, 30784); // this is just for Barrett
generate_compares!(U32768, 32768); // this is just for expansion
generate_compares!(U32896, 32896); // this is just for Barrett
generate_compares!(U61440, 61440); // this is just for expansion
generate_compares!(U61568, 61568); // this is just for Barrett

