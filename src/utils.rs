use cryptonum::unsigned::*;
use num::BigUint;

pub trait TranslateNums {
    fn from_num(x: BigUint) -> Self;
    fn to_num(&self) -> BigUint;
}

macro_rules! from_biguint {
    ($uname: ident, $size: expr) => {
        impl TranslateNums for $uname {
            fn from_num(x: BigUint) -> $uname {
                let mut base_vec = x.to_bytes_be();
                let target_bytes = $size / 8;

                while target_bytes > base_vec.len() {
                    base_vec.insert(0,0);
                }

                while base_vec.len() > target_bytes {
                    base_vec.remove(0);
                }

                $uname::from_bytes(&base_vec)
            }

            fn to_num(&self) -> BigUint {
                let bytes = self.to_bytes();
                BigUint::from_bytes_be(&bytes)
            }
        }
    };
}

from_biguint!(U512,   512);
from_biguint!(U1024,  1024);
from_biguint!(U2048,  2048);
from_biguint!(U3072,  3072);
from_biguint!(U4096,  4096);
from_biguint!(U8192,  8192);
from_biguint!(U15360, 15360);
