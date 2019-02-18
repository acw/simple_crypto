use cryptonum::unsigned::*;
use num::{BigInt,BigUint};
use num::bigint::Sign;

pub trait TranslateNums<N>: Sized {
    fn from_num(x: &N) -> Option<Self>;
    fn to_num(&self) -> N;
}

macro_rules! from_biguint {
    ($uname: ident, $size: expr) => {
        impl TranslateNums<BigUint> for $uname {
            fn from_num(x: &BigUint) -> Option<$uname> {
                let mut base_vec = x.to_bytes_be();
                let target_bytes = $size / 8;

                if target_bytes < base_vec.len() {
                    return None;

                }
                while target_bytes > base_vec.len() {
                    base_vec.insert(0,0);
                }

                Some($uname::from_bytes(&base_vec))
            }

            fn to_num(&self) -> BigUint {
                let bytes = self.to_bytes();
                BigUint::from_bytes_be(&bytes)
            }
        }

        impl TranslateNums<BigInt> for $uname {
            fn from_num(x: &BigInt) -> Option<$uname> {
                let ux = x.to_biguint()?;
                $uname::from_num(&ux)
            }

            fn to_num(&self) -> BigInt {
                BigInt::from_biguint(Sign::Plus, self.to_num())
            }
        }
    };
}

from_biguint!(U192,   192);
from_biguint!(U256,   256);
from_biguint!(U384,   384);
from_biguint!(U512,   512);
from_biguint!(U576,   576);
from_biguint!(U1024,  1024);
from_biguint!(U2048,  2048);
from_biguint!(U3072,  3072);
from_biguint!(U4096,  4096);
from_biguint!(U8192,  8192);
from_biguint!(U15360, 15360);