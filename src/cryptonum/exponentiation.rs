use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::division::divmod;
use cryptonum::multiplication::ModMul;
use cryptonum::squaring::ModSquare;

pub trait ModExp<T=Self> {
    fn modexp(&mut self, e: &Self, m: &T);
}

macro_rules! generate_exponentiators
{
    ($name: ident, $size: expr) => {
        impl ModExp for $name {
            fn modexp(&mut self, e: &$name, m: &$name) {
                // S <- g
                let mut s     = self.clone();
                let mut _dead = [0; $size/32];
                divmod(&self.values, &m.values, &mut _dead, &mut s.values);
                // A <- 1
                for val in self.values.iter_mut() { *val = 0; }
                self.values[0] = 1;
                // We do a quick skim through and find the highest index that
                // actually has a value in it.
                let mut highest_digit = 0;
                for (idx, val) in e.values.iter().enumerate() {
                    if *val != 0 {
                        highest_digit = idx;
                    }
                }
                // While e != 0 do the following:
                //   If e is odd then A <- A * S
                //   e <- floor(e / 2)
                //   If e != 0 then S <- S * S
                for i in 0..highest_digit+1 {
                    let mut mask = 1;

                    while mask != 0 {
                        if e.values[i] & mask != 0 {
                            self.modmul(&s, m);
                        }
                        mask <<= 1;
                        s.modsq(m);
                    }
                }
                // Return A
            }
        }
    }
}

generate_exponentiators!(U192,192);
generate_exponentiators!(U256,256);
generate_exponentiators!(U384,384);
generate_exponentiators!(U512,512);
generate_exponentiators!(U576,576);
generate_exponentiators!(U1024,1024);
generate_exponentiators!(U2048,2048);
generate_exponentiators!(U3072,3072);
generate_exponentiators!(U4096,4096);
generate_exponentiators!(U8192,8192);
generate_exponentiators!(U15360,15360);

macro_rules! generate_tests {
    ( $( $name:ident ),* ) => {
        #[cfg(test)]
        mod slow_modular {
            use cryptonum::encoding::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                #[ignore]
                fn $name() {
                    let fname = format!("tests/math/modexp{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, bbytes) = case.get("b").unwrap();
                        let (neg1, ebytes) = case.get("e").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3);
                        let mut b = $name::from_bytes(bbytes);
                        let e = $name::from_bytes(ebytes);
                        let m = $name::from_bytes(mbytes);
                        let r = $name::from_bytes(rbytes);
                        b.modexp(&e, &m);
                        assert_eq!(b, r);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod varrett_modular {
            use cryptonum::encoding::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                #[ignore]
                fn $name() {
                    let fname = format!("tests/math/modexp{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 4, |case| {
                        let (neg0, bbytes) = case.get("b").unwrap();
                        let (neg1, ebytes) = case.get("e").unwrap();
                        let (neg2, mbytes) = case.get("m").unwrap();
                        let (neg3, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1 && !neg2 && !neg3);
                        let mut b = $name::from_bytes(bbytes);
                        let e = $name::from_bytes(ebytes);
                        let m = $name::from_bytes(mbytes);
                        let r = $name::from_bytes(rbytes);
                        b.modexp(&e, &m);
                        assert_eq!(b, r);
                    });
                }
            )*
        }

    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048,
                U3072, U4096, U8192, U15360);
