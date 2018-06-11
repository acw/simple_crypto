use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use cryptonum::division::divmod;
use std::fmt;

macro_rules! generate_barrett_implementations {
    ($bname: ident, $name: ident, $size: expr) => {
        pub struct $bname {
            pub(crate) mu: [u64; $size/32]
        }

        impl fmt::Debug for $bname {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, stringify!($bname))?;
                write!(f, "{{ ")?;
                for x in self.mu.iter() {
                    write!(f, "{:X} ", *x)?;
                }
                write!(f, "}} ")
            }
        }

        impl PartialEq for $bname {
            fn eq(&self, rhs: &$bname) -> bool {
                for (left, right) in rhs.mu.iter().zip(rhs.mu.iter()) {
                    if *left != *right {
                        return false;
                    }
                }
                true
            }
        }


        impl $bname {
            fn new(m: &$name) -> $bname {
                let mut b      = [0; ($size/32) + 1];
                let mut widerm = [0; ($size/32) + 1];
                let mut quot   = [0; ($size/32) + 1];
                let mut remndr = [0; ($size/32) + 1];
                let mut result = $bname{ mu: [0; $size/32] };

                b[$size/32] = 1;
                for (idx, val) in m.values.iter().enumerate() { widerm[idx] = *val; }
                divmod(&b, &widerm, &mut quot, &mut remndr);
                for (idx, val) in result.mu.iter_mut().enumerate() { *val = quot[idx]; }
                result
            }
        }
    };
}


generate_barrett_implementations!(BarrettU192,   U192,  192);
generate_barrett_implementations!(BarrettU256,   U256,  256);
generate_barrett_implementations!(BarrettU384,   U384,  384);
generate_barrett_implementations!(BarrettU512,   U512,  512);
generate_barrett_implementations!(BarrettU576,   U576,  576);
generate_barrett_implementations!(BarrettU1024,  U1024, 1024);
generate_barrett_implementations!(BarrettU2048,  U2048, 2048);
generate_barrett_implementations!(BarrettU3072,  U3072, 3072);
generate_barrett_implementations!(BarrettU4096,  U4096, 4096);
generate_barrett_implementations!(BarrettU8192,  U8192, 8192);
generate_barrett_implementations!(BarrettU15360, U15360,15360);

macro_rules! generate_tests {
    ( $( ($bname: ident, $name:ident, $size:expr) ),* ) => {
        #[cfg(test)]
        mod generation {
            use cryptonum::encoding::{Decoder,raw_decoder};
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/barrett_gen{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 2, |case| {
                        let (neg0, mbytes) = case.get("m").unwrap();
                        let (neg1, ubytes) = case.get("u").unwrap();

                        assert!(!neg0 && !neg1);
                        let m = $name::from_bytes(mbytes);
                        let mut u = $bname{ mu: [0; $size/32]};
                        raw_decoder(&ubytes, &mut u.mu);
                        let r = $bname::new(&m);
                        assert_eq!(u,r);
                    });
                }
            )*
        }
    }
}

generate_tests!((BarrettU192,   U192,   192),
                (BarrettU256,   U256,   256),
                (BarrettU384,   U384,   384),
                (BarrettU512,   U512,   512),
                (BarrettU576,   U576,   576),
                (BarrettU1024,  U1024,  1024),
                (BarrettU2048,  U2048,  2048),
                (BarrettU3072,  U3072,  3072),
                (BarrettU4096,  U4096,  4096),
                (BarrettU8192,  U8192,  8192),
                (BarrettU15360, U15360, 15360));
