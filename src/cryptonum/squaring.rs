use cryptonum::basetypes::*;

macro_rules! generate_squarers
{
    ($name: ident, $bigger: ident, $size: expr) => {
        impl $name {
            pub fn square(&self) -> $bigger {
                let mut w = [0; $size/32];
                let     t = $size / 64;

                for i in 0..t {
                    let x128 = self.values[i] as u128;
                    let mut uvb = (w[2*i] as u128) + (x128 * x128);
                    w[2*i] = uvb & 0xFFFFFFFFFFFFFFFF;
                    let mut c = uvb >> 64;
                    for j in (i+1)..t {
                        let xj128  = self.values[j] as u128;
                        let xi128  = self.values[i] as u128;
                        // this first product is safely 128 bits or less,
                        // because the input arguments are both 64 bits.
                        let xij128 = xj128 * xi128;
                        // this next bit may overflow, but will do so by exactly
                        // one bit.
                        let twoxij128 = xij128 << 1;
                        let carried_shl = (xij128 & (1 << 127)) != 0;
                        // this next bit may *also* overflow, but should also do
                        // so by no more than one bit.
                        let (new,carry1) = twoxij128.overflowing_add(c);
                        // ditto ...
                        let wij = w[i+j];
                        let (uvb2,carry2) = new.overflowing_add(wij as u128);
                        // for the value we're going to save for this digit, we
                        // only care about the low bits, so we can forget about
                        // the carry stuff.
                        w[i+j] = uvb2 & 0xFFFFFFFFFFFFFFFF;
                        // for c, though, we do care about the carries, above.
                        // Fortunately, they were both by only one bit, so we
                        // should be able to just back-fix them.
                        c = uvb2 >> 64;
                        if carried_shl  { c += 1 << 64; }
                        if carry1       { c += 1 << 64; }
                        if carry2       { c += 1 << 64; }
                    }
                    w[i+t] = c;
                }
                let mut res = $bigger::zero();
                for i in 0..w.len() { res.values[i] = w[i] as u64; }
                res
            }
        }
//
//        impl ModSquare for $name {
//            fn modsq(&self, m: &$name) -> $name {
//                let bigsquare = self.square();
//                let bigm      = $bigger::from(m);
//                let bigres    = bigsquare.reduce(&bigm);
//                $name::from(bigres)
//            }
//        }
    }
}

generate_squarers!(U192,   U384,    192);
generate_squarers!(U256,   U512,    256);
generate_squarers!(U384,   U768,    384);
generate_squarers!(U512,   U1024,   512);
generate_squarers!(U576,   U1152,   576);
generate_squarers!(U1024,  U2048,  1024);
generate_squarers!(U2048,  U4096,  2048);
generate_squarers!(U3072,  U6144,  3072);
generate_squarers!(U4096,  U8192,  4096);
generate_squarers!(U8192,  U16384, 8192);
generate_squarers!(U15360, U30720,15360);

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
                    let fname = format!("tests/math/squaring{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 2, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1);
                        let a = $name::from_bytes(abytes);
                        let r = $bigger::from_bytes(rbytes);
                        let myres = a.square();
                        assert_eq!(r, myres);
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
