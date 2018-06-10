use cryptonum::{U192,U256,U384,U512,U576,U1024,U2048,U3072,U4096,U8192,U15360};
use cryptonum::division::divmod;

pub trait ModSquare<T=Self>
{
    fn modsq(&mut self, m: &T);
}

// This is algorithm 14.16 from "Handbook of Applied Cryptography".
pub fn raw_square(x: &[u64], result: &mut [u64])
{
    assert_eq!(x.len() * 2, result.len());
    let t = x.len();
    let mut w: Vec<u128> = Vec::with_capacity(t * 2);
    w.resize(t * 2, 0);

    for i in 0..t {
        let x128 = x[i] as u128;
        let mut uvb = (w[2*i] as u128) + (x128 * x128);
        w[2*i] = uvb & 0xFFFFFFFFFFFFFFFF;
        let mut c = uvb >> 64;
        for j in (i+1)..t {
            let xj128  = x[j] as u128;
            let xi128  = x[i] as u128;
            // this first product is safely 128 bits or less, because the
            // input arguments are both 64 bits.
            let xij128 = xj128 * xi128;
            // this next bit may overflow, but will do so by exactly one bit.
            let twoxij128 = xij128 << 1;
            let carried_shl = (xij128 & (1 << 127)) != 0;
            // this next bit may *also* overflow, but should also do so by no
            // more than one bit.
            let (newstuff, carried_add1) = twoxij128.overflowing_add(c);
            // ditto ...
            let (uvb2, carried_add2) = newstuff.overflowing_add(w[i+j] as u128);
            // for the value we're going to save for this digit, we only care
            // about the low bits, so we can forget about the carry stuff.
            w[i+j] = uvb2 & 0xFFFFFFFFFFFFFFFF;
            // for c, though, we do care about the carries, above. Fortunately,
            // they were both by only one bit, so we should be able to just
            // back-fix them.
            c = uvb2 >> 64;
            if carried_shl  { c += 1 << 64; }
            if carried_add1 { c += 1 << 64; }
            if carried_add2 { c += 1 << 64; }
        }
        w[i+t] = c;
    }

    for (idx, val) in w.iter().enumerate() {
        result[idx] = *val as u64;
    }
}

macro_rules! generate_squarers {
    ($type: ident, $size: expr) => {
        impl ModSquare for $type {
            fn modsq(&mut self, m: &$type) {
                let mut sqres  = [0; $size/32];
                raw_square(&self.values, &mut sqres);
                let mut widerm = [0; $size/32];
                for (idx,val) in m.values.iter().enumerate() { widerm[idx] = *val; }
                let mut dead   = [0; $size/32];
                let mut answer = [0; $size/32];
                divmod(&sqres, &widerm, &mut dead, &mut answer);
                for i in 0..answer.len() {
                    if i < self.values.len() {
                        self.values[i] = answer[i];
                    } else {
                        assert_eq!(answer[i], 0);
                    }
                }
            }
        }
    };
}

generate_squarers!(U192,     192);
generate_squarers!(U256,     256);
generate_squarers!(U384,     384);
generate_squarers!(U512,     512);
generate_squarers!(U576,     576);
generate_squarers!(U1024,   1024);
generate_squarers!(U2048,   2048);
generate_squarers!(U3072,   3072);
generate_squarers!(U4096,   4096);
generate_squarers!(U8192,   8192);
generate_squarers!(U15360, 15360);

macro_rules! generate_tests {
    ( $( $name:ident ),* ) => {
        #[cfg(test)]
        mod normal {
            use cryptonum::Decoder;
            use cryptonum::encoding::raw_decoder;
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
                        let mut result = Vec::with_capacity(a.values.len() * 2);
                        result.resize(a.values.len() * 2, 0);
                        let mut myresult = result.clone();
                        raw_decoder(rbytes, &mut result);
                        raw_square(&a.values, &mut myresult);
                        assert_eq!(result, myresult);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod slow_modular {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/modsq{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (neg0, abytes) = case.get("a").unwrap();
                        let (neg1, mbytes) = case.get("m").unwrap();
                        let (neg2, rbytes) = case.get("r").unwrap();

                        assert!(!neg0 && !neg1 && !neg2);
                        let mut a = $name::from_bytes(abytes);
                        let     m = $name::from_bytes(mbytes);
                        let     r = $name::from_bytes(rbytes);
                        a.modsq(&m);
                        assert_eq!(a, r);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192, U256, U384, U512, U576, U1024, U2048, U3072, U4096, U8192, U15360);