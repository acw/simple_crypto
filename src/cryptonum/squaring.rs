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

#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use cryptonum::Decoder;
#[cfg(test)]
use cryptonum::encoding::raw_decoder;
#[cfg(test)]
use cryptonum::{U192,U256,U384,U512,U576,U1024,U2048,U3072,U4096,U8192,U15360};

macro_rules! generate_tests {
    ($name: ident, $testname: ident) => (
        #[cfg(test)]
        #[test]
        #[allow(non_snake_case)]
        fn $testname() {
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
    )
}

generate_tests!(U192,u192);
generate_tests!(U256,u256);
generate_tests!(U384,u384);
generate_tests!(U512,u512);
generate_tests!(U576,u576);
generate_tests!(U1024,u1024);
generate_tests!(U2048,u2048);
generate_tests!(U3072,u3072);
generate_tests!(U4096,u4096);
generate_tests!(U8192,u8192);
generate_tests!(U15360,u15360);