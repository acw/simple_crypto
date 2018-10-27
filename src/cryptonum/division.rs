use cryptonum::basetypes::*;

pub trait ModReduce<T=Self> {
    fn reduce(&self, value: &T) -> T;
}

macro_rules! safesubidx
{
    ($array: expr, $index: expr, $amt: expr) => ({
        let idx = $index;
        let amt = $amt;

        if idx < amt {
            0
        } else {
            $array[idx-amt]
        }
    })
}

macro_rules! generate_dividers
{
    ($name: ident, $bigger: ident) => {
        impl $name {
            // This is based on algorithm 14.20 from the Handbook of Applied
            // Cryptography, slightly modified.
            pub fn divmod(&self, rhs: &$name) -> ($name, $name) {
                // if the divisor is larger, then the answer is pretty simple
                if rhs > self {
                    return ($name::zero(), self.clone());
                }
                // compute the basic number sizes
                let mut n = match get_number_size(&self.values) {
                                None    => 0,
                                Some(v) => v
                            };
                let t = match get_number_size(&rhs.values) {
                            None    => panic!("Division by zero!"),
                            Some(v) => v
                        };
                assert!(t <= n);
                // now generate mutable versions we can mess with
                let mut x = $bigger::from(self);
                let mut y = $bigger::from(rhs);
                // If we want this to perform reasonable, it's useful if the
                // value of y[t] is shifted so that the high bit is set.
                let lambda_shift = y.values[t].leading_zeros() as usize;
                if lambda_shift != 0 {
                    shiftl(&mut x.values, lambda_shift);
                    shiftl(&mut y.values, lambda_shift);
                    n = get_number_size(&x.values).unwrap();
                }
                // now go!
                // 1. For j from 0 to (n-t) do: q[j] = 0;
                //      [NB: I take some liberties with this concept]
                let mut q = $bigger::zero();
                // 2. While (x >= y * b^(n-t)) do the following:
                let mut ybnt = $bigger::zero();
                for i in 0..self.values.len() {
                    ybnt.values[(n-t)+i] = y.values[i];
                    if (n-t)+i >= ybnt.values.len() {
                        break;
                    }
                }
                while x > ybnt {
                    q.values[n - t] += 1;
                    x -= &ybnt;
                }
                // 3. For i from n down to t+1 do the following:
                let mut i = n;
                while i >= (t + 1) {
                    // 3.1. If x[i] = y[t]
                    if x.values[i] == y.values[t] {
                        // ... then set q[i-t-1] = b - 1
                        q.values[i-t-1] = 0xFFFFFFFFFFFFFFFF;
                    } else {
                        // ... otherwise set q[i-t-1] =
                        //        floor((x[i] * b + x[i-1]) / y[t])
                        let xib         = (x.values[i] as u128) << 64;
                        let xi1         = safesubidx!(x.values,i,1) as u128;
                        let yt          = y.values[t] as u128;
                        let qit1        = (xib + xi1) / yt;
                        q.values[i-t-1] = qit1 as u64;
                    }
                    // 3.2. While q[i-t-1] * (y[t]*b + y[t-1]) >
                    //                  (x[i] * b^2 + x[i-1] * b + x[i-2])
                    loop {
                        // three is very close to 2.
                        let     qit1    = U192::from(safesubidx!(q.values,i-t,1));
                        let mut ybits   = U192::zero();
                        ybits.values[0] = safesubidx!(y.values, t, 1);
                        ybits.values[1] = y.values[t];
                        let       qiybs = &qit1 * &ybits;
                        let mut   xbits = U384::zero();
                        xbits.values[0] = safesubidx!(x.values,i,2);
                        xbits.values[1] = safesubidx!(x.values,i,1);
                        xbits.values[2] = x.values[i];

                        if !(&qiybs > &xbits) {
                            break;
                        }

                        // ... do q[i-t-1] = q[i-t-1] - 1
                        q.values[i-t-1] -= 1;
                    }
                    // 3.3. x = x - q[i-t-1] * y * b^(i-t-1)
                    // 3.4. If x < 0
                    //      then set x = x + y * b^(i-t-1) and
                    //               q[i-t-1] = q[i-t-1] - 1
                    let mut qbit1 = $name::zero();
                    qbit1.values[i-t-1] = q.values[i-t-1];
                    let smallery = $name::from(&y);
                    let mut subpart = &smallery * &qbit1;
                    if subpart > x {
                        let mut addback = $bigger::zero();
                        for (idx, val) in y.values.iter().enumerate() {
                            let dest = idx + (i - t - 1);
                            if dest < addback.values.len() {
                                addback.values[dest] = *val;
                            }
                        }
                        q.values[i-t-1] -= 1;
                        subpart -= &addback;
                    }
                    assert!(subpart <= x);
                    x -= &subpart;
                    i -= 1;
                }
                // 4. r = x ... sort of. Remember, we potentially did a bit of shifting
                // around at the very beginning, which we now need to account for. On the
                // bright side, we only need to account for this in the remainder.
                let mut r = $name::from(&x);
                shiftr(&mut r.values, lambda_shift);
                // 5. Return (q,r)
                let resq = $name::from(&q);
                (resq, r)
            }
        }

        impl ModReduce for $name {
            fn reduce(&self, value: &$name) -> $name {
                let (_, res) = self.divmod(value);
                res
            }
        }
    }
}

fn shiftl(x: &mut [u64], amt: usize)
{
    let mut carry = 0;

    for v in x.iter_mut() {
        let new_carry = *v >> (64 - amt);
        *v = (*v << amt) | carry;
        carry = new_carry;
    }
    assert!(carry == 0);
}

fn shiftr(x: &mut [u64], amt: usize)
{
    let mut carry = 0;

    for val in x.iter_mut().rev() {
        let mask = !(0xFFFFFFFFFFFFFFFF << amt);
        let newcarry = *val & mask;
        *val = (*val >> amt) | carry;
        carry = newcarry;
    }
}

fn get_number_size(v: &[u64]) -> Option<usize>
{
    for (idx, val) in v.iter().enumerate().rev() {
        if *val != 0 {
            return Some(idx);
        }
    }
    None
}

generate_dividers!(U192,   U384);
generate_dividers!(U256,   U512);
generate_dividers!(U384,   U768);
generate_dividers!(U448,   U896);
generate_dividers!(U512,   U1024);
generate_dividers!(U576,   U1152);
generate_dividers!(U768,   U1536);
generate_dividers!(U832,   U1664);
generate_dividers!(U1024,  U2048);
generate_dividers!(U1088,  U2176);
generate_dividers!(U1152,  U2304);
generate_dividers!(U1216,  U2432);
generate_dividers!(U2048,  U4096);
generate_dividers!(U2112,  U4224);
generate_dividers!(U3072,  U6144);
generate_dividers!(U4096,  U8192);
generate_dividers!(U4160,  U8320);
generate_dividers!(U6144,  U12288);
generate_dividers!(U6208,  U12416);
generate_dividers!(U7680,  U15360);
generate_dividers!(U8192,  U16384);
generate_dividers!(U8256,  U16512);
generate_dividers!(U15360, U30720);
generate_dividers!(U16384, U32768);
generate_dividers!(U16448, U32896);
generate_dividers!(U30720, U61440);
generate_dividers!(U30784, U61568);

#[cfg(test)]
mod normal {
    use testing::run_test;
    use cryptonum::Decoder;
    use cryptonum::{U192,U256,U384,U512,U576,U1024,
                    U2048,U3072,U4096,U8192,U15360};

    macro_rules! generate_tests {
        ($name: ident) => (
            #[cfg(test)]
            #[test]
            #[allow(non_snake_case)]
            fn $name() {
                let fname = format!("tests/math/division{}.test",
                                    stringify!($name));
                run_test(fname.to_string(), 4, |case| {
                    let (neg0, abytes) = case.get("a").unwrap();
                    let (neg1, bbytes) = case.get("b").unwrap();
                    let (neg2, qbytes) = case.get("q").unwrap();
                    let (neg3, rbytes) = case.get("r").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3);

                    let a = $name::from_bytes(abytes);
                    let b = $name::from_bytes(bbytes);
                    let q = $name::from_bytes(qbytes);
                    let r = $name::from_bytes(rbytes);
                    let (myq, myr) = a.divmod(&b);
                    assert_eq!(q, myq);
                    assert_eq!(r, myr);
                });
            }
        )
    }

    generate_tests!(U192);
    generate_tests!(U256);
    generate_tests!(U384);
    generate_tests!(U512);
    generate_tests!(U576);
    generate_tests!(U1024);
    generate_tests!(U2048);
    generate_tests!(U3072);
    generate_tests!(U4096);
    generate_tests!(U8192);
    generate_tests!(U15360);
}
