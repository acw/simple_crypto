use cryptonum::addition::raw_addition;
use cryptonum::comparison::{bignum_cmp,bignum_ge};
use cryptonum::multiplication::raw_multiplication;
use cryptonum::subtraction::raw_subtraction;
use std::cmp::Ordering;

// This is based on algorithm 14.20 from the Handbook of Applied Cryptography,
// slightly modified.
pub fn divmod(inx: &[u64], iny: &[u64], q: &mut [u64], r: &mut [u64])
{
    // let's make sure we get the basic sizes right
    assert_eq!(inx.len(), iny.len());
    assert!(q.len() >= (inx.len() - 1));
    assert!(r.len() >= iny.len());
    // compute the basic number sizes
    let mut n = match get_number_size(iny) {
                    None    => 0,
                    Some(v) => v
                };
    let mut t = match get_number_size(iny) {
                    None    => panic!("Division by zero!"),
                    Some(v) => v
                };
    // if the divisor is larger, then the answer is pretty simple
    if t > n {
        for x in q.iter_mut() {
            *x = 0;
        }
        for (idx, val) in inx.iter().enumerate() {
            r[idx] = *val;
        }
        return
    }
    // OK, if we're here, then we've cleared the conditions that n >= t,
    // and that y[t] != 0. However, we have not cleared the bar that
    // n >= t >= 1.
    let mut x = Vec::with_capacity(inx.len());
    let mut y = Vec::with_capacity(iny.len());
    let added_zero = t == 0;
    if added_zero {
        x.push(0);
        y.push(0);
        n += 1;
        t += 1;
    }
    for v in inx.iter() { x.push(*v); }
    for v in iny.iter() { y.push(*v); }
    // OK, now we've cleared the n >= t >= 1 hurdle. Last thing: if we want
    // this to perform reasonably, it's useful if the value is shifted y[t]
    // such that the high bit is set.
    let lambda_shift = y[t].leading_zeros() as usize;
    if lambda_shift != 0 {
        shiftl(&mut x, lambda_shift);
        shiftl(&mut y, lambda_shift);
        n = get_number_size(&x).unwrap();
    }
    // At this point, we can actually start the algorithm.
    // 1. For j from 0 to (n-t) do: q[j] = 0;
    //      [NB: I take some liberties with this concept]
    for v in q.iter_mut() { *v = 0; }
    // 2. While (x >= y * b^(n-t)) do the following:
    let mut ybnt = y.clone();
    // we can shift left by just adding the right amount of digits, adding
    // some on the end of x to keep the vectors the same size.
    for _ in 0..n-t { ybnt.insert(0,0); x.push(0); }
    while matching_bignum_ge(&x, &ybnt) {
        // q[n-t] = q[n-t] + 1
        q[n-t] += 1;
        // x = x - y * b^(n-t)
        raw_subtraction(&mut x, &ybnt);
    }
    // 3. For i from n down to t+1 do the following:
    let mut i = n;
    while i >= (t + 1) {
        // 3.1. If x[i] = y[t]
        if x[i] == y[t] {
            // ... then set q[i-t-1] = b - 1
            q[i-t-1] = 0xFFFFFFFFFFFFFFFF;
        } else {
            // ... otherwise set q[i-t-1] = floor((x[i] * b + x[i-1]) / y[t])
            let xib  = (x[i] as u128) << 64;
            let xi1  = x[i-1] as u128;
            let yt   = y[t] as u128;
            let qit1 = (xib + xi1) / yt;
            q[i-t-1] = qit1 as u64;
        }
        // 3.2. While q[i-t-1] * (y[t]*b + y[t-1]) > (x[i] * b^2 + x[i-1] * b + x[i-2])
        loop {
            let     qit1:  [u64; 2] = [q[i-t-1], 0];
            let     ybits: [u64; 2] = [y[t-1], y[t]];
            let mut qiybs: [u64; 4] = [0, 0, 0, 0];
            raw_multiplication(&qit1, &ybits, &mut qiybs);
            let     xbits: [u64; 4] = [x[i-2], x[i-1], x[i], 0];
            
            if bignum_ge(&xbits, &qiybs) {
                break;
            }

            // ... do q[i-t-1] = q[i-t-1] - 1
            q[i-t-1] -= 1;
        }
        // 3.3. x = x - q[i-t-1] * y * b^(i-t-1)
        // this is a bit of a pain in the ass, to make sure all the sizes line
        // up. we start by computing an appropriately-shifted version of y
        let mut widery = y.clone();
        for _ in 0..(i-t-1) { widery.insert(0,0); }
        // OK, then we need to multiply in the q[i-t-1] digit
        let mut qit1 = Vec::with_capacity(widery.len());
        qit1.resize(widery.len(), 0);
        qit1[0] = q[i-t-1];
        // Multiply these together, and we have what we want to subtract
        let mut subamt = Vec::with_capacity(2 * widery.len());
        subamt.resize(2 * widery.len(), 0);
        raw_multiplication(&widery, &qit1, &mut subamt);
        // then we make a wider version of x to match this one
        let mut widerx = x.clone();
        while widerx.len() < subamt.len() { widerx.push(0); }
        // and compare them, which is going to inline the following steps:
        // 3.4. If x < 0
        //      then set x = x + y * b^(i-t-1) and
        //               q[i-t-1] = q[i-t-1] - 1
        if bignum_cmp(&subamt, &widerx) == Ordering::Greater {
            assert!(subamt.len() >= widery.len());
            while widery.len() < subamt.len() { widery.push(0); }
            raw_subtraction(&mut subamt, &widery);
            q[i-t-1] -= 1;
        } else {
            assert!(subamt.len() >= widerx.len());
        }
        raw_subtraction(&mut widerx, &subamt);
        for i in 0..widerx.len() {
            if i < x.len() {
                x[i] = widerx[i];
            } else {
                assert_eq!(widerx[i], 0);
            }
        }
        i -= 1;
    }
    // 4. r = x ... sort of. Remember, we potentially did a bit of shifting
    // around at the very beginning, which we now need to account for. On the
    // bright side, we only need to account for this in the remainder.
    let offset = if added_zero { 1 } else { 0 };
    for (idx, rval) in r.iter_mut().enumerate() {
        let baseval = x[idx + offset] >> lambda_shift;
        if idx + offset + 1 < x.len() { 
            let mask = !(0xFFFFFFFFFFFFFFFF << lambda_shift);
            let highbits = x[idx + offset + 1] & mask;
            *rval = baseval | highbits;
        } else {
            *rval = baseval;
        }
    }
    // 5. Return (q,r)
}

fn shiftl(x: &mut Vec<u64>, amt: usize)
{
    let mut carry = 0;
    
    for v in x.iter_mut() {
        let new_carry = *v >> (64 - amt);
        *v = (*v << amt) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        x.push(carry);
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

fn matching_bignum_ge(x: &[u64], y: &[u64]) -> bool
{
    if x.len() == y.len() {
        return bignum_ge(&x, &y);
    }

    if x.len() > y.len() {
        let mut yprime = Vec::with_capacity(x.len());
        yprime.extend_from_slice(&y);
        while yprime.len() < x.len() { yprime.push(0); }
        bignum_ge(&x, &yprime)
    } else {
        let mut xprime = Vec::with_capacity(y.len());
        xprime.extend_from_slice(&x);
        while xprime.len() < y.len() { xprime.push(0); }
        bignum_ge(&xprime, &y)
    }
}

#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use cryptonum::Decoder;
#[cfg(test)]
use cryptonum::{U192,U256,U384,U512,U576,U1024,U2048,U3072,U4096,U8192,U15360};

macro_rules! generate_tests {
    ($name: ident, $testname: ident) => (
        #[cfg(test)]
        #[test]
        #[allow(non_snake_case)]
        fn $testname() {
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

                let mut myq = $name::new();
                let mut myr = $name::new();

                divmod(&a.values, &b.values, &mut myq.values, &mut myr.values);
                assert_eq!(q, myq);
                assert_eq!(r, myr);
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