use std::cmp::Ordering;

#[inline(always)]
pub fn generic_cmp(a: &[u64], b: &[u64]) -> Ordering {
    let mut i = a.len() - 1;

    assert!(a.len() == b.len());
    loop {
        match a[i].cmp(&b[i]) {
            Ordering::Equal if i == 0 =>
                return Ordering::Equal,
            Ordering::Equal =>
                i -= 1,
            res =>
                return res
        }
    }
}

fn le(a: &[u64], b: &[u64]) -> bool {
    generic_cmp(a, b) != Ordering::Greater
}

fn ge(a: &[u64], b: &[u64]) -> bool {
    generic_cmp(a, b) != Ordering::Less
}

#[inline(always)]
pub fn generic_bitand(a: &mut [u64], b: &[u64]) {
    let mut i = 0;

    assert!(a.len() == b.len());
    while i < a.len() {
        a[i] &= b[i];
        i += 1;
    }
}

#[inline(always)]
pub fn generic_bitor(a: &mut [u64], b: &[u64]) {
    let mut i = 0;

    assert!(a.len() == b.len());
    while i < a.len() {
        a[i] |= b[i];
        i += 1;
    }
}

#[inline(always)]
pub fn generic_bitxor(a: &mut [u64], b: &[u64]) {
    let mut i = 0;

    assert!(a.len() == b.len());
    while i < a.len() {
        a[i] ^= b[i];
        i += 1;
    }
}

#[inline(always)]
pub fn generic_not(a: &mut [u64]) {
    for x in a.iter_mut() {
        *x = !*x;
    }
}

#[inline(always)]
pub fn generic_shl(a: &mut [u64], orig: &[u64], amount: usize) {
    let digits = amount / 64;
    let bits   = amount % 64;

    assert!(a.len() == orig.len());
    for i in 0..a.len() {
        if i < digits {
            a[i] = 0;
        } else {
            let origidx = i - digits;
            let prev = if origidx == 0 { 0 } else { orig[origidx - 1] };
            let (carry,_) = if bits == 0 { (0, false) }
                            else { prev.overflowing_shr(64 - bits as u32) };
            a[i] = (orig[origidx] << bits) | carry;
        }
    }
}

#[inline(always)]
pub fn generic_shr(a: &mut [u64], orig: &[u64], amount: usize) {
    let digits = amount / 64;
    let bits   = amount % 64;

    assert!(a.len() == orig.len());
    for i in 0..a.len() {
        let oldidx = i + digits;
        let caridx = i + digits + 1;
        let old    = if oldidx >= a.len() { 0 } else { orig[oldidx] };
        let carry  = if caridx >= a.len() { 0 } else { orig[caridx] };
        let cb     = if bits == 0  { 0 } else { carry << (64 - bits) };
        a[i] = (old >> bits) | cb;
    }
}

#[inline(always)]
pub fn generic_add(a: &mut [u64], b: &[u64]) {
    let mut carry = 0;

    assert!(a.len() == b.len());
    for i in 0..a.len() {
        let x = a[i] as u128;
        let y = b[i] as u128;
        let total = x + y + carry;
        a[i] = total as u64;
        carry = total >> 64;
    }
}

#[inline(always)]
pub fn generic_sub(a: &mut [u64], b: &[u64]) {
    let mut negated_rhs = b.to_vec();
    generic_not(&mut negated_rhs);
    let mut one = Vec::with_capacity(a.len());
    one.resize(a.len(), 0);
    one[0] = 1;
    generic_add(&mut negated_rhs, &one);
    generic_add(a, &negated_rhs);
}

#[inline(always)]
pub fn generic_mul(a: &mut [u64], orig: &[u64], b: &[u64]) {
    assert!(a.len() == orig.len());
    assert!(a.len() == b.len());
    assert!(a == orig);

    // Build the output table. This is a little bit awkward because we don't
    // know how big we're running, but hopefully the compiler is smart enough
    // to work all this out.
    let mut table = Vec::with_capacity(a.len());
    for _ in 0..a.len() {
        let mut row = Vec::with_capacity(a.len());
        row.resize(a.len(), 0);
        table.push(row);
    }
    // This uses "simple" grade school techniques to work things out. But,
    // for reference, consider two 4 digit numbers:
    //
    //     l0c3        l0c2        l0c1        l0c0    [orig]
    //  x  l1c3        l1c2        l1c1        l1c0    [b]
    //  ------------------------------------------------------------
    //     (l0c3*l1c0) (l0c2*l1c0) (l0c1*l1c0) (l0c0*l1c0)
    //     (l0c2*l1c1) (l0c1*l1c1) (l0c0*l1c1)
    //     (l0c1*l1c2) (l0c0*l1c2)
    //     (l0c0*l1c3)
    //  ------------------------------------------------------------
    //     AAAAA       BBBBB       CCCCC       DDDDD
    for line in 0..a.len() {
        let maxcol = a.len() - line;
        for col in 0..maxcol {
            let left  = orig[col] as u128;
            let right = b[line] as u128;
            table[line][col + line] = left * right;
        }
    }
    // ripple the carry across each line, ensuring that each entry in the
    // table is 64-bits
    for line in 0..a.len() {
        let mut carry = 0;
        for col in 0..a.len() {
            table[line][col] = table[line][col] + carry;
            carry = table[line][col] >> 64;
            table[line][col] &= 0xFFFFFFFFFFFFFFFF;
        }
    }
    // now do the final addition across the lines, rippling the carry as
    // normal
    let mut carry = 0;
    for col in 0..a.len() {
        let mut total = carry;
        for line in 0..a.len() {
            total += table[line][col];
        }
        a[col] = total as u64;
        carry = total >> 64;
    }
}

#[inline(always)]
pub fn generic_div(inx: &[u64], iny: &[u64],
                   outq: &mut [u64], outr: &mut [u64])
{
    assert!(inx.len() == inx.len());
    assert!(inx.len() == iny.len());
    assert!(inx.len() == outq.len());
    assert!(inx.len() == outr.len());
    // This algorithm is from the Handbook of Applied Cryptography, Chapter 14,
    // algorithm 14.20. It has a couple assumptions about the inputs, namely that
    // n >= t >= 1 and y[t] != 0, where n and t refer to the number of digits in
    // the numbers. Which means that if we used the inputs unmodified, we can't
    // divide by single-digit numbers.
    //
    // To deal with this, we multiply inx and iny by 2^64, so that we push out
    // t by one.
    //
    // In addition, this algorithm starts to go badly when y[t] is very small
    // and x[n] is very large. Really, really badly. This can be fixed by
    // insuring that the top bit is set in y[t], which we can achieve by
    // shifting everyone over a maxiumum of 63 bits.
    //
    // What this means is, just for safety, we add a 0 at the beginning and
    // end of each number.
    let mut y = iny.to_vec();
    let mut x = inx.to_vec();
    y.insert(0,0); y.push(0);
    x.insert(0,0); x.push(0);
    // 0. Compute 'n' and 't'
    let n = x.len() - 1;
    let mut t = y.len() - 1;
    while (t > 0) && (y[t] == 0) { t -= 1 }
    assert!(y[t] != 0); // this is where division by zero will fire
    // 0.5. Figure out a shift we can do such that the high bit of y[t] is
    // set, and then shift x and y left by that much.
    let additional_shift: usize = y[t].leading_zeros() as usize;
    let origx = x.clone();
    let origy = y.clone();
    generic_shl(&mut x, &origx, additional_shift);
    generic_shl(&mut y, &origy, additional_shift);
    // 1. For j from 0 to (n - 1) do: q_j <- 0
    let mut q = Vec::with_capacity(y.len());
    q.resize(y.len(), 0);
    for qj in q.iter_mut() { *qj = 0 }
    // 2. While (x >= yb^(n-t)) do the following:
    //       q_(n-t) <- q_(n-t) + 1
    //       x       <- x - yb^(n-t)
    let mut ybnt = y.clone();
    generic_shl(&mut ybnt, &y, 64 * (n - t));
    while ge(&x, &ybnt) {
        q[n-t] = q[n-t] + 1;
        generic_sub(&mut x, &ybnt);
    }
    // 3. For i from n down to (t + 1) do the following:
    let mut i = n;
    while i >= (t + 1) {
        // 3.1. if x_i = y_t, then set q_(i-t-1) <- b - 1; otherwise set
        //      q_(i-t-1) <- floor((x_i * b + x_(i-1)) / y_t).
        if x[i] == y[t] {
            q[i-t-1] = 0xFFFFFFFFFFFFFFFF;
        } else {
            let top = ((x[i] as u128) << 64) + (x[i-1] as u128);
            let bot = y[t] as u128;
            let solution = top / bot;
            q[i-t-1] = solution as u64;
        }
        // 3.2. While (q_(i-t-1)(y_t * b + y_(t-1)) > x_i(b2) + x_(i-1)b +
        //      x_(i-2)) do:
        //        q_(i - t - 1) <- q_(i - t 1) - 1.
        loop {
            let mut left = Vec::with_capacity(x.len());
            left.resize(x.len(), 0);
            left[0] = q[i - t - 1];
            let mut leftright = Vec::with_capacity(x.len());
            leftright.resize(x.len(), 0);
            leftright[0] = y[t-1];

            let copy = left.clone();
            generic_mul(&mut left, &copy, &leftright);
            let mut right = Vec::with_capacity(x.len());
            right.resize(x.len(), 0);
            right[0] = x[i-2];
            right[1] = x[i-1];
            right[2] = x[i];

            if le(&left, &right) {
                break
            }

            q[i - t - 1] -= 1;
        }
        // 3.3. x <- x - q_(i - t - 1) * y * b^(i-t-1)
        let mut right = Vec::with_capacity(y.len());
        right.resize(y.len(), 0);
        right[i - t - 1] = q[i - t - 1];
        let rightclone = right.clone();
        generic_mul(&mut right, &rightclone, &y);
        let wentnegative = generic_cmp(&x, &right) == Ordering::Less;
        generic_sub(&mut x, &right);
        // 3.4. if x < 0 then set x <- x + yb^(i-t-1) and
        //      q_(i-t-1) <- q_(i-t-1) - 1
        if wentnegative {
            let mut ybit1 = y.to_vec();
            generic_shl(&mut ybit1, &y, 64 * (i - t - 1));
            generic_add(&mut x, &ybit1);
            q[i - t - 1] -= 1;
        }
        i -= 1;
    }
    // 4. r <- x
    let finalx = x.clone();
    generic_shr(&mut x, &finalx, additional_shift);
    for i in 0..outr.len() {
        outr[i] = x[i + 1]; // note that for the remainder, we're dividing by
                            // our normalization value.
    }
    // 5. return (q,r)
    for i in 0..outq.len() {
        outq[i] = q[i];
    }
}
