macro_rules! derive_barrett
{
    ($type: ident, $barrett: ident, $count: expr) => {
        impl CryptoNumFastMod for $type {
            type BarrettMu = $barrett;

            fn barrett_mu(&self) -> Option<$barrett> {
                // Step #0: Don't divide by 0.
                if self.is_zero() {
                    return None
                }
                // Step #1: Compute k.
                let mut k = $count;
                while self.contents[k - 1] == 0 { k -= 1 };
                // Step #2: The algorithm below only works if x has at most 2k
                // digits, so if k*2 < count, abort this whole process.
                if (k * 2) < $count {
                    return None
                }
                // Step #2: Compute floor(b^2k / m), where m is this value.
                let mut widebody_b2k  = [0; ($count * 2) + 1];
                let mut widebody_self = [0; ($count * 2) + 1];
                let mut quotient      = [0; ($count * 2) + 1];
                let mut remainder     = [0; ($count * 2) + 1];
                widebody_b2k[$count * 2] = 1;
                for i in 0..k {
                    widebody_self[i] = self.contents[i];
                }
                generic_div(&widebody_b2k, &widebody_self,
                            &mut quotient, &mut remainder);
                let mut result        = [0; $count + 1];
                for (idx, val) in quotient.iter().enumerate() {
                    if idx < ($count + 1) {
                        result[idx] = *val;
                    } else {
                        if quotient[idx] != 0 {
                            return None;
                        }
                    }
                }
                Some($barrett{k: k, progenitor: self.clone(), contents: result})
            }

            fn fastmod(&self, mu: &$barrett) -> $type {
                // This algorithm is from our friends at the Handbook of
                // Applied Cryptography, Chapter 14, Algorithm 14.42.
                // Step #0:
                //    Expand x so that it has the same size as the Barrett
                //    value.
                let mut x = [0; $count + 1];
                for i in 0..$count {
                    x[i] = self.contents[i];
                }
                // Step #1:
                //    q1 <- floor(x / b^(k-1))
                let mut q1 = x.clone();
                generic_shr(&mut q1, &x, 64 * (mu.k - 1));
                //    q2 <- q1 * mu
                let q2 = expanding_mul(&q1, &mu.contents);
                //    q3 <- floor(q2 / b^(k+1))
                let mut q3big = q2.clone();
                generic_shr(&mut q3big, &q2, 64 * (mu.k + 1));
                let mut q3 = [0; $count + 1];
                for (idx, val) in q3big.iter().enumerate() {
                    if idx <= $count {
                        q3[idx] = *val;
                    } else {
                        assert_eq!(*val, 0);
                    }
                }
                // Step #2:
                //    r1 <- x mod b^(k+1)
                let mut r1 = x.clone();
                for i in mu.k..($count+1) {
                    r1[i] = 0;
                }
                //    r2 <- q3 * m mod b^(k+1)
                let mut moddedm = [0; $count + 1];
                for i in 0..mu.k {
                    moddedm[i] = mu.progenitor.contents[i];
                }
                let mut r2 = q3.clone();
                generic_mul(&mut r2, &q3, &moddedm);
                //    r  <- r1 - r2
                let mut r = r1.clone();
                generic_sub(&mut r, &r2);
                let is_negative = !ge(&r1, &r2);
                // Step #3:
                //    if r < 0 then r <- r + b^(k + 1)
                if is_negative {
                    let mut bk1 = [0; $count + 1];
                    bk1[mu.k] = 1;
                    generic_add(&mut r, &bk1);
                }
                // Step #4:
                //    while r >= m do: r <- r - m.
                while ge(&r, &moddedm) {
                    generic_sub(&mut r, &moddedm);
                }
                // Step #5:
                //    return r
                let mut retval = [0; $count];
                for i in 0..$count {
                    retval[i] = r[i];
                }
                assert_eq!(r[$count], 0);
                $type{ contents: retval }
            }
        }
    }
}

