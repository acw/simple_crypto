use std::cmp::Ordering;

#[inline]
pub fn generic_cmp(a: &[u64], b: &[u64]) -> Ordering {
    let mut i = a.len() - 1;

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
