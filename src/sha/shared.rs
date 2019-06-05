macro_rules! ch {
    ($x: expr, $y: expr, $z: expr) => {{
        let xval = $x;
        (xval & $y) ^ (!xval & $z)
    }};
}

macro_rules! parity {
    ($x: expr, $y: expr, $z: expr) => {
        $x ^ $y ^ $z
    };
}

macro_rules! maj {
    ($x: expr, $y: expr, $z: expr) => {{
        /* the original function is (x & y) ^ (x & z) ^ (y & z).
           if you fire off truth tables, this is equivalent to
             (x & y) | (x & z) | (y & z)
           which you can then use distribution on:
             (x & (y | z)) | (y & z)
           which saves one operation */
        let yval = $y;
        let zval = $z;
        ($x & (yval | zval)) | (yval & zval)
    }};
}

macro_rules! process_u32_block {
    ($buf: expr, $off: expr, $self: ident) => {{
        let w00 = ($buf[$off+0]  as u32) << 24 | ($buf[$off+1]  as u32) << 16 |
                  ($buf[$off+2]  as u32) << 8  | ($buf[$off+3]  as u32);
        let w01 = ($buf[$off+4]  as u32) << 24 | ($buf[$off+5]  as u32) << 16 |
                  ($buf[$off+6]  as u32) << 8  | ($buf[$off+7]  as u32);
        let w02 = ($buf[$off+8]  as u32) << 24 | ($buf[$off+9]  as u32) << 16 |
                  ($buf[$off+10] as u32) << 8  | ($buf[$off+11] as u32);
        let w03 = ($buf[$off+12] as u32) << 24 | ($buf[$off+13] as u32) << 16 |
                  ($buf[$off+14] as u32) << 8  | ($buf[$off+15] as u32);
        let w04 = ($buf[$off+16] as u32) << 24 | ($buf[$off+17] as u32) << 16 |
                  ($buf[$off+18] as u32) << 8  | ($buf[$off+19] as u32);
        let w05 = ($buf[$off+20] as u32) << 24 | ($buf[$off+21] as u32) << 16 |
                  ($buf[$off+22] as u32) << 8  | ($buf[$off+23] as u32);
        let w06 = ($buf[$off+24] as u32) << 24 | ($buf[$off+25] as u32) << 16 |
                  ($buf[$off+26] as u32) << 8  | ($buf[$off+27] as u32);
        let w07 = ($buf[$off+28] as u32) << 24 | ($buf[$off+29] as u32) << 16 |
                  ($buf[$off+30] as u32) << 8  | ($buf[$off+31] as u32);
        let w08 = ($buf[$off+32] as u32) << 24 | ($buf[$off+33] as u32) << 16 |
                  ($buf[$off+34] as u32) << 8  | ($buf[$off+35] as u32);
        let w09 = ($buf[$off+36] as u32) << 24 | ($buf[$off+37] as u32) << 16 |
                  ($buf[$off+38] as u32) << 8  | ($buf[$off+39] as u32);
        let w10 = ($buf[$off+40] as u32) << 24 | ($buf[$off+41] as u32) << 16 |
                  ($buf[$off+42] as u32) << 8  | ($buf[$off+43] as u32);
        let w11 = ($buf[$off+44] as u32) << 24 | ($buf[$off+45] as u32) << 16 |
                  ($buf[$off+46] as u32) << 8  | ($buf[$off+47] as u32);
        let w12 = ($buf[$off+48] as u32) << 24 | ($buf[$off+49] as u32) << 16 |
                  ($buf[$off+50] as u32) << 8  | ($buf[$off+51] as u32);
        let w13 = ($buf[$off+52] as u32) << 24 | ($buf[$off+53] as u32) << 16 |
                  ($buf[$off+54] as u32) << 8  | ($buf[$off+55] as u32);
        let w14 = ($buf[$off+56] as u32) << 24 | ($buf[$off+57] as u32) << 16 |
                  ($buf[$off+58] as u32) << 8  | ($buf[$off+59] as u32);
        let w15 = ($buf[$off+60] as u32) << 24 | ($buf[$off+61] as u32) << 16 |
                  ($buf[$off+62] as u32) << 8  | ($buf[$off+63] as u32);
        $self.process(w00, w01, w02, w03, w04, w05, w06, w07,
                      w08, w09, w10, w11, w12, w13, w14, w15);
    }};
}



// Calculate the value `k` used in the padding for all the hashes, solving the
// equation (l + 1 + k) mod b = a.
pub fn calculate_k(a: usize, b: usize, l: usize) -> usize
{
    (a - (l + 1)) % b
}

#[cfg(test)]
quickcheck!
{
    fn maj_rewrite_ok(x: u64, y: u64, z: u64) -> bool
    {
        let orig = (x & y) ^ (x & z) ^ (y & z);
        maj!(x, y, z) == orig
    }

    // Note, these two laws hold because we hash with bytes as the atomic size,
    // not bits. If we hashed true bit streams, we'd be in trouble.
    fn sha1_k_plus_1_multiple_of_8(lbytes: usize) -> bool
    {
        let l = lbytes * 8;
        (calculate_k(448,512,l) + 1) % 8 == 0
    }

    // Note, these two laws hold because we hash with bytes as the atomic size,
    // not bits. If we hashed true bit streams, we'd be in trouble.
    fn sha2_k_plus_1_multiple_of_8(lbytes: usize) -> bool
    {
        let l = lbytes * 8;
        (calculate_k(896,1024,l) + 1) % 8 == 0
    }
}

