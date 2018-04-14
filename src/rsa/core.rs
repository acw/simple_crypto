use cryptonum::{BarrettUCN,UCN};
use rand::Rng;

pub static ACCEPTABLE_KEY_SIZES: [(usize,usize); 8] =
    [(512,   7),
     (1024,  7),
     (2048,  4),
     (3072,  3),
     (4096,  3),
     (7680,  3),
     (8192,  3),
     (15360, 3)];

fn iterations_for_size(l: usize) -> usize {
    for &(m, i) in ACCEPTABLE_KEY_SIZES.iter() {
        if m == l {
            return i;
        }
    }
    panic!("Bad key size, can't get M-R iterations")
}

pub fn generate_pq<G: Rng>(rng: &mut G, e: &UCN, bitlen: usize) -> (UCN, UCN) {
    let iterations = iterations_for_size(bitlen);
    let sqrt2 = UCN::from(6074001000 as u64);
    let topbit = UCN::from(1 as u64) << ((bitlen / 2) - 1);
    let minval = sqrt2 << ((bitlen / 2) - 33);
    let mindiff = UCN::from(1 as u64) << ((bitlen / 2) - 101);
    let validate = |inval| {
                       let x = &inval | &topbit;
                       if x < minval {
                           return None
                       }
                       if !gcd_is_one(&e, &x) {
                           return None
                       }
                       Some(x)
                   };

    let p = UCN::generate_prime(rng, bitlen / 2, iterations, validate);
    loop {
        let q = UCN::generate_prime(rng, bitlen / 2, iterations, validate);

        if diff(&p, &q) >= mindiff {
            return (p, q);
        }
    }
}

fn diff(a: &UCN, b: &UCN) -> UCN {
    if a > b {
        a - b
    } else {
        b - a
    }
}

fn gcd_is_one(a: &UCN, b: &UCN) -> bool {
    let mut u = a.clone();
    let mut v = b.clone();

    if u.is_zero() {
        return v == UCN::from(1 as u8);
    }

    if v.is_zero() {
        return u == UCN::from(1 as u8);
    }

    if u.is_even() && v.is_even() {
        return false;
    }

    while u.is_even() {
        u >>= 1;
    }

    loop {
        while v.is_even() {
            v >>= 1;
        }
        // u and v guaranteed to be odd right now.
        if u > v {
            // make sure that v > u, so that our subtraction works
            // out.
            let t = u;
            u = v;
            v = t;
        }
        v = v - &u;

        if v.is_zero() {
            return u == UCN::from(1 as u64);
        }
    }
}


// the RSA encryption function
pub fn ep(nu: &BarrettUCN, e: &UCN, m: &UCN) -> UCN {
    m.fastmodexp(e, nu)
}

// the RSA decryption function
pub fn dp(nu: &BarrettUCN, d: &UCN, c: &UCN) -> UCN {
    c.fastmodexp(d, nu)
}

// the RSA signature generation function
pub fn sp1(nu: &BarrettUCN, d: &UCN, m: &UCN) -> UCN {
    m.fastmodexp(d, nu)
}

// the RSA signature verification function
pub fn vp1(nu: &BarrettUCN, e: &UCN, s: &UCN) -> UCN {
    s.fastmodexp(e, nu)
}

// encoding PKCS1 stuff
pub fn pkcs1_pad(ident: &[u8], hash: &[u8], keylen: usize) -> Vec<u8> {
    let mut idhash = Vec::new();
    idhash.extend_from_slice(ident);
    idhash.extend_from_slice(hash);
    let tlen = idhash.len();
    assert!(keylen > (tlen + 3));
    let mut padding = Vec::new();
    padding.resize(keylen - tlen - 3, 0xFF);
    let mut result = vec![0x00, 0x01];
    result.append(&mut padding);
    result.push(0x00);
    result.append(&mut idhash);
    result
}


#[cfg(test)]
mod tests {
    use rand::OsRng;
    use super::*;

    #[test]
    fn can_get_p_and_q() {
        let mut rng = OsRng::new().unwrap();
        let e = UCN::from(65537 as u64);

        for &(size, _) in ACCEPTABLE_KEY_SIZES.iter().take(3) {
            let (p,q) = generate_pq(&mut rng, &e, size);
            let minval = UCN::from(1 as u8) << ((size / 2) - 1);
            assert!(p > minval);
            assert!(q > minval);
            assert!(p != q);
            assert!(p.is_odd());
            assert!(q.is_odd());
            let phi = (p - UCN::from(1 as u64)) * (q - UCN::from(1 as u64));
            let d = e.modinv(&phi);
            assert_eq!( (&e * &d) % phi, UCN::from(1 as u64) );
        }
    }
}
