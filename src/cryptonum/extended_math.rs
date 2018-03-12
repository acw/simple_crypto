use cryptonum::traits::*;
use std::ops::*;

pub fn modinv<S,U>(e: &U, phi: &U) -> U
  where
    S: Clone + CryptoNumBase + CryptoNumSigned<Unsigned=U>,
    S: Div<Output=S> + Mul<Output=S> + Neg<Output=S> + Sub<Output=S>,
    S: AddAssign,
    U: Clone
{
    let (_, mut x, _): (S, S, S) = extended_euclidean(e, phi);
    let int_phi: S = S::new(phi.clone());
    while x.is_negative() {
        // FIXME: Unnecessary clone
        x += int_phi.clone();
    }
    x.abs()
}

pub fn modexp<T>(b: &T, e: &T, m: &T) -> T
{
    panic!("modexp")
}

pub fn extended_euclidean<U,S>(a: &U, b: &U) -> (S, S, S)
  where
    S: Clone + CryptoNumBase + CryptoNumSigned<Unsigned=U>,
    S: Div<Output=S> + Mul<Output=S> + Neg<Output=S> + Sub<Output=S>,
    U: Clone
{
    let posinta = S::new(a.clone());
    let posintb = S::new(b.clone());
    let (mut d, mut x, mut y) = egcd(&posinta, &posintb);

    if d.is_negative() {
        d = -d;
        x = -x;
        y = -y;
    }

    (d, x, y)
}

pub fn egcd<S>(a: &S, b: &S) -> (S, S, S)
  where
    S: Clone + CryptoNumBase,
    S: Div<Output=S> + Mul<Output=S> + Sub<Output=S>,
{
    let mut s: S      = S::zero();
    let mut old_s: S  = S::from_u8(1);
    let mut t: S      = S::from_u8(1);
    let mut old_t: S  = S::zero();
    let mut r: S      = b.clone();
    let mut old_r: S  = a.clone();

    while !r.is_zero() {
        let quotient: S = old_r.clone() / r.clone();

        let prov_r = r.clone();
        let prov_s = s.clone();
        let prov_t = t.clone();

        // FIXME: Unnecessary clones
        r = old_r - (r * quotient.clone());
        s = old_s - (s * quotient.clone());
        t = old_t - (t * quotient.clone());

        old_r = prov_r;
        old_s = prov_s;
        old_t = prov_t;
    }

    (old_r, old_s, old_t)
}
