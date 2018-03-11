use cryptonum::signed::Signed;
use cryptonum::traits::*;
use std::ops::*;

pub fn modinv<'a,T>(e: &T, phi: &T) -> T
  where
   T: Clone + CryptoNumBase + Ord,
   T: AddAssign + SubAssign + MulAssign + DivAssign,
   T: Add<Output=T> + Sub<Output=T> + Mul<Output=T> + Div<Output=T>,
   &'a T: Sub<Output=T>,
   T: 'a
{
    let (_, mut x, _) = extended_euclidean(e, phi);
    let int_phi = Signed::<T>::new(phi.clone());
    while x.is_negative() {
        x += &int_phi;
    }
    x.abs()
}

pub fn modexp<T>(b: &T, e: &T, m: &T) -> T
{
    panic!("modexp")
}

pub fn extended_euclidean<T>(a: &T, b: &T) -> (Signed<T>, Signed<T>, Signed<T>)
  where
    T: Clone + CryptoNumBase + Div + Mul + Sub
{
    let posinta = Signed::<T>::new(a.clone());
    let posintb = Signed::<T>::new(b.clone());
    let (mut d, mut x, mut y) = egcd(&posinta, &posintb);

    if d.is_negative() {
        d.negate();
        x.negate();
        y.negate();
    }

    (d, x, y)
}

pub fn egcd<T>(a: &Signed<T>, b: &Signed<T>) -> (Signed<T>,Signed<T>,Signed<T>)
  where
    T: Clone + CryptoNumBase + Div + Mul + Sub
{
    let mut s         = Signed::<T>::zero();
    let mut old_s     = Signed::<T>::from_u8(1);
    let mut t         = Signed::<T>::from_u8(1);
    let mut old_t     = Signed::<T>::zero();
    let mut r         = b.clone();
    let mut old_r     = a.clone();

    while !r.is_zero() {
        let quotient = old_r.clone() / r.clone();

        let prov_r = r.clone();
        let prov_s = s.clone();
        let prov_t = t.clone();

        r = old_r - (r * &quotient);
        s = old_s - (s * &quotient);
        t = old_t - (t * &quotient);

        old_r = prov_r;
        old_s = prov_s;
        old_t = prov_t;
    }

    (old_r, old_s, old_t)
}
