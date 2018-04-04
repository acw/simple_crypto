#[macro_use]
mod conversions;
#[macro_use]
mod complete_arith;
mod signed;
mod unsigned;

pub use self::signed::SCN;
pub use self::unsigned::UCN;

use std::ops::Neg;

pub fn modinv(e: &UCN, phi: &UCN) -> UCN {
    let (_, mut x, _) = extended_euclidean(&e, &phi);
    let int_phi = SCN::from(phi.clone());
    while x.is_negative() {
        x = x + &int_phi;
    }
    x.into()
}

fn extended_euclidean(a: &UCN, b: &UCN) -> (SCN, SCN, SCN) {
    let posinta = SCN::from(a.clone());
    let posintb = SCN::from(b.clone());
    let (d, x, y) = egcd(posinta, posintb);

    if d.is_negative() {
        (d.neg(), x.neg(), y.neg())
    } else {
        (d, x, y)
    }
}

fn egcd(a: SCN, b: SCN) -> (SCN, SCN, SCN) {
    let mut s     = SCN::zero();
    let mut old_s = SCN::from(1 as u8);
    let mut t     = SCN::from(1 as u8);
    let mut old_t = SCN::zero();
    let mut r     = b;
    let mut old_r = a;

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

