use cryptonum::unsigned::{UCN,divmod};
use std::fmt;
use std::cmp::Ordering;
use std::fmt::Write;
use std::ops::*;

/// In case you were wondering, it stands for "Signed Crypto Num".
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SCN {
    pub(crate) negative: bool,
    pub(crate) value: UCN
}

impl SCN {
    pub fn zero() -> SCN {
        SCN{ negative: false, value: UCN::zero() }
    }

    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }

    pub fn from_str(x: &str) -> SCN {
        if x.get(0..1) == Some("-") {
            SCN{ negative: true, value: UCN::from_str(&x[1..]) }
        } else {
            SCN{ negative: false, value: UCN::from_str(x) }
        }
    }

    fn cleanup(&mut self) {
        if self.value.is_zero() {
            self.negative = false;
        }
    }

    pub fn egcd(self, b: SCN) -> (SCN, SCN, SCN) {
        let mut s     = SCN::zero();
        let mut old_s = SCN::from(1 as u8);
        let mut t     = SCN::from(1 as u8);
        let mut old_t = SCN::zero();
        let mut r     = b;
        let mut old_r = self;

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
}

impl fmt::UpperHex for SCN {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(),fmt::Error> {
        if self.negative {
            fmt.write_char('-')?;
        }
        self.value.fmt(fmt)
    }
}

//------------------------------------------------------------------------------
//
//  Conversions to/from crypto nums.
//
//------------------------------------------------------------------------------

define_signed_from!(SCN, i8,  u8);
define_signed_from!(SCN, i16, u16);
define_signed_from!(SCN, i32, u32);
define_signed_from!(SCN, i64, u64);
define_signed_into!(SCN, i8,  u8);
define_signed_into!(SCN, i16, u16);
define_signed_into!(SCN, i32, u32);
define_signed_into!(SCN, i64, u64);

impl From<UCN> for SCN {
    fn from(x: UCN) -> SCN {
        SCN{ negative: false, value: x }
    }
}

impl Into<UCN> for SCN {
    fn into(self) -> UCN {
        self.value
    }
}

//------------------------------------------------------------------------------
//
//  Comparisons
//
//------------------------------------------------------------------------------

impl PartialOrd for SCN {
    fn partial_cmp(&self, other: &SCN) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SCN {
    fn cmp(&self, other: &SCN) -> Ordering {
        match (self.negative, other.negative) {
            (false, false) => self.value.cmp(&other.value),
            (false, true)  => Ordering::Greater,
            (true,  false) => Ordering::Less,
            (true,  true)  => self.value.cmp(&other.value).reverse()
        }
    }
}

//------------------------------------------------------------------------------
//
//  Arithmetic
//
//------------------------------------------------------------------------------

impl Neg for SCN {
    type Output = SCN;

    fn neg(self) -> SCN {
        if self.is_zero() {
            self
        } else {
            SCN{ negative: !self.negative, value: self.value }
        }
    }
}

impl<'a> Neg for &'a SCN {
    type Output = SCN;

    fn neg(self) -> SCN {
        if self.is_zero() {
            self.clone()
        } else {
            SCN{ negative: !self.negative, value: self.value.clone() }
        }
    }
}

impl<'a> AddAssign<&'a SCN> for SCN {
    fn add_assign(&mut self, rhs: &SCN) {
        if self.negative == rhs.negative {
            self.value.add_assign(&rhs.value);
        } else {
            if self.value >= rhs.value {
                self.value.sub_assign(&rhs.value);
            } else {
                self.negative = !self.negative;
                self.value = &rhs.value - &self.value;
            }
        }
        self.cleanup();
    }
}

impl<'a> SubAssign<&'a SCN> for SCN {
    fn sub_assign(&mut self, rhs: &SCN) {
        let flipped = SCN{ negative: !rhs.negative, value: rhs.value.clone() };
        self.add_assign(&flipped);
        self.cleanup();
    }
}

impl<'a> MulAssign<&'a SCN> for SCN {
    fn mul_assign(&mut self, rhs: &SCN) {
        self.negative ^= rhs.negative;
        self.value.mul_assign(&rhs.value);
        self.cleanup();
    }
}

impl<'a> DivAssign<&'a SCN> for SCN {
    fn div_assign(&mut self, rhs: &SCN) {
        self.negative ^= rhs.negative;
        // rounding makes me grumpy
        let mut remainder = Vec::new();
        let copy = self.value.contents.clone();
        divmod(&mut self.value.contents, &mut remainder,
               &copy, &rhs.value.contents);
        if self.negative && !remainder.is_empty() {
            let one = UCN{ contents: vec![1] };
            self.sub_assign(SCN{ negative: false, value: one});
        }
        self.cleanup();
    }
}

impl<'a> RemAssign<&'a SCN> for SCN {
    fn rem_assign(&mut self, rhs: &SCN) {
        let base = &self.value % &rhs.value;

        if self.negative == rhs.negative {
            self.value = base;
        } else {
            self.negative = rhs.negative;
            self.value = &rhs.value - &base;
        }
        self.cleanup();
    }
}

derive_arithmetic_operators!(SCN, Add, add, AddAssign, add_assign);
derive_arithmetic_operators!(SCN, Sub, sub, SubAssign, sub_assign);
derive_arithmetic_operators!(SCN, Mul, mul, MulAssign, mul_assign);
derive_arithmetic_operators!(SCN, Div, div, DivAssign, div_assign);
derive_arithmetic_operators!(SCN, Rem, rem, RemAssign, rem_assign);

//------------------------------------------------------------------------------
//
//  Tests!
//
//------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    impl Arbitrary for SCN {
        fn arbitrary<G: Gen>(g: &mut G) -> SCN {
            let neg = (g.next_u32() & 1) == 1;
            SCN{ negative: neg, value: UCN::arbitrary(g) }
        }
    }

    fn one() -> SCN {
        SCN{ negative: false, value: UCN::from(1 as u8) }
    }

    quickcheck! {
        fn additive_identity(x: SCN) -> bool {
            (&x + &SCN::zero()) == x
        }
        fn subtractive_identity(x: SCN) -> bool {
            (&x - &SCN::zero()) == x
        }
        fn multiplicative_identity(x: SCN) -> bool {
            (&x * &one()) == x
        }
        fn division_identity(x: SCN) -> bool {
            let result = &x / &one();
            result == x
        }

        fn additive_destructor(x: SCN) -> bool {
            (&x + (- &x)) == SCN::zero()
        }
        fn subtractive_destructor(x: SCN) -> bool {
            (&x - &x) == SCN::zero()
        }
        fn multiplicative_destructor(x: SCN) -> bool {
            (x * SCN::zero()) == SCN::zero()
        }
        fn division_deastructor(x: SCN) -> bool {
            (&x / &x) == one()
        }
        fn remainder_destructor(x: SCN) -> bool {
            (&x % &x) == SCN::zero()
        }

        fn addition_commutes(a: SCN, b: SCN) -> bool {
            (&a + &b) == (&b + &a)
        }
        fn multiplication_commutes(a: SCN, b: SCN) -> bool {
            (&a * &b) == (&b * &a)
        }
        fn addition_associates(a: SCN, b: SCN, c: SCN) -> bool {
            ((&a + &b) + &c) == (&a + (&b + &c))
        }
        fn multiplication_associates(a: SCN, b: SCN, c: SCN) -> bool {
            ((&a * &b) * &c) == (&a * (&b * &c))
        }
        fn distribution_works(a: SCN, b: SCN, c: SCN) -> bool {
            (&a * (&b + &c)) == ((&a * &b) + (&a * &c))
        }

        fn negation_works(a: SCN) -> bool {
            (- &a) == (&a * &SCN{ negative: true, value: UCN::from(1 as u8) })
        }
        fn double_negation_works(a: SCN) -> bool {
            (- (- &a)) == a
        }
        fn negation_commutes(a: SCN, b: SCN) -> bool {
            ((- &a) * &b) == (&a * (- &b))
        }
        fn negation_cancels(a: SCN, b: SCN) -> bool {
            ((- &a) * (- &b)) == (&a * &b)
        }
        fn negation_distributes(a: SCN, b: SCN) -> bool {
            (- (&a + &b)) == ((- &a) + (- &b))
        }
    }

    quickcheck! {
        fn egcd_works(a: SCN, b: SCN) -> bool {
            let (d, x, y) = a.clone().egcd(b.clone());
            ((a * x) + (b * y)) == d
        }
    }
}
