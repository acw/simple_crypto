use cryptonum::unsigned::{UCN,divmod};
use std::fmt;
use std::cmp::Ordering;
use std::fmt::Write;
use std::ops::*;

/// In case you were wondering, it stands for "Signed Crypto Num".
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SCN {
    negative: bool,
    value: UCN
}

impl SCN {
    pub fn zero() -> SCN {
        SCN{ negative: false, value: UCN::zero() }
    }

    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
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
        if self.negative {
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
    use std::fs::File;
    use std::io::Read;
    use super::*;

    fn gold_test<F>(name: &str, f: F)
     where
      F: Fn(SCN,SCN) -> SCN
    {
        let mut file = File::open(name).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut iter = contents.lines();

        while let Some(xstr) = iter.next() {
            let ystr = iter.next().unwrap();
            let zstr = iter.next().unwrap();

            assert!(xstr.starts_with("x: "));
            assert!(ystr.starts_with("y: "));
            assert!(zstr.starts_with("z: "));
            let x = SCN::from_str(&xstr[3..]);
            let y = SCN::from_str(&ystr[3..]);
            let z = SCN::from_str(&zstr[3..]);
            assert_eq!(f(x,y), z);
        }
    }

    #[test]
    fn add_tests() {
        gold_test("tests/add_tests_signed.txt", |x,y| x + y);
    }

    #[test]
    fn sub_tests() {
        gold_test("tests/sub_tests_signed.txt", |x,y| x - y);
    }

    #[test]
    fn mul_tests() {
        gold_test("tests/mul_tests_signed.txt", |x,y| x * y);
    }

    #[test]
    fn div_tests() {
        gold_test("tests/div_tests_signed.txt", |x,y| x / y);
    }

    #[test]
    fn mod_tests() {
        gold_test("tests/mod_tests_signed.txt", |x,y| x % y);
    }
}
