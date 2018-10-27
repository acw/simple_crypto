use cryptonum::addition::UnsafeAdd;
use cryptonum::basetypes::*;
use cryptonum::encoding::Decoder;
use std::fmt;
use std::cmp::{Ord,Ordering};
use std::ops::{Add,Shl,ShrAssign,Sub,SubAssign};

pub struct Signed<T> {
    pub(crate) negative: bool,
    pub(crate) value:    T
}

impl<T> Signed<T> {
    pub fn new(negative: bool, value: T) -> Signed<T> {
        Signed{ negative: negative, value: value }
    }
}

impl<T: Clone> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Signed{ negative: self.negative, value: self.value.clone() }
    }
}

impl<T: CryptoNum> CryptoNum for Signed<T> {
    fn zero() -> Signed<T> {
        Signed::new(false, T::zero())
    }
    fn is_odd(&self) -> bool {
        self.value.is_odd()
    }
    fn is_even(&self) -> bool {
        self.value.is_even()
    }
    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

impl<T: Decoder> Decoder for Signed<T> {
    fn from_bytes(x: &[u8]) -> Signed<T> {
        let x: T = T::from_bytes(x);
        Signed{ negative: false, value: x }
    }
}

impl<T: fmt::Debug> fmt::Debug for  Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.negative {
            write!(f, "NEGATIVE:")?;
        } else {
            write!(f, "POSITIVE:")?;
        }
        self.value.fmt(f)
    }
}

impl<T: fmt::UpperHex> fmt::UpperHex for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.negative {
            write!(f, "-")?;
        }
        self.value.fmt(f)
    }
}

impl<T: fmt::LowerHex> fmt::LowerHex for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.negative {
            write!(f, "-")?;
        }
        self.value.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for Signed<T> {
    fn eq(&self, other: &Signed<T>) -> bool {
        (self.negative == other.negative) && (self.value == other.value)
    }
}

impl<T: Eq> Eq for Signed<T> {}

impl<T> ShrAssign<usize> for Signed<T>
 where
  T: ShrAssign<usize> + UnsafeAdd + CryptoNum + From<u64> + Clone + fmt::UpperHex,
  T: Shl<usize,Output=T> + PartialEq
{
    fn shr_assign(&mut self, rhs: usize) {
        // arithmatic right shift is normal right shift, but always rounding
        // to negative infinity. To implement this, we first shift right by
        // rhs bits, and then shift that value back left rhs bits. If the two
        // are the same, we just cleared out even bits, and there's no rounding
        // to worry about. If they aren't the same, then we add one back.
        let original = self.value.clone();
        self.value.shr_assign(rhs);
        if self.negative {
            let review = self.value.clone() << rhs;
            if review != original {
                self.value = self.value.clone().unsafe_add(&T::from(1u64));
            } 
        }
    }
}

impl<T> UnsafeAdd for Signed<T>
 where
  T: UnsafeAdd + SubAssign + Sub<Output=T>,
  T: PartialOrd + Ord,
  T: Clone
{
    fn unsafe_add(mut self, rhs: &Signed<T>) -> Signed<T> {
        if self.negative == rhs.negative {
            Signed{
                negative: self.negative,
                value: self.value.unsafe_add(&rhs.value)
            }
        } else {
            if self.value > rhs.value {
                self.value -= rhs.value.clone();
            } else {
                self.value = rhs.value.clone() - self.value.clone();
                self.negative = rhs.negative;
            }
            self
        }
    }
}

impl<'a,'b,T,U> Add<&'a Signed<T>> for &'b Signed<T>
  where
    &'a T: Add<&'b T,Output=U> + Sub<&'b T,Output=T>,
    T: PartialOrd + Ord,
    T: Clone,
    U: From<T>
{
    type Output = Signed<U>;

    fn add(self, rhs: &Signed<T>) -> Signed<U> {
        if self.negative == rhs.negative {
            Signed {
                negative: self.negative,
                value: &self.value + &rhs.value
            }
        } else {
            if self.value > rhs.value {
                Signed {
                    negative: self.negative,
                    value: U::from(&self.value - &rhs.value)
                }
            } else {
                Signed {
                    negative: rhs.negative,
                    value: U::from(&rhs.value - &self.value)
                }
            }
        }
    }
}

impl<'a,T> SubAssign<&'a Signed<T>> for Signed<T>
 where
  T: SubAssign<T>,
  T: Sub<T,Output=T>,
  T: UnsafeAdd,
  T: PartialOrd,
  T: Clone
{
    fn sub_assign(&mut self, rhs: &Signed<T>) {
        if self.negative == rhs.negative {
            if &self.value >= &rhs.value {
                self.value -= rhs.value.clone();
            } else {
                self.value = rhs.value.clone() - self.value.clone();
                self.negative = !self.negative;
            }
        } else {
            self.value = rhs.value.clone().unsafe_add(&self.value);
        }
    }
}

impl<T: Ord + PartialOrd> PartialOrd for Signed<T> {
    fn partial_cmp(&self, other: &Signed<T>) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl<T: Ord + PartialOrd> Ord for Signed<T> {
    fn cmp(&self, other: &Signed<T>) -> Ordering {
        match (self.negative, other.negative) {
            (false, false) => self.value.cmp(&other.value),
            (true,  false) => Ordering::Greater,
            (false, true)  => Ordering::Less,
            (true,  true)  => self.value.cmp(&other.value).reverse()
        }
    }
}

impl<T> Shl<usize> for Signed<T>
 where T: Shl<usize,Output=T>
{
    type Output = Signed<T>;

    fn shl(mut self, amt: usize) -> Signed<T> {
        self.value = self.value << amt;
        self
    }
}

macro_rules! generate_tests {
    ( $( $name:ident ),* ) => {
        #[cfg(test)]
        mod shr {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/sigshr{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (nega, abytes) = case.get("a").unwrap();
                        let (negb, bbytes) = case.get("b").unwrap();
                        let (negx, xbytes) = case.get("x").unwrap();

                        assert!(!negb);
                        let     ua = $name::from_bytes(abytes);
                        let     b  = $name::from_bytes(bbytes);
                        let     ux = $name::from_bytes(xbytes);
                        let mut a  = Signed::new(*nega, ua);
                        let     x  = Signed::new(*negx, ux);

                        a >>= usize::from(b);
                        assert_eq!(a, x);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod add {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/sigadd{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (nega, abytes) = case.get("a").unwrap();
                        let (negb, bbytes) = case.get("b").unwrap();
                        let (negx, xbytes) = case.get("x").unwrap();

                        let ua = $name::from_bytes(abytes);
                        let ub = $name::from_bytes(bbytes);
                        let ux = $name::from_bytes(xbytes);
                        let a  = Signed::new(*nega, ua);
                        let b  = Signed::new(*negb, ub);
                        let x  = Signed::new(*negx, ux);

                        let    res = a.unsafe_add(&b);
                        assert_eq!(res, x);
                    });
                }
            )*
        }

        #[cfg(test)]
        mod sub {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;

            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    let fname = format!("tests/math/sigsub{}.test",
                                        stringify!($name));
                    run_test(fname.to_string(), 3, |case| {
                        let (nega, abytes) = case.get("a").unwrap();
                        let (negb, bbytes) = case.get("b").unwrap();
                        let (negx, xbytes) = case.get("x").unwrap();

                        let     ua = $name::from_bytes(abytes);
                        let     ub = $name::from_bytes(bbytes);
                        let     ux = $name::from_bytes(xbytes);
                        let mut a  = Signed::new(*nega, ua);
                        let     b  = Signed::new(*negb, ub);
                        let     b2 = b.clone();
                        let     x  = Signed::new(*negx, ux);

                        a -= &b2;
                        assert_eq!(a, x);
                        assert_eq!(b, b2);
                    });
                }
            )*
        }
    }
}

generate_tests!(U192,  U256,  U384,  U512,  U1024,
                U2048, U3072, U4096, U8192, U15360);
