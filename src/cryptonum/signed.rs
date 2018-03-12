use cryptonum::traits::*;
use cryptonum::unsigned::*;

pub struct I512 {
    negative: bool,
    value: U512
}


//use cryptonum::traits::*;
//use std::cmp::Ordering;
//use std::fmt::{Debug,Error,Formatter};
//use std::ops::*;
//
//pub struct Signed<T: Sized>
//  where T: Clone + CryptoNumBase + Sized
//{
//    positive: bool,
//    value: T
//}
//
//impl<T> Signed<T>
//  where T: Clone + CryptoNumBase + Sized
//{
//    pub fn new(v: T) -> Signed<T> {
//        Signed{ positive: true, value: v }
//    }
//
//    pub fn abs(&self) -> T
//    {
//        self.value.clone()
//    }
//
//    pub fn is_positive(&self) -> bool
//    {
//        self.positive && !self.value.is_zero()
//    }
//
//    pub fn is_negative(&self) -> bool
//    {
//        !self.positive && !self.value.is_zero()
//    }
//
//    pub fn negate(&mut self)
//    {
//        self.positive = !self.positive;
//    }
//}
//
//impl<T> CryptoNumBase for Signed<T>
//  where T: Clone + CryptoNumBase + Sized
//{
//    fn zero() -> Signed<T> {
//        Signed{ positive: true, value: T::zero() }
//    }
//    fn max_value() -> Signed<T> {
//        Signed{ positive: true, value: T::max_value() }
//    }
//    fn is_zero(&self) -> bool {
//        self.value.is_zero()
//    }
//    fn is_odd(&self) -> bool {
//        self.value.is_odd()
//    }
//    fn is_even(&self) -> bool {
//        self.value.is_even()
//    }
//    fn from_u8(x: u8) -> Signed<T> {
//        Signed{ positive: true, value: T::from_u8(x) }
//    }
//    fn to_u8(&self) -> u8 {
//        self.value.to_u8()
//    }
//    fn from_u16(x: u16) -> Signed<T> {
//        Signed{ positive: true, value: T::from_u16(x) }
//    }
//    fn to_u16(&self) -> u16 {
//        self.value.to_u16()
//    }
//    fn from_u32(x: u32) -> Signed<T> {
//        Signed{ positive: true, value: T::from_u32(x) }
//    }
//    fn to_u32(&self) -> u32 {
//        self.value.to_u32()
//    }
//    fn from_u64(x: u64) -> Signed<T> {
//        Signed{ positive: true, value: T::from_u64(x) }
//    }
//    fn to_u64(&self) -> u64 {
//        self.value.to_u64()
//    }
//}
//
//impl<T: CryptoNumFastMod> CryptoNumFastMod for Signed<T> {
//    type BarrettMu = T::BarrettMu;
//
//    fn barrett_mu(&self) -> Option<T::BarrettMu> {
//        if self.positive {
//            self.value.barrett_mu()
//        } else {
//            None
//        }
//    }
//
//    fn fastmod(&self, mu: &T::BarrettMu) -> Signed<T> {
//        Signed{ positive: self.positive, value: self.value.fastmod(&mu) }
//    }
//}
//
//impl<T: Clone> Clone for Signed<T> {
//    fn clone(&self) -> Signed<T> {
//        Signed{ positive: self.positive, value: self.value.clone() }
//    }
//}

//impl<'a,T: PartialEq> PartialEq<&'a Signed<T>> for Signed<T> {
//    fn eq(&self, other: &&Signed<T>) -> bool {
//        (self.positive == other.positive) && (self.value == other.value)
//    }
//}
//
//impl<'a,T: PartialEq> PartialEq<Signed<T>> for &'a Signed<T> {
//    fn eq(&self, other: &Signed<T>) -> bool {
//        (self.positive == other.positive) && (self.value == other.value)
//    }
//}
//
//impl<T: PartialEq> PartialEq for Signed<T> {
//    fn eq(&self, other: &Signed<T>) -> bool {
//        (self.positive == other.positive) && (self.value == other.value)
//    }
//}
//
//impl<T: Eq> Eq for Signed<T> {}
//
//impl<T: Debug> Debug for Signed<T> {
//    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
//        if self.positive {
//            f.write_str("+")?;
//        } else {
//            f.write_str("-")?;
//        }
//        self.value.fmt(f)
//    }
//}
//
//impl<T: Ord> Ord for Signed<T> {
//    fn cmp(&self, other: &Signed<T>) -> Ordering {
//        match (self.positive, other.positive) {
//            (true,  true)  => self.value.cmp(&other.value),
//            (true,  false) => Ordering::Greater,
//            (false, true)  => Ordering::Less,
//            (false, false) =>
//                self.value.cmp(&other.value).reverse()
//        }
//    }
//}
//
//impl<T: Ord> PartialOrd for Signed<T> {
//    fn partial_cmp(&self, other: &Signed<T>) -> Option<Ordering>{
//        Some(self.cmp(other))
//    }
//}
//
////------------------------------------------------------------------------------
//
//impl<T: Clone> Neg for Signed<T> {
//    type Output = Signed<T>;
//
//    fn neg(self) -> Signed<T> {
//        Signed {
//            positive: !self.positive,
//            value: self.value.clone()
//        }
//    }
//}
//
//impl<'a,T: Clone> Neg for &'a Signed<T> {
//    type Output = Signed<T>;
//
//    fn neg(self) -> Signed<T> {
//        Signed {
//            positive: !self.positive,
//            value: self.value.clone()
//        }
//    }
//}
//
////------------------------------------------------------------------------------
//
//impl<T> AddAssign for Signed<T>
//  where
//    T: Clone + Ord,
//    T: AddAssign + SubAssign,
//{
//    fn add_assign(&mut self, other: Signed<T>) {
//        match (self.positive, other.positive, self.value.cmp(&other.value)) {
//            // if the signs are the same, we maintain the sign and just increase
//            // the magnitude
//            (x, y, _) if x == y =>
//                self.value.add_assign(other.value),
//            // if the signs are different and the numbers are equal, we just set
//            // this to zero. However, we actually do the subtraction to make the
//            // timing roughly similar.
//            (_, _, Ordering::Equal) => {
//                self.positive = true;
//                self.value.sub_assign(other.value);
//            }
//            // if the signs are different and the first one is less than the
//            // second, then we flip the sign and subtract.
//            (_, _, Ordering::Less) => {
//                self.positive = !self.positive;
//                let temp = self.value.clone();
//                self.value = other.value.clone();
//                self.value.sub_assign(temp);
//            }
//            // if the signs are different and the first one is greater than the
//            // second, then we leave the sign and subtract.
//            (_, _, Ordering::Greater) => {
//                self.value.sub_assign(other.value);
//            }
//        }
//    }
//}
//
//impl<'a,T> AddAssign<&'a Signed<T>> for Signed<T>
//  where
//    T: Clone + Ord,
//    T: AddAssign + SubAssign,
//    T: AddAssign<&'a T> + SubAssign<&'a T>
//{
//    fn add_assign(&mut self, other: &'a Signed<T>) {
//        match (self.positive, other.positive, self.value.cmp(&other.value)) {
//            // if the signs are the same, we maintain the sign and just increase
//            // the magnitude
//            (x, y, _) if x == y =>
//                self.value.add_assign(&other.value),
//            // if the signs are different and the numbers are equal, we just set
//            // this to zero. However, we actually do the subtraction to make the
//            // timing roughly similar.
//            (_, _, Ordering::Equal) => {
//                self.positive = true;
//                self.value.sub_assign(&other.value);
//            }
//            // if the signs are different and the first one is less than the
//            // second, then we flip the sign and subtract.
//            (_, _, Ordering::Less) => {
//                self.positive = !self.positive;
//                let temp = self.value.clone();
//                self.value = other.value.clone();
//                self.value.sub_assign(temp);
//            }
//            // if the signs are different and the first one is greater than the
//            // second, then we leave the sign and subtract.
//            (_, _, Ordering::Greater) => {
//                self.value.sub_assign(&other.value);
//            }
//        }
//    }
//}
//
//math_operator!(Add,add,add_assign);
//
////------------------------------------------------------------------------------
//
//impl<T> SubAssign for Signed<T>
//  where
//    T: Clone + Ord,
//    T: AddAssign + SubAssign,
//{
//    fn sub_assign(&mut self, other: Signed<T>) {
//        let mut other2 = other.clone();
//        other2.positive = !other.positive;
//        self.add_assign(other2);
//    }
//}
//
//impl<'a,T> SubAssign<&'a Signed<T>> for Signed<T>
//  where
//    T: Clone + Ord,
//    T: AddAssign + SubAssign,
//    T: AddAssign<&'a T> + SubAssign<&'a T>
//{
//    fn sub_assign(&mut self, other: &'a Signed<T>) {
//        let mut other2 = other.clone();
//        other2.positive = !other.positive;
//        self.add_assign(other2);
//    }
//}
//
//math_operator!(Sub,sub,sub_assign);
//
////------------------------------------------------------------------------------
//
//impl<T> MulAssign for Signed<T>
//  where
//    T: MulAssign
//{
//    fn mul_assign(&mut self, other: Signed<T>) {
//        self.positive  = !(self.positive ^ other.positive);
//        self.value    *= other.value;
//    }
//}
//
//impl<'a,T> MulAssign<&'a Signed<T>> for Signed<T>
//  where
//    T: MulAssign + MulAssign<&'a T>
//{
//    fn mul_assign(&mut self, other: &'a Signed<T>) {
//        self.positive  = !(self.positive ^ other.positive);
//        self.value    *= &other.value;
//    }
//}
//
//math_operator!(Mul,mul,mul_assign);
//
////------------------------------------------------------------------------------
//
//impl<T> DivAssign for Signed<T>
//  where
//    T: DivAssign
//{
//    fn div_assign(&mut self, other: Signed<T>) {
//        self.positive  = !(self.positive ^ other.positive);
//        self.value    /= other.value;
//    }
//}
//
//impl<'a,T> DivAssign<&'a Signed<T>> for Signed<T>
//  where
//    T: DivAssign + DivAssign<&'a T>
//{
//    fn div_assign(&mut self, other: &'a Signed<T>) {
//        self.positive  = !(self.positive ^ other.positive);
//        self.value    /= &other.value;
//    }
//}
//
//math_operator!(Div,div,div_assign);
//
////------------------------------------------------------------------------------
//
//#[cfg(test)]
//mod tests {
//    use cryptonum::unsigned::U512;
//    use quickcheck::{Arbitrary,Gen};
//    use std::cmp::{max,min};
//    use super::*;
//
//    impl<T: Arbitrary + CryptoNumBase> Arbitrary for Signed<T> {
//        fn arbitrary<G: Gen>(g: &mut G) -> Signed<T> {
//            let value = T::arbitrary(g);
//            if value.is_zero() {
//                Signed {
//                    positive: true,
//                    value: value
//                }
//            } else {
//                Signed {
//                    positive: g.gen_weighted_bool(2),
//                    value: value
//                }
//            }
//        }
//    }
//
//    quickcheck! {
//        fn double_negation(x: Signed<U512>) -> bool {
//            &x == (- (- &x))
//        }
//    }
//
//    quickcheck! {
//        fn add_associates(x: Signed<U512>, y: Signed<U512>, z: Signed<U512>)
//            -> bool
//        {
//            let mut a = x.clone();
//            let mut b = y.clone();
//            let mut c = z.clone();
//
//            // we shift these right because rollover makes for weird behavior
//            a.value >>= 2;
//            b.value >>= 2;
//            c.value >>= 2;
//
//            (&a + (&b + &c)) == ((&a + &b) + &c)
//        }
//        fn add_commutes(x: Signed<U512>, y: Signed<U512>) -> bool {
//            (&x + &y) == (&y + &x)
//        }
//        fn add_identity(x: Signed<U512>) -> bool {
//            let zero = Signed{ positive: true, value: U512::zero() };
//            (&x + &zero) == &x
//        }
//    }
//
//    quickcheck! {
//        fn sub_is_add_negation(x: Signed<U512>, y: Signed<U512>) -> bool {
//            (&x - &y) == (&x + (- &y))
//        }
//    }
//
//    quickcheck! {
//        fn mul_associates(x: Signed<U512>, y: Signed<U512>, z: Signed<U512>)
//            -> bool
//        {
//            let mut a = x.clone();
//            let mut b = y.clone();
//            let mut c = z.clone();
//
//            // we shift these right because rollover makes for weird behavior
//            a.value >>= 258;
//            b.value >>= 258;
//            c.value >>= 258;
//
//            (&a * (&b * &c)) == ((&a * &b) * &c)
//        }
//        fn mul_commutes(x: Signed<U512>, y: Signed<U512>) -> bool {
//            (&x * &y) == (&y * &x)
//        }
//        fn mul_identity(x: Signed<U512>) -> bool {
//            let one = Signed{ positive: true, value: U512::from_u8(1) };
//            (&x * &one) == &x
//        }
//    }
//
//    quickcheck! {
//        fn add_mul_distribution(x:Signed<U512>,y:Signed<U512>,z:Signed<U512>)
//            -> bool
//        {
//            let mut a = x.clone();
//            let mut b = y.clone();
//            let mut c = z.clone();
//
//            // we shift these right because rollover makes for weird behavior
//            a.value >>= 258;
//            b.value >>= 258;
//            c.value >>= 258;
//
//            (&a * (&b + &c)) == ((&a * &b) + (&a * &c))
//        }
//    }
//}
