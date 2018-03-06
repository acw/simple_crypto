//! # Simple-Crypto CryptoNum
//!
//! This module is designed to provide large, fixed-width number support for
//! the rest of the Simple-Crypto libraries. Feel free to use it other places,
//! of course, but that's its origin.

mod core;
mod traits;

use self::core::*;
use self::traits::*;
use std::cmp::Ordering;
use std::ops::*;

/// A 512-bit unsigned value
#[derive(PartialEq,Eq,Debug,Clone)]
pub struct U512 {
    contents: [u64; 8]
}

impl U512 {
    /// 0!
    pub fn zero() -> U512 {
        U512 {
            contents: [0, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// The maximum possible value: 2^512 - 1.
    pub fn max() -> U512 {
        U512 {
            contents: [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                       0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                       0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                       0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
        }
    }

    /// Convert a `u8` to a `U512`. This is always safe.
    pub fn from_u8(x: u8) -> U512 {
        U512 {
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// Convert a U512 into a `u8`. This should be the equivalent of masking
    /// the U512 with `0xFF` and then converting to a `u8`.
    pub fn to_u8(&self) -> u8 {
        self.contents[0] as u8
    }

    /// Convert a `u16` to a `U512`. This is always safe.
    pub fn from_u16(x: u16) -> U512 {
        U512 {
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// Convert a U512 into a `u16`. This should be the equivalent of masking
    /// the U512 with `0xFFFF` and then converting to a `u16`.
    pub fn to_u16(&self) -> u16 {
        self.contents[0] as u16
    }

    /// Convert a `u32` to a `U512`. This is always safe.
    pub fn from_u32(x: u32) -> U512 {
        U512 {
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// Convert a U512 into a `u32`. This should be the equivalent of masking
    /// the U512 with `0xFFFFFFFF` and then converting to a `u32`.
    pub fn to_u32(&self) -> u32 {
        self.contents[0] as u32
    }

    /// Convert a `u64` to a `U512`. This is always safe.
    pub fn from_u64(x: u64) -> U512 {
        U512 {
            contents: [x, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// Convert a U512 into a `u64`. This should be the equivalent of masking
    /// the U512 with `0xFFFFFFFFFFFFFFFF` and then converting to a `u64`.
    pub fn to_u64(&self) -> u64 {
        self.contents[0]
    }
}

//------------------------------------------------------------------------------

impl PartialOrd for U512 {
    fn partial_cmp(&self, other: &U512) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U512 {
    fn cmp(&self, other: &U512) -> Ordering {
        generic_cmp(&self.contents, &other.contents)
    }
}

//------------------------------------------------------------------------------

impl BitOrAssign for U512 {
    fn bitor_assign(&mut self, other: U512) {
        self.bitor_assign(&other)
    }
}

impl<'a> BitOrAssign<&'a U512> for U512 {
    fn bitor_assign(&mut self, other: &U512) {
        generic_bitor(&mut self.contents, &other.contents)
    }
}

impl BitOr for U512 {
    type Output = U512;

    fn bitor(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy |= rhs;
        copy
    }
}

impl<'a> BitOr<&'a U512> for U512 {
    type Output = U512;

    fn bitor(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy |= rhs;
        copy
    }
}

impl<'a> BitOr<U512> for &'a U512 {
    type Output = U512;

    fn bitor(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy |= rhs;
        copy
    }
}

impl<'a> BitOr<&'a U512> for &'a U512 {
    type Output = U512;

    fn bitor(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy |= rhs;
        copy
    }
}

//------------------------------------------------------------------------------

impl Not for U512 {
    type Output = U512;

    fn not(self) -> U512 {
        !&self
    }
}

impl<'a> Not for &'a U512 {
    type Output = U512;

    fn not(self) -> U512 {
        let mut output = self.clone();
        generic_not(&mut output.contents);
        output
    }
}

//------------------------------------------------------------------------------

impl BitAndAssign for U512 {
    fn bitand_assign(&mut self, other: U512) {
        self.bitand_assign(&other)
    }
}

impl<'a> BitAndAssign<&'a U512> for U512 {
    fn bitand_assign(&mut self, other: &U512) {
        generic_bitand(&mut self.contents, &other.contents)
    }
}

impl BitAnd for U512 {
    type Output = U512;

    fn bitand(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy &= rhs;
        copy
    }
}

impl<'a> BitAnd<&'a U512> for U512 {
    type Output = U512;

    fn bitand(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy &= rhs;
        copy
    }
}

impl<'a> BitAnd<U512> for &'a U512 {
    type Output = U512;

    fn bitand(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy &= rhs;
        copy
    }
}

impl<'a> BitAnd<&'a U512> for &'a U512 {
    type Output = U512;

    fn bitand(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy &= rhs;
        copy
    }
}

//------------------------------------------------------------------------------

impl BitXorAssign for U512 {
    fn bitxor_assign(&mut self, other: U512) {
        self.bitxor_assign(&other)
    }
}

impl<'a> BitXorAssign<&'a U512> for U512 {
    fn bitxor_assign(&mut self, other: &U512) {
        generic_bitxor(&mut self.contents, &other.contents);
    }
}

impl BitXor for U512 {
    type Output = U512;

    fn bitxor(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy ^= rhs;
        copy
    }
}

impl<'a> BitXor<&'a U512> for U512 {
    type Output = U512;

    fn bitxor(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy ^= rhs;
        copy
    }
}

impl<'a> BitXor<U512> for &'a U512 {
    type Output = U512;

    fn bitxor(self, rhs: U512) -> U512 {
        let mut copy = self.clone();
        copy ^= rhs;
        copy
    }
}

impl<'a> BitXor<&'a U512> for &'a U512 {
    type Output = U512;

    fn bitxor(self, rhs: &U512) -> U512 {
        let mut copy = self.clone();
        copy ^= rhs;
        copy
    }
}

//------------------------------------------------------------------------------

impl ShlAssign<usize> for U512 {
    fn shl_assign(&mut self, amount: usize) {
        let copy = self.contents.clone();
        generic_shl(&mut self.contents, &copy, amount);
    }
}

impl Shl<usize> for U512 {
    type Output = U512;

    fn shl(self, rhs: usize) -> U512 {
        let mut copy = self.clone();
        copy <<= rhs;
        copy
    }
}

impl<'a> Shl<usize> for &'a U512 {
    type Output = U512;

    fn shl(self, rhs: usize) -> U512 {
        let mut copy = self.clone();
        copy <<= rhs;
        copy
    }
}

//------------------------------------------------------------------------------

impl ShrAssign<usize> for U512 {
    fn shr_assign(&mut self, amount: usize) {
        let copy = self.contents.clone();
        generic_shr(&mut self.contents, &copy, amount);
    }
}

impl Shr<usize> for U512 {
    type Output = U512;

    fn shr(self, rhs: usize) -> U512 {
        let mut copy = self.clone();
        copy >>= rhs;
        copy
    }
}

impl<'a> Shr<usize> for &'a U512 {
    type Output = U512;

    fn shr(self, rhs: usize) -> U512 {
        let mut copy = self.clone();
        copy >>= rhs;
        copy
    }
}

//------------------------------------------------------------------------------

impl AddAssign<U512> for U512 {
    fn add_assign(&mut self, rhs: U512) {
        self.add_assign(&rhs);
    }
}

impl<'a> AddAssign<&'a U512> for U512 {
    fn add_assign(&mut self, rhs: &U512) {
        generic_add(&mut self.contents, &rhs.contents);
    }
}

impl Add<U512> for U512 {
    type Output = U512;

    fn add(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.add_assign(rhs);
        res
    }
}

impl<'a> Add<U512> for &'a U512 {
    type Output = U512;

    fn add(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.add_assign(rhs);
        res
    }
}

impl<'a> Add<&'a U512> for U512 {
    type Output = U512;

    fn add(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.add_assign(rhs);
        res
    }
}

impl<'a,'b> Add<&'a U512> for &'b U512 {
    type Output = U512;

    fn add(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.add_assign(rhs);
        res
    }
}

//------------------------------------------------------------------------------

impl SubAssign<U512> for U512 {
    fn sub_assign(&mut self, rhs: U512) {
        self.sub_assign(&rhs);
    }
}

impl<'a> SubAssign<&'a U512> for U512 {
    fn sub_assign(&mut self, rhs: &U512) {
        generic_sub(&mut self.contents, &rhs.contents);
    }
}

impl Sub<U512> for U512 {
    type Output = U512;

    fn sub(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.sub_assign(rhs);
        res
    }
}

impl<'a> Sub<U512> for &'a U512 {
    type Output = U512;

    fn sub(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.sub_assign(rhs);
        res
    }
}

impl<'a> Sub<&'a U512> for U512 {
    type Output = U512;

    fn sub(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.sub_assign(rhs);
        res
    }
}

impl<'a,'b> Sub<&'a U512> for &'b U512 {
    type Output = U512;

    fn sub(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.sub_assign(rhs);
        res
    }
}

//------------------------------------------------------------------------------

impl MulAssign<U512> for U512 {
    fn mul_assign(&mut self, rhs: U512) {
        self.mul_assign(&rhs);
    }
}

impl<'a> MulAssign<&'a U512> for U512 {
    fn mul_assign(&mut self, rhs: &U512) {
        let copy = self.contents.clone();
        generic_mul(&mut self.contents, &copy, &rhs.contents);
    }
}

impl Mul<U512> for U512 {
    type Output = U512;

    fn mul(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.mul_assign(rhs);
        res
    }
}

impl<'a> Mul<U512> for &'a U512 {
    type Output = U512;

    fn mul(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.mul_assign(rhs);
        res
    }
}

impl<'a> Mul<&'a U512> for U512 {
    type Output = U512;

    fn mul(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.mul_assign(rhs);
        res
    }
}

impl<'a,'b> Mul<&'a U512> for &'b U512 {
    type Output = U512;

    fn mul(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.mul_assign(rhs);
        res
    }
}

//------------------------------------------------------------------------------

impl CryptoNum for U512 {
    fn divmod(&self, a: &U512, q: &mut U512, r: &mut U512) {
        generic_div(&self.contents,  &a.contents,
                    &mut q.contents, &mut r.contents);
    }
}

//------------------------------------------------------------------------------

impl DivAssign<U512> for U512 {
    fn div_assign(&mut self, rhs: U512) {
        self.div_assign(&rhs);
    }
}

impl<'a> DivAssign<&'a U512> for U512 {
    fn div_assign(&mut self, rhs: &U512) {
        let     copy = self.contents.clone();
        let mut dead = [0; 8];
        generic_div(&copy, &rhs.contents, &mut self.contents, &mut dead);
    }
}

impl Div<U512> for U512 {
    type Output = U512;

    fn div(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.div_assign(rhs);
        res
    }
}

impl<'a> Div<U512> for &'a U512 {
    type Output = U512;

    fn div(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.div_assign(rhs);
        res
    }
}

impl<'a> Div<&'a U512> for U512 {
    type Output = U512;

    fn div(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.div_assign(rhs);
        res
    }
}

impl<'a,'b> Div<&'a U512> for &'b U512 {
    type Output = U512;

    fn div(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.div_assign(rhs);
        res
    }
}

//------------------------------------------------------------------------------

impl RemAssign<U512> for U512 {
    fn rem_assign(&mut self, rhs: U512) {
        self.rem_assign(&rhs);
    }
}

impl<'a> RemAssign<&'a U512> for U512 {
    fn rem_assign(&mut self, rhs: &U512) {
        let     copy = self.contents.clone();
        let mut dead = [0; 8];
        generic_div(&copy, &rhs.contents, &mut dead, &mut self.contents);
    }
}

impl Rem<U512> for U512 {
    type Output = U512;

    fn rem(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.rem_assign(rhs);
        res
    }
}

impl<'a> Rem<U512> for &'a U512 {
    type Output = U512;

    fn rem(self, rhs: U512) -> U512 {
        let mut res = self.clone();
        res.rem_assign(rhs);
        res
    }
}

impl<'a> Rem<&'a U512> for U512 {
    type Output = U512;

    fn rem(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.rem_assign(rhs);
        res
    }
}

impl<'a,'b> Rem<&'a U512> for &'b U512 {
    type Output = U512;

    fn rem(self, rhs: &U512) -> U512 {
        let mut res = self.clone();
        res.rem_assign(rhs);
        res
    }
}

//------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    #[test]
    fn test_builders() {
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,0] },
                   U512::from_u8(0));
        assert_eq!(U512{ contents: [0x7F,0,0,0,0,0,0,0] },
                   U512::from_u8(0x7F));
        assert_eq!(U512{ contents: [0x7F7F,0,0,0,0,0,0,0] },
                   U512::from_u16(0x7F7F));
        assert_eq!(U512{ contents: [0xCA5CADE5,0,0,0,0,0,0,0] },
                   U512::from_u32(0xCA5CADE5));
        assert_eq!(U512{ contents: [0xCA5CADE5,0,0,0,0,0,0,0] },
                   U512::from_u64(0xCA5CADE5));
        assert_eq!(U512{ contents: [0xFFFFFFFFFFFFFFFF,0,0,0,0,0,0,0] },
                   U512::from_u64(0xFFFFFFFFFFFFFFFF));
    }

    #[test]
    fn test_max() {
        assert_eq!(U512::from_u64(u64::max_value()).to_u64(),
                   u64::max_value());
        assert_eq!(U512::max().to_u64(), u64::max_value());
    }

    quickcheck! {
        fn builder_u8_upgrade_u16(x: u8) -> bool {
            U512::from_u8(x) == U512::from_u16(x as u16)
        }
        fn builder_u16_upgrade_u32(x: u16) -> bool {
            U512::from_u16(x) == U512::from_u32(x as u32)
        }
        fn builder_u32_upgrade_u64(x: u32) -> bool {
            U512::from_u32(x) == U512::from_u64(x as u64)
        }
        fn builder_u8_roundtrips(x: u8) -> bool {
            x == U512::from_u8(x).to_u8()
        }
        fn builder_u16_roundtrips(x: u16) -> bool {
            x == U512::from_u16(x).to_u16()
        }
        fn builder_u32_roundtrips(x: u32) -> bool {
            x == U512::from_u32(x).to_u32()
        }
        fn builder_u64_roundtrips(x: u64) -> bool {
            x == U512::from_u64(x).to_u64()
        }
    }

    quickcheck! {
        fn partial_ord64_works(x: u64, y: u64) -> bool {
            let x512 = U512::from_u64(x);
            let y512 = U512::from_u64(y);
            x512.partial_cmp(&y512) == x.partial_cmp(&y)
        }
        fn ord64_works(x: u64, y: u64) -> bool {
            let x512 = U512::from_u64(x);
            let y512 = U512::from_u64(y);
            x512.cmp(&y512) == x.cmp(&y)
        }
    }

    impl Arbitrary for U512 {
        fn arbitrary<G: Gen>(g: &mut G) -> U512 {
            let x1 = g.next_u64();
            let x2 = g.next_u64();
            let x3 = g.next_u64();
            let x4 = g.next_u64();
            let x5 = g.next_u64();
            let x6 = g.next_u64();
            let x7 = g.next_u64();
            let x8 = g.next_u64();
            U512{ contents: [x1, x2, x3, x4, x5, x6, x7, x8] }
        }
    }

    quickcheck! {
        fn and_annulment(x: U512) -> bool {
            (x & U512::zero()) == U512::zero()
        }
        fn or_annulment(x: U512) -> bool {
            (x | U512::max()) == U512::max()
        }
        fn and_identity(x: U512) -> bool {
            (&x & U512::max()) == x
        }
        fn or_identity(x: U512) -> bool {
            (&x | U512::zero()) == x
        }
        fn and_idempotent(x: U512) -> bool {
            (&x & &x) == x
        }
        fn or_idempotent(x: U512) -> bool {
            (&x | &x) == x
        }
        fn and_complement(x: U512) -> bool {
            (&x & &x) == x
        }
        fn or_complement(x: U512) -> bool {
            (&x | !&x) == U512::max()
        }
        fn and_commutative(x: U512, y: U512) -> bool {
            (&x & &y) == (&y & &x)
        }
        fn or_commutative(x: U512, y: U512) -> bool {
            (&x | &y) == (&y | &x)
        }
        fn double_negation(x: U512) -> bool {
            !!&x == x
        }
        fn or_distributive(a: U512, b: U512, c: U512) -> bool {
            (&a & (&b | &c)) == ((&a & &b) | (&a & &c))
        }
        fn and_distributive(a: U512, b: U512, c: U512) -> bool {
            (&a | (&b & &c)) == ((&a | &b) & (&a | &c))
        }
        fn or_absorption(a: U512, b: U512) -> bool {
            (&a | (&a & &b)) == a
        }
        fn and_absorption(a: U512, b: U512) -> bool {
            (&a & (&a | &b)) == a
        }
        fn or_associative(a: U512, b: U512, c: U512) -> bool {
            (&a | (&b | &c)) == ((&a | &b) | &c)
        }
        fn and_associative(a: U512, b: U512, c: U512) -> bool {
            (&a & (&b & &c)) == ((&a & &b) & &c)
        }
        fn xor_as_defined(a: U512, b: U512) -> bool {
            (&a ^ &b) == ((&a | &b) & !(&a & &b))
        }
        fn small_or_check(x: u64, y: u64) -> bool {
            let x512 = U512::from_u64(x);
            let y512 = U512::from_u64(y);
            let z512 = x512 | y512;
            z512.to_u64() == (x | y)
        }
        fn small_and_check(x: u64, y: u64) -> bool {
            let x512 = U512::from_u64(x);
            let y512 = U512::from_u64(y);
            let z512 = x512 & y512;
            z512.to_u64() == (x & y)
        }
        fn small_xor_check(x: u64, y: u64) -> bool {
            let x512 = U512::from_u64(x);
            let y512 = U512::from_u64(y);
            let z512 = x512 ^ y512;
            z512.to_u64() == (x ^ y)
        }
        fn small_neg_check(x: u64) -> bool {
            let x512 = U512::from_u64(x);
            let z512 = !x512;
            z512.to_u64() == !x
        }
    }

    #[test]
    fn shl_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } << 0,
                   U512{ contents: [1,1,1,1,1,1,1,1] });
        assert_eq!(U512{ contents: [1,2,3,4,5,6,7,8] } << 0,
                   U512{ contents: [1,2,3,4,5,6,7,8] });
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } << 512,
                   U512{ contents: [0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0] } << 1,
                   U512{ contents: [4,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } << 64,
                   U512{ contents: [0,1,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } << 66,
                   U512{ contents: [0,4,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0x8000000000000000,0,0,0,0,0,0,0] } << 1,
                   U512{ contents: [0,1,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } << 1,
                   U512{ contents: [2,0,0,0,0,0,0,0] });
    }

    #[test]
    fn shr_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } >> 0,
                   U512{ contents: [1,1,1,1,1,1,1,1] });
        assert_eq!(U512{ contents: [1,2,3,4,5,6,7,8] } >> 0,
                   U512{ contents: [1,2,3,4,5,6,7,8] });
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } >> 512,
                   U512{ contents: [0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0] } >> 1,
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,1,0,0,0,0,0,0] } >> 1,
                   U512{ contents: [0x8000000000000000,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,1,0,0,0,0,0,0] } >> 64,
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,4,0,0,0,0,0,0] } >> 66,
                   U512{ contents: [1,0,0,0,0,0,0,0] });
    }

    quickcheck! {
        fn shift_mask_equivr(x: U512, in_shift: usize) -> bool {
            let shift       = in_shift % 512;
            let mask        = U512::max() << shift;
            let masked_x    = &x & mask;
            let shift_maskr = (x >> shift) << shift;
            shift_maskr == masked_x
        }
        fn shift_mask_equivl(x: U512, in_shift: usize) -> bool {
            let shift       = in_shift % 512;
            let mask        = U512::max() >> shift;
            let masked_x    = &x & mask;
            let shift_maskl = (x << shift) >> shift;
            shift_maskl == masked_x
        }
    }

    #[test]
    fn add_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } +
                   U512{ contents: [1,1,1,1,1,1,1,1] },
                   U512{ contents: [2,2,2,2,2,2,2,2] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } +
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0,0,0,0,0,0,0] },
                   U512{ contents: [0,1,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,1] } +
                   U512{ contents: [0,0,0,0,0,0,0,0xFFFFFFFFFFFFFFFF] },
                   U512{ contents: [0,0,0,0,0,0,0,0] });
    }

    quickcheck! {
        fn add_symmetry(a: U512, b: U512) -> bool {
            (&a + &b) == (&b + &a)
        }
        fn add_commutivity(a: U512, b: U512, c: U512) -> bool {
            (&a + (&b + &c)) == ((&a + &b) + &c)
        }
        fn add_identity(a: U512) -> bool {
            (&a + U512::zero()) == a
        }
    }

    #[test]
    fn sub_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1] } -
                   U512{ contents: [1,1,1,1,1,1,1,1] },
                   U512{ contents: [0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,1,0,0,0,0,0,0] } -
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,0] } -
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF] });
    }

    quickcheck! {
        fn sub_destroys(a: U512) -> bool {
            (&a - &a) == U512::zero()
        }
        fn sub_add_ident(a: U512, b: U512) -> bool {
            ((&a - &b) + &b) == a
        }
    }

    #[test]
    fn mul_tests() {
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } *
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } *
                   U512{ contents: [0,0,0,0,0,0,0,0] },
                   U512{ contents: [0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } *
                   U512{ contents: [2,0,0,0,0,0,0,0] },
                   U512{ contents: [2,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0xFFFFFFFFFFFFFFFF,0,0,0,0,0,0,0] } *
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0xFFFFFFFFFFFFFFFE,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0] } *
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF] },
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF] });
         assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0] } *
                   U512{ contents: [0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF] },
                   U512{ contents: [0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,
                                    0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF] });
    }

    quickcheck! {
        fn mul_symmetry(a: U512, b: U512) -> bool {
            (&a * &b) == (&b * &a)
        }
        fn mul_commutivity(a: U512, b: U512, c: U512) -> bool {
            (&a * (&b * &c)) == ((&a * &b) * &c)
        }
        fn mul_identity(a: U512) -> bool {
            (&a * U512::from_u64(1)) == a
        }
        fn mul_zero(a: U512) -> bool {
            (&a * U512::zero()) == U512::zero()
        }
    }

    quickcheck! {
        fn addmul_distribution(a: U512, b: U512, c: U512) -> bool {
            (&a * (&b + &c)) == ((&a * &b) + (&a * &c))
        }
        fn submul_distribution(a: U512, b: U512, c: U512) -> bool {
            (&a * (&b - &c)) == ((&a * &b) - (&a * &c))
        }
        fn mul2shift1_equiv(a: U512) -> bool {
            (&a << 1) == (&a * U512::from_u64(2))
        }
        fn mul16shift4_equiv(a: U512) -> bool {
            (&a << 4) == (&a * U512::from_u64(16))
        }
    }

    #[test]
    fn div_tests() {
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0] } /
                   U512{ contents: [2,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0] } /
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [2,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [4,0,0,0,0,0,0,0] } /
                   U512{ contents: [3,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [4,0,0,0,0,0,0,0] } /
                   U512{ contents: [5,0,0,0,0,0,0,0] },
                   U512{ contents: [0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [4,0,0,0,0,0,0,0] } /
                   U512{ contents: [4,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,4] } /
                   U512{ contents: [0,0,0,0,0,0,0,4] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,4] } /
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [0,0,0,0,0,0,0,4] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,0xFFFFFFFFFFFFFFFF] } /
                   U512{ contents: [1,0,0,0,0,0,0,0] },
                   U512{ contents: [0,0,0,0,0,0,0,0xFFFFFFFFFFFFFFFF] });
    }

    #[test]
    fn mod_tests() {
        assert_eq!(U512{ contents: [4,0,0,0,0,0,0,0] } %
                   U512{ contents: [5,0,0,0,0,0,0,0] },
                   U512{ contents: [4,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [5,0,0,0,0,0,0,0] } %
                   U512{ contents: [4,0,0,0,0,0,0,0] },
                   U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [5,5,5,5,5,5,5,5] } %
                   U512{ contents: [4,4,4,4,4,4,4,4] },
                   U512{ contents: [1,1,1,1,1,1,1,1] });
    }

    #[test]
    fn divmod_tests() {
        let     a = U512::from_u64(4);
        let     b = U512::from_u64(3);
        let mut q = U512::zero();
        let mut r = U512::zero();
        a.divmod(&b, &mut q, &mut r);
        assert_eq!(q, U512{ contents: [1,0,0,0,0,0,0,0] });
        assert_eq!(r, U512{ contents: [1,0,0,0,0,0,0,0] });
    }

    quickcheck! {
        fn div_identity(a: U512) -> bool {
            &a / U512::from_u64(1) == a
        }
        fn div_self_is_one(a: U512) -> bool {
            if a == U512::zero() {
                return true;
            }
            &a / &a == U512::from_u64(1)
        }
        fn euclid_is_alive(a: U512, b: U512) -> bool {
            let mut q = U512::zero();
            let mut r = U512::zero();
            a.divmod(&b, &mut q, &mut r);
            a == ((b * q) + r)
        }
    }
}
