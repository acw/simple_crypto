//! # Simple-Crypto CryptoNum
//!
//! This module is designed to provide large, fixed-width number support for
//! the rest of the Simple-Crypto libraries. Feel free to use it other places,
//! of course, but that's its origin.

use std::cmp::Ordering;
use std::ops::*;

/// A 512-bit unsigned value
#[derive(PartialEq,Eq,Debug,Clone)]
pub struct U512 {
    // Why 9? Remember, we represent numbers in base 2^63, so that we can
    // recover the carry bit as necessary. So we actually need ceiling(512/63)
    // = 9 bytes to hold a 512-bit number.
    contents: [u64; 9]
}

impl U512 {
    /// 0!
    pub fn zero() -> U512 {
        U512 {
            contents: [0, 0, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// The maximum possible value: 2^512 - 1.
    pub fn max() -> U512 {
        U512 {
            contents: [0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                       0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                       0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                       0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                       0xFF]
        }
    }

    /// Convert a `u8` to a `U512`. This is always safe.
    pub fn from_u8(x: u8) -> U512 {
        U512 {
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0, 0]
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
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0, 0]
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
            contents: [x as u64, 0, 0, 0, 0, 0, 0, 0, 0]
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
            contents: [x & 0x7FFFFFFFFFFFFFFF, x >> 63, 0, 0, 0, 0, 0, 0, 0]
        }
    }

    /// Convert a U512 into a `u64`. This should be the equivalent of masking
    /// the U512 with `0xFFFFFFFFFFFFFFFF` and then converting to a `u64`.
    pub fn to_u64(&self) -> u64 {
        (self.contents[0] as u64) | (self.contents[1] << 63)
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
        let sback = self.contents.iter().rev();
        let oback = other.contents.iter().rev();
        for (x,y) in sback.zip(oback) {
            match x.cmp(y) {
                Ordering::Equal => {},
                res             => return res
            }
        }
        Ordering::Equal
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
        let mut oback = other.contents.iter();
        for x in self.contents.iter_mut() {
            match oback.next() {
                None => panic!("Internal error in cryptonum (|=)."),
                Some(v) => *x = *x | *v
            }
        }
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

        for x in output.contents.iter_mut() {
            *x = !*x & 0x7FFFFFFFFFFFFFFF;
        }
        output.contents[8] &= 0xFF;
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
        let mut oback = other.contents.iter();
        for x in self.contents.iter_mut() {
            match oback.next() {
                None => panic!("Internal error in cryptonum (&=)."),
                Some(v) => *x = *x & *v
            }
        }
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
        let mut oback = other.contents.iter();
        for x in self.contents.iter_mut() {
            match oback.next() {
                None => panic!("Internal error in cryptonum (&=)."),
                Some(v) => *x = *x ^ *v
            }
        }
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
        let digits = amount / 63;
        let bits   = amount % 63;
        let orig   = self.contents.clone();

        for i in 0..9 {
            if i < digits {
                self.contents[i] = 0;
            } else {
                let origidx = i - digits;
                let prev = if origidx == 0 { 0 } else { orig[origidx - 1] };
                let carry = prev >> (63 - bits);
                self.contents[i] = (orig[origidx] << bits) | carry;
                self.contents[i] &= 0x7FFFFFFFFFFFFFFF;
            }
        }
        self.contents[8] &= 0xFF;
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
        let digits = amount / 63;
        let bits   = amount % 63;
        let orig   = self.contents.clone();

        for i in 0..9 {
            let oldidx = i + digits;
            let caridx = i + digits + 1;
            let old    = if oldidx > 8 { 0 } else { orig[oldidx] };
            let carry  = if caridx > 8 { 0 } else { orig[caridx] };
            let (cb,_) = carry.overflowing_shl(63 - bits as u32);
            self.contents[i] = (old >> bits) | cb;
            self.contents[i] &= 0x7FFFFFFFFFFFFFFF;
        }
        self.contents[8] &= 0xFF;
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
        let mut carry = 0;

        for i in 0..9 {
            let a = self.contents[i];
            let b = rhs.contents[i];
            let total = a + b + carry;

            carry = total >> 63;
            self.contents[i] = total & 0x7FFFFFFFFFFFFFFF;
        }
        self.contents[8] &= 0xFF;
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

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    #[test]
    fn test_builders() {
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,0,0] },
                   U512::from_u8(0));
        assert_eq!(U512{ contents: [0x7F,0,0,0,0,0,0,0,0] },
                   U512::from_u8(0x7F));
        assert_eq!(U512{ contents: [0x7F7F,0,0,0,0,0,0,0,0] },
                   U512::from_u16(0x7F7F));
        assert_eq!(U512{ contents: [0xCA5CADE5,0,0,0,0,0,0,0,0] },
                   U512::from_u32(0xCA5CADE5));
        assert_eq!(U512{ contents: [0xCA5CADE5,0,0,0,0,0,0,0,0] },
                   U512::from_u64(0xCA5CADE5));
        assert_eq!(U512{ contents: [0x7FFFFFFFFFFFFFFF,1,0,0,0,0,0,0,0] },
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
            let x1 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x2 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x3 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x4 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x5 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x6 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x7 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x8 = g.next_u64() & 0x7FFFFFFFFFFFFFFF;
            let x9 = g.next_u64() & 0xFF;
            U512{ contents: [x1, x2, x3, x4, x5, x6, x7, x8, x9] }
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
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1,1] } << 0,
                   U512{ contents: [1,1,1,1,1,1,1,1,1] });
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1,1] } << 512,
                   U512{ contents: [0,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0,0] } << 1,
                   U512{ contents: [4,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0,0] } << 63,
                   U512{ contents: [0,1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0,0] } << 65,
                   U512{ contents: [0,4,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0x4000000000000000,0,0,0,0,0,0,0,0] } << 1,
                   U512{ contents: [0,1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0,0xFF] } << 1,
                   U512{ contents: [2,0,0,0,0,0,0,0,0xFE] });
    }

    #[test]
    fn shr_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1,1] } >> 0,
                   U512{ contents: [1,1,1,1,1,1,1,1,1] });
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1,1] } >> 512,
                   U512{ contents: [0,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [2,0,0,0,0,0,0,0,0] } >> 1,
                   U512{ contents: [1,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,1,0,0,0,0,0,0,0] } >> 1,
                   U512{ contents: [0x4000000000000000,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,1,0,0,0,0,0,0,0] } >> 63,
                   U512{ contents: [1,0,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,4,0,0,0,0,0,0,0] } >> 65,
                   U512{ contents: [1,0,0,0,0,0,0,0,0] });
    }

    #[test]
    fn add_tests() {
        assert_eq!(U512{ contents: [1,1,1,1,1,1,1,1,1] } +
                   U512{ contents: [1,1,1,1,1,1,1,1,1] },
                   U512{ contents: [2,2,2,2,2,2,2,2,2] });
        assert_eq!(U512{ contents: [1,0,0,0,0,0,0,0,0] } +
                   U512{ contents: [0x7FFFFFFFFFFFFFFF,0,0,0,0,0,0,0,0] },
                   U512{ contents: [0,1,0,0,0,0,0,0,0] });
        assert_eq!(U512{ contents: [0,0,0,0,0,0,0,0,1] } +
                   U512{ contents: [0,0,0,0,0,0,0,0,0xFF] },
                   U512{ contents: [0,0,0,0,0,0,0,0,0] });
    }

    quickcheck! {
        fn add_symmetry(a: U512, b: U512) -> bool {
            (&a + &b) == (&b + &a)
        }
        fn add_commutivity(a: U512, b: U512, c: U512) -> bool {
            (&a + (&b + &c)) == ((&a + &b) + &c)
        }
    }
}
