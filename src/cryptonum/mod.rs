#[macro_use]
mod conversions;
#[macro_use]
mod complete_arith;

use num::{BigUint,ToPrimitive,Zero};
use std::fmt;
use std::fmt::Write;
use std::cmp::Ordering;
use std::ops::*;

/// In case you were wondering, it stands for "Unsigned Crypto Num".
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct UCN {
    contents: Vec<u64>
}

impl UCN {
    fn clean(&mut self) {
        loop {
            match self.contents.pop() {
                None =>
                    break,
                Some(0) =>
                    continue,
                Some(x) => {
                    self.contents.push(x);
                    break
                }
            }
        }
    }

    fn expand(&mut self, rhs: &UCN) {
        while self.contents.len() < rhs.contents.len() {
            self.contents.push(0);
        }
    }
}

impl fmt::UpperHex for UCN {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(),fmt::Error> {
        for x in self.contents.iter().rev() {
            fmt.write_char(tochar_upper(x >> 60))?;
            fmt.write_char(tochar_upper(x >> 56))?;
            fmt.write_char(tochar_upper(x >> 52))?;
            fmt.write_char(tochar_upper(x >> 48))?;
            fmt.write_char(tochar_upper(x >> 44))?;
            fmt.write_char(tochar_upper(x >> 40))?;
            fmt.write_char(tochar_upper(x >> 36))?;
            fmt.write_char(tochar_upper(x >> 32))?;
            fmt.write_char(tochar_upper(x >> 28))?;
            fmt.write_char(tochar_upper(x >> 24))?;
            fmt.write_char(tochar_upper(x >> 20))?;
            fmt.write_char(tochar_upper(x >> 16))?;
            fmt.write_char(tochar_upper(x >> 12))?;
            fmt.write_char(tochar_upper(x >>  8))?;
            fmt.write_char(tochar_upper(x >>  4))?;
            fmt.write_char(tochar_upper(x >>  0))?;
        }
        Ok(())
    }
}

fn tochar_upper(x: u64) -> char {
    match (x as u8) & (0xF as u8) {
        0x0 => '0',
        0x1 => '1',
        0x2 => '2',
        0x3 => '3',
        0x4 => '4',
        0x5 => '5',
        0x6 => '6',
        0x7 => '7',
        0x8 => '8',
        0x9 => '9',
        0xA => 'A',
        0xB => 'B',
        0xC => 'C',
        0xD => 'D',
        0xE => 'E',
        0xF => 'F',
        _   => panic!("the world is broken")
    }
}

impl fmt::LowerHex for UCN {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(),fmt::Error> {
        for x in self.contents.iter().rev() {
            fmt.write_char(tochar_lower(x >> 60))?;
            fmt.write_char(tochar_lower(x >> 56))?;
            fmt.write_char(tochar_lower(x >> 52))?;
            fmt.write_char(tochar_lower(x >> 48))?;
            fmt.write_char(tochar_lower(x >> 44))?;
            fmt.write_char(tochar_lower(x >> 40))?;
            fmt.write_char(tochar_lower(x >> 36))?;
            fmt.write_char(tochar_lower(x >> 32))?;
            fmt.write_char(tochar_lower(x >> 28))?;
            fmt.write_char(tochar_lower(x >> 24))?;
            fmt.write_char(tochar_lower(x >> 20))?;
            fmt.write_char(tochar_lower(x >> 16))?;
            fmt.write_char(tochar_lower(x >> 12))?;
            fmt.write_char(tochar_lower(x >>  8))?;
            fmt.write_char(tochar_lower(x >>  4))?;
            fmt.write_char(tochar_lower(x >>  0))?;
        }
        Ok(())
    }
}

fn tochar_lower(x: u64) -> char {
    match (x as u8) & (0xF as u8) {
        0x0 => '0',
        0x1 => '1',
        0x2 => '2',
        0x3 => '3',
        0x4 => '4',
        0x5 => '5',
        0x6 => '6',
        0x7 => '7',
        0x8 => '8',
        0x9 => '9',
        0xA => 'a',
        0xB => 'b',
        0xC => 'c',
        0xD => 'd',
        0xE => 'e',
        0xF => 'f',
        _   => panic!("the world is broken")
    }
}

//------------------------------------------------------------------------------
//
//  Conversions to/from crypto nums.
//
//------------------------------------------------------------------------------

define_from!(UCN, u8);
define_from!(UCN, u16);
define_from!(UCN, u32);
define_from!(UCN, u64);
define_into!(UCN, u8);
define_into!(UCN, u16);
define_into!(UCN, u32);
define_into!(UCN, u64);

impl From<BigUint> for UCN {
    fn from(mut x: BigUint) -> UCN {
        let mut dest = Vec::new();
        let mask = BigUint::from(0xFFFFFFFFFFFFFFFF as u64);

        while !x.is_zero() {
            match (&x & &mask).to_u64() {
                None =>
                    panic!("Can't use BigUint in From<BigUint>"),
                Some(val) =>
                    dest.push(val)
            }
            x >>= 64;
        }

        UCN{ contents: dest }
    }
}

impl Into<BigUint> for UCN {
    fn into(self) -> BigUint {
        let mut result = BigUint::zero();

        for part in self.contents.iter().rev() {
            result <<= 64;
            result += BigUint::from(*part);
        }

        result
    }
}

//------------------------------------------------------------------------------
//
//  Comparisons
//
//------------------------------------------------------------------------------

impl PartialOrd for UCN {
    fn partial_cmp(&self, other: &UCN) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UCN {
    fn cmp(&self, other: &UCN) -> Ordering {
        match self.contents.len().cmp(&other.contents.len()) {
            Ordering::Equal => {
                let mut me   = self.contents.iter().rev();
                let mut them = other.contents.iter().rev();

                for (m, t) in me.zip(them) {
                    match m.cmp(t) {
                        Ordering::Equal =>
                            continue,
                        res =>
                            return res
                    }
                }

                Ordering::Equal
            }
            x => x
        }
    }
}

//------------------------------------------------------------------------------
//
//  Bit Operations
//
//------------------------------------------------------------------------------

impl Not for UCN {
    type Output = UCN;

    fn not(self) -> UCN {
        let mut contents = self.contents;

        for x in contents.iter_mut() {
            *x = !*x;
        }

        let mut res = UCN{ contents: contents };
        res.clean();
        res
    }
}

impl<'a> Not for &'a UCN {
    type Output = UCN;

    fn not(self) -> UCN {
        let res = self.clone();
        res.not()
    }
}

impl<'a> BitOrAssign<&'a UCN> for UCN {
    fn bitor_assign(&mut self, rhs: &UCN) {
        self.expand(&rhs);
        {
            let mut iter_me = self.contents.iter_mut();
            let mut iter_tm = rhs.contents.iter();

            loop {
                match (iter_me.next(), iter_tm.next()) {
                    (Some(dest), Some(val)) =>
                        *dest |= val,
                    _ =>
                        break
                }
            }
        }
        self.clean();
    }
}

impl<'a> BitXorAssign<&'a UCN> for UCN {
    fn bitxor_assign(&mut self, rhs: &UCN) {
        self.expand(&rhs);
        {
            let mut iter_me = self.contents.iter_mut();
            let mut iter_tm = rhs.contents.iter();

            loop {
                match (iter_me.next(), iter_tm.next()) {
                    (Some(dest), Some(val)) =>
                        *dest ^= val,
                    _ =>
                        break
                }
            }
        }
        self.clean();
    }
}

impl<'a> BitAndAssign<&'a UCN> for UCN {
    fn bitand_assign(&mut self, rhs: &UCN) {
        if self.contents.len() > rhs.contents.len() {
            self.contents.resize(rhs.contents.len(), 0);
        }
        {
            let mut iter_me = self.contents.iter_mut();
            let mut iter_tm = rhs.contents.iter();

            loop {
                match (iter_me.next(), iter_tm.next()) {
                    (Some(dest), Some(val)) =>
                        *dest &= val,
                    _ =>
                        break
                }
            }
        }
        self.clean();
    }
}

derive_arithmetic_operators!(UCN, BitOr,  bitor,  BitOrAssign,  bitor_assign);
derive_arithmetic_operators!(UCN, BitXor, bitxor, BitXorAssign, bitxor_assign);
derive_arithmetic_operators!(UCN, BitAnd, bitand, BitAndAssign, bitand_assign);

//------------------------------------------------------------------------------
//
//  Shifts
//
//------------------------------------------------------------------------------

impl ShlAssign<u64> for UCN {
    fn shl_assign(&mut self, rhs: u64) {
        let mut digits = rhs / 64;
        let bits = rhs % 64;
        let mut carry = 0;

        // ripple the bit-level shift through
        if bits != 0 {
            for x in self.contents.iter_mut() {
                let new_carry = *x >> (64 - bits);
                *x = (*x << bits) | carry;
                carry = new_carry;
            }
        }

        // if we pulled some stuff off the end, add it back
        if carry != 0 {
            self.contents.push(carry);
        }

        // add the appropriate digits on the low side
        while digits > 0 {
            self.contents.insert(0,0);
            digits -= 1;
        }
    }
}

impl Shl<u64> for UCN {
    type Output = UCN;

    fn shl(self, rhs: u64) -> UCN {
        let mut copy = self.clone();
        copy.shl_assign(rhs);
        copy
    }
}

derive_shift_operators!(UCN, ShlAssign, Shl, shl_assign, shl, usize);
derive_shift_operators!(UCN, ShlAssign, Shl, shl_assign, shl, u32);
derive_shift_operators!(UCN, ShlAssign, Shl, shl_assign, shl, u16);
derive_shift_operators!(UCN, ShlAssign, Shl, shl_assign, shl, u8);

impl ShrAssign<u64> for UCN {
    fn shr_assign(&mut self, rhs: u64) {
        let mut digits = rhs / 64;
        let bits = rhs % 64;

        // remove the appropriate digits on the low side
        while digits > 0 {
            self.contents.remove(0);
            digits -= 1;
        }
        // ripple the shifts over
        let mut carry = 0;
        let mask = !(0xFFFFFFFFFFFFFFFF << bits);

        for x in self.contents.iter_mut().rev() {
            let base = *x >> bits;
            let (new_carry, _) = (*x & mask).overflowing_shl((64-bits) as u32);
            *x = base | carry;
            carry = new_carry;
        }
        // in this case, we just junk the extra carry bits
    }
}

impl Shr<u64> for UCN {
    type Output = UCN;

    fn shr(self, rhs: u64) -> UCN {
        let mut copy = self.clone();
        copy.shr_assign(rhs);
        copy
    }
}

derive_shift_operators!(UCN, ShrAssign, Shr, shr_assign, shr, usize);
derive_shift_operators!(UCN, ShrAssign, Shr, shr_assign, shr, u32);
derive_shift_operators!(UCN, ShrAssign, Shr, shr_assign, shr, u16);
derive_shift_operators!(UCN, ShrAssign, Shr, shr_assign, shr, u8);

derive_signed_shift_operators!(UCN, usize, isize);
derive_signed_shift_operators!(UCN, u64,   i64);
derive_signed_shift_operators!(UCN, u32,   i32);
derive_signed_shift_operators!(UCN, u16,   i16);
derive_signed_shift_operators!(UCN, u8,    i8);

//------------------------------------------------------------------------------
//
//  Tests!
//
//------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    #[test]
    fn test_clean() {
        let mut val1 = UCN{ contents: vec![1,0,0] };
        val1.clean();
        assert_eq!(val1, UCN{ contents: vec![1] });
        //
        let mut val2 = UCN{ contents: vec![0,0,0] };
        val2.clean();
        assert_eq!(val2, UCN{ contents: vec![] });
        //
        let mut val3 = UCN{ contents: vec![1,0,1] };
        val3.clean();
        assert_eq!(val3, UCN{ contents: vec![1,0,1] });
        //
        let mut val4 = UCN{ contents: vec![] };
        val4.clean();
        assert_eq!(val4, UCN{ contents: vec![] });
    }

    #[test]
    #[allow(overflowing_literals)]
    fn test_builders() {
        assert_eq!(UCN{ contents: vec![] },
                   UCN::from(0 as u8));
        assert_eq!(UCN{ contents: vec![0x7F] },
                   UCN::from(0x7F as u8));
        assert_eq!(UCN{ contents: vec![0x7F7F] },
                   UCN::from(0x7F7F as u16));
        assert_eq!(UCN{ contents: vec![0xCA5CADE5] },
                   UCN::from(0xCA5CADE5 as u32));
        assert_eq!(UCN{ contents: vec![0xFFFFFFFFFFFFFFFF] },
                   UCN::from(0xFFFFFFFFFFFFFFFF as u64));
        assert_eq!(UCN{ contents: vec![0x00000000FFFFFFFF] },
                   UCN::from(0xFFFFFFFFFFFFFFFF as u32));
    }

    quickcheck! {
        fn builder_u8_upgrade_u16(x: u8) -> bool {
            UCN::from(x) == UCN::from(x as u16)
        }
        fn builder_u16_upgrade_u32(x: u16) -> bool {
            UCN::from(x) == UCN::from(x as u32)
        }
        fn builder_u32_upgrade_u64(x: u32) -> bool {
            UCN::from(x) == UCN::from(x as u64)
        }
        fn builder_u8_roundtrips(x: u8) -> bool {
            let thereback: u8 = UCN::from(x).into();
            x == thereback
        }
        fn builder_u16_roundtrips(x: u16) -> bool {
            let thereback: u16 = UCN::from(x).into();
            x == thereback
        }
        fn builder_u32_roundtrips(x: u32) -> bool {
            let thereback: u32 = UCN::from(x).into();
            x == thereback
        }
        fn builder_u64_roundtrips(x: u64) -> bool {
            let thereback: u64 = UCN::from(x).into();
            x == thereback
        }
    }

    quickcheck! {
        fn u64_comparison_sane(x: u64, y: u64) -> bool {
            let ucnx = UCN::from(x);
            let ucny = UCN::from(y);
            ucnx.cmp(&ucny) == x.cmp(&y)
        }
        fn longer_is_greater(x: u64, y: u64) -> bool {
            if x == 0 {
                true
            } else {
                let ucnx = UCN{ contents: vec![x, 1] };
                let ucny = UCN::from(y);
                ucnx.cmp(&ucny) == Ordering::Greater
            }
        }
        fn self_is_equal(x: Vec<u64>) -> bool {
            let val = UCN{ contents: x };
            let copy = val.clone();

            (&val == &copy) && (val.cmp(&copy) == Ordering::Equal)
        }
    }

    impl Arbitrary for UCN {
        fn arbitrary<G: Gen>(g: &mut G) -> UCN {
            let lenopts = [4,8]; //,8,16,32,48,64,112,128,240];
            let mut len = *g.choose(&lenopts).unwrap();
            let mut contents = Vec::with_capacity(len);

            while len > 0 {
                contents.push(g.gen());
                len -= 1;
            }
            UCN{ contents: contents }
        }
    }

    fn expand_to_match(a: &mut UCN, b: &UCN) {
        assert!(a.contents.len() <= b.contents.len());
        while a.contents.len() < b.contents.len() {
            a.contents.push(0);
        }
    }

    quickcheck! {
        fn double_negation(x: UCN) -> bool {
            let mut x2 = x.clone().not();
            expand_to_match(&mut x2, &x);
            let mut x3 = x2.not();
            expand_to_match(&mut x3, &x);
            x3 == x
        }
    }

    quickcheck! {
        fn or_associative(a: UCN, b: UCN, c: UCN) -> bool {
            ((&a | &b) | &c) == (&a | (&b | &c))
        }
        fn xor_associative(a: UCN, b: UCN, c: UCN) -> bool {
            ((&a ^ &b) ^ &c) == (&a ^ (&b ^ &c))
        }
        fn and_associative(a: UCN, b: UCN, c: UCN) -> bool {
            ((&a & &b) & &c) == (&a & (&b & &c))
        }
    }

    quickcheck! {
        fn or_commutative(a: UCN, b: UCN) -> bool {
            (&a | &b) == (&b | &a)
        }
        fn xor_commutative(a: UCN, b: UCN) -> bool {
            (&a ^ &b) == (&b ^ &a)
        }
        fn and_commutative(a: UCN, b: UCN) -> bool {
            (&a & &b) == (&b & &a)
        }
    }

    quickcheck! {
        fn or_identity(a: UCN) -> bool {
            (&a | &UCN{ contents: vec![] }) == a
        }
        fn xor_identity(a: UCN) -> bool {
            (&a ^ &UCN{ contents: vec![] }) == a
        }
        fn and_identity(a: UCN) -> bool {
            let mut contents = Vec::new();
            contents.resize(a.contents.len(), 0xFFFFFFFFFFFFFFFF);
            let effs = UCN{ contents: contents };
            (&a & &effs) == a
        }
        fn shl_identity(a: UCN) -> bool {
            (&a << 0) == a
        }
        fn shr_identity(a: UCN) -> bool {
            (&a << 0) == a
        }
    }

    quickcheck! {
        fn or_annihilator(a: UCN) -> bool {
            let mut contents = Vec::new();
            contents.resize(a.contents.len(), 0xFFFFFFFFFFFFFFFF);
            let effs = UCN{ contents: contents };
            (&a | &effs) == effs
        }
        fn and_annihilator(a: UCN) -> bool {
            let zero = UCN{ contents: vec![] };
            (&a & &zero) == zero
        }
        fn shl_shr_annihilate(a: UCN, b: u8) -> bool {
            ((&a << b) >> b) == a
        }
        fn xor_inverse(a: UCN, b: UCN) -> bool {
            ((&a ^ &b) ^ &b) == a
        }
        fn or_idempotent(a: UCN, b: UCN) -> bool {
            (&a | &b) == ((&a | &b) | &b)
        }
        fn and_idempotent(a: UCN, b: UCN) -> bool {
            (&a & &b) == ((&a & &b) & &b)
        }
        fn andor_absorbtion(a: UCN, b: UCN) -> bool {
            (&a & (&a | &b)) == a
        }
        fn orand_absorbtion(a: UCN, b: UCN) -> bool {
            (&a | (&a & &b)) == a
        }
        fn and_over_or_distribution(a: UCN, b: UCN, c: UCN) -> bool {
            (&a & (&b | &c)) == ((&a & &b) | (&a & &c))
        }
        fn and_over_xor_distribution(a: UCN, b: UCN, c: UCN) -> bool {
            (&a & (&b ^ &c)) == ((&a & &b) ^ (&a & &c))
        }
        fn or_over_and_distribution(a: UCN, b: UCN, c: UCN) -> bool {
            (&a | (&b & &c)) == ((&a | &b) & (&a | &c))
        }
        fn demorgans(a: UCN, b: UCN) -> bool {
            let mut a2 = if a.contents.len() < b.contents.len() {a.clone()}
                                                           else {b.clone()};
            let     b2 = if a.contents.len() < b.contents.len() {b.clone()}
                                                           else {a.clone()};
            expand_to_match(&mut a2, &b2);
            (!(&a2 | &b2)) == (!a2 & !b2)
        }
    }

}
