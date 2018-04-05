use cryptonum::signed::SCN;
use num::{BigUint,ToPrimitive,Zero};
use rand::Rng;
use std::fmt;
use std::fmt::Write;
use std::cmp::Ordering;
use std::ops::*;

/// In case you were wondering, it stands for "Unsigned Crypto Num".
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct UCN {
    pub(crate) contents: Vec<u64>
}

static SMALL_PRIMES: [u32; 310] = [
      2,     3,     5,     7,    11,    13,    17,    19,    23,    29,
     31,    37,    41,    43,    47,    53,    59,    61,    67,    71,
     73,    79,    83,    89,    97,   101,   103,   107,   109,   113,
    127,   131,   137,   139,   149,   151,   157,   163,   167,   173,
    179,   181,   191,   193,   197,   199,   211,   223,   227,   229,
    233,   239,   241,   251,   257,   263,   269,   271,   277,   281,
    283,   293,   307,   311,   313,   317,   331,   337,   347,   349,
    353,   359,   367,   373,   379,   383,   389,   397,   401,   409,
    419,   421,   431,   433,   439,   443,   449,   457,   461,   463,
    467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
    547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
    607,   613,   617,   619,   631,   641,   643,   647,   653,   659,
    661,   673,   677,   683,   691,   701,   709,   719,   727,   733,
    739,   743,   751,   757,   761,   769,   773,   787,   797,   809,
    811,   821,   823,   827,   829,   839,   853,   857,   859,   863,
    877,   881,   883,   887,   907,   911,   919,   929,   937,   941,
    947,   953,   967,   971,   977,   983,   991,   997,  1009,  1013,
   1019,  1021,  1031,  1033,  1039,  1049,  1051,  1061,  1063,  1069,
   1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,  1129,  1151,
   1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223,
   1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,  1289,  1291,
   1297,  1301,  1303,  1307,  1319,  1321,  1327,  1361,  1367,  1373,
   1381,  1399,  1409,  1423,  1427,  1429,  1433,  1439,  1447,  1451,
   1453,  1459,  1471,  1481,  1483,  1487,  1489,  1493,  1499,  1511,
   1523,  1531,  1543,  1549,  1553,  1559,  1567,  1571,  1579,  1583,
   1597,  1601,  1607,  1609,  1613,  1619,  1621,  1627,  1637,  1657,
   1663,  1667,  1669,  1693,  1697,  1699,  1709,  1721,  1723,  1733,
   1741,  1747,  1753,  1759,  1777,  1783,  1787,  1789,  1801,  1811,
   1823,  1831,  1847,  1861,  1867,  1871,  1873,  1877,  1879,  1889,
   1901,  1907,  1913,  1931,  1933,  1949,  1951,  1973,  1979,  1987,
   1993,  1997,  1999,  2003,  2011,  2017,  2027,  2029,  2039,  2053];



impl UCN {
    pub fn zero() -> UCN {
        UCN{ contents: vec![] }
    }

    pub fn bits(&self) -> usize {
        self.contents.len() * 64
    }

    pub fn is_zero(&self) -> bool {
        self.contents.len() == 0
    }

    pub fn is_odd(&self) -> bool {
        if self.contents.len() == 0 {
            false
        } else {
            (self.contents[0] & 1) == 1
        }
    }

    pub fn is_even(&self) -> bool {
        if self.contents.len() == 0 {
            false
        } else {
            (self.contents[0] & 1) == 0
        }
    }

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

    pub fn from_str(x: &str) -> UCN {
        let mut outvec = Vec::new();
        let mut worker = 0;
        let mut shift  = 0;

        for c in x.chars().rev() {
            match c.to_digit(16) {
                None =>
                    panic!("Bad character in string: {}", c),
                Some(v) => {
                    worker = worker + ((v as u64) << shift);
                    shift += 4;
                }
            }
            if shift == 64 {
                outvec.push(worker);
                worker = 0;
                shift = 0;
            }
        }
        outvec.push(worker);
        let mut res = UCN{ contents: outvec };
        res.clean();
        res
    }

    pub fn modinv(&self, phi: &UCN) -> UCN {
        let (_, mut x, _) = self.extended_euclidean(&phi);
        let int_phi = SCN::from(phi.clone());
        while x.is_negative() {
            x = x + &int_phi;
        }
        x.into()
    }

    fn extended_euclidean(&self, b: &UCN) -> (SCN, SCN, SCN) {
        let posinta = SCN::from(self.clone());
        let posintb = SCN::from(b.clone());
        let (d, x, y) = posinta.egcd(posintb);

        if d.is_negative() {
            (d.neg(), x.neg(), y.neg())
        } else {
            (d, x, y)
        }
    }

    pub fn generate_prime<F,G>(rng: &mut G,
                               bitlen: usize,
                               iterations: usize,
                               ok_value: F)
        -> UCN
      where
        G: Rng,
        F: Fn(&UCN) -> bool
    {
        let one = UCN::from(1 as u8);
        let topbit = &one << (bitlen - 1);

        loop {
            let base = random_number(rng, bitlen);
            let candidate = base | &topbit | &one;

            if !ok_value(&candidate) {
                continue;
            }

            if candidate.probably_prime(rng, iterations) {
                return candidate
            }
        }
    }

    pub fn probably_prime<G: Rng>(&self, g: &mut G, iters: usize) -> bool {
        for tester in SMALL_PRIMES.iter() {
            if (self % UCN::from(*tester)).is_zero() {
                return false;
            }
        }
        miller_rabin(g, &self, iters)
    }

    pub fn modexp(&self, e: &UCN, m: &UCN) -> UCN {
        let mut b = self.clone() % m;
        let mut eprime = e.clone();
        let mut result = UCN::from(1 as u8);

        loop {
            if eprime.is_zero() {
                return result;
            }

            if eprime.is_odd() {
                result = (result * &b) % m;
            }

            b = (&b * &b) % m;
            eprime >>= 1;
        }
    }
}

fn miller_rabin<G: Rng>(g: &mut G, n: &UCN, iters: usize) -> bool {
    let one = UCN::from(1 as u8);
    let two = UCN::from(2 as u8);
    let nm1 = n - &one;
    // Quoth Wikipedia:
    // write n - 1 as 2^r*d with d odd by factoring powers of 2 from n - 1
    let mut d = nm1.clone();
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
        assert!(r < n.bits());
    }
    // WitnessLoop: repeat k times
    'WitnessLoop: for _k in 0..iters {
        // pick a random integer a in the range [2, n - 2]
        let a = random_in_range(g, &two, &nm1);
        // x <- a^d mod n
        let mut x = a.modexp(&d, &n);
        // if x = 1 or x = n - 1 then
        if (&x == &one) || (&x == &nm1) {
            // continue WitnessLoop
            continue 'WitnessLoop;
        }
        // repeat r - 1 times:
        for _i in 0..r {
            // x <- x^2 mod n
            x = x.modexp(&two, &n);
            // if x = 1 then
            if &x == &one {
                // return composite
                return false;
            }
            // if x = n - 1 then
            if &x == &nm1 {
                // continue WitnessLoop
                continue 'WitnessLoop;
            }
        }
        // return composite
        return false;
    }
    // return probably prime
    true
}

fn random_in_range<G: Rng>(rng: &mut G, min: &UCN, max: &UCN) -> UCN {
    let bitlen = ((max.bits() + 31) / 32) * 32;
    loop {
        let candidate = random_number(rng, bitlen);

        if (&candidate >= min) && (&candidate < max) {
            return candidate;
        }
    }
}

fn random_number<G: Rng>(rng: &mut G, bitlen: usize) -> UCN {
    assert!(bitlen % 32 == 0);
    let wordlen = bitlen / 32;
    let components = rng.gen_iter().take(wordlen).collect();
    UCN{ contents: components }
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
        // in this case, we just junk the extra carry bits, but we do need to
        // cleanup possible zeros at the end.
        self.clean();
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
//  Addition, Subtraction and Multiplication
//
//------------------------------------------------------------------------------

impl<'a> AddAssign<&'a UCN> for UCN {
    fn add_assign(&mut self, rhs: &UCN) {
        let mut iter_tm = rhs.contents.iter();
        let mut stolen  = None;
        let mut carry   = 0;

        // loop through every element on the left hand side, breaking early
        // on if we right the end of the left hand side.
        {
            let mut iter_me = self.contents.iter_mut();
            loop {
                match(iter_me.next(), iter_tm.next()) {
                    (None, None) =>
                        break,
                    (Some(dest), None) => {
                        let dest128 = *dest as u128;
                        let newdest = dest128 + carry;
                        *dest = newdest as u64;
                        carry = newdest >> 64;
                    }
                    (None, Some(x)) => {
                        stolen = Some(*x);
                        break;
                    }
                    (Some(dest), Some(r)) => {
                        let newdest = (*dest as u128) + (*r as u128) + carry;
                        *dest = newdest as u64;
                        carry = newdest >> 64;
                    }
                }
            }
        }
        // if we accidentally stole something form the right iterator,
        // push it back on.
        if let Some(x) = stolen {
            let stolen128 = (x as u128) + carry;
            self.contents.push(stolen128 as u64);
            carry = stolen128 >> 64;
        }
        // now loop through any remaining items on the right hand side,
        // pushing them onto the result.
        for x in iter_tm {
            let x128 = (*x as u128) + carry;
            self.contents.push(x128 as u64);
            carry = x128 >> 64;
        }
        // finally, if there's still a carry, push it on the end.
        if carry > 0 {
            self.contents.push(carry as u64);
        }
    }
}

impl<'a> SubAssign<&'a UCN> for UCN {
    fn sub_assign(&mut self, rhs: &UCN) {
        {
        let mut borrow = 0;
        let mut iter_me = self.contents.iter_mut();
        let mut iter_tm = rhs.contents.iter();

        loop {
            assert!( (borrow == 0) | (borrow == 1) );
            match (iter_me.next(), iter_tm.next()) {
                (None, None) if borrow == 0 =>
                    break,
                (None, None) =>
                    panic!("Generated negative UCN in subtraction (1)."),
                (Some(x), None) => {
                    if borrow == 0 {
                        break;
                    }
                    if *x == 0 {
                        *x = 0xFFFFFFFFFFFFFFFF;
                        borrow = 1;
                    } else {
                        *x = *x - borrow;
                        break;
                    }
                }
                (None, Some(_)) => {
                    panic!("Generated negative UCN in subtraction (2).");
                }
                (Some(x), Some(y)) => {
                    if (*x - borrow) >= *y {
                        *x = (*x - borrow) - *y;
                        borrow = 0;
                    } else {
                        let x128 = (*x as u128) + 0x10000000000000000;
                        let res = x128 - (*y as u128) - (borrow as u128);
                        *x = res as u64;
                        borrow = 1;
                    }
                }
            }
        }
        }
        self.clean();
    }
}

impl<'a> MulAssign<&'a UCN> for UCN {
    fn mul_assign(&mut self, rhs: &UCN) {
        // Handle the quick and easy multiplication by zero cases first.
        if self.contents.len() == 0 {
            return;
        }
        if rhs.contents.len() == 0 {
            self.contents.resize(0,0);
            return;
        }

        // OK, do some real multiplication
        let x = self.contents.clone();
        let y = rhs.contents.clone();
        let outlen = x.len() + y.len();
        let n = y.len() - 1;

        // this algorithm is 14.12 from "Handbook of Applied Cryptography"
        self.contents.resize(0, 0);
        self.contents.resize(outlen, 0);
        for (i,xi) in x.iter().enumerate() {
            let mut c = 0;
            for (j,yj) in y.iter().enumerate() {
                let wij = self.contents[i+j] as u128;
                let xjyi = (*xi as u128) * (*yj as u128);
                let uv = wij + xjyi + c;
                self.contents[i+j] = uv as u64;
                c = uv >> 64;
            }
            self.contents[i+n+1] = c as u64;
        }
        self.clean();
    }
}

pub fn divmod(quotient: &mut Vec<u64>, remainder: &mut Vec<u64>,
              inx: &Vec<u64>, iny: &Vec<u64>)
{
    quotient.resize(0,0);
    remainder.resize(0,0);
    // This algorithm is 14.20 from "Handbook of Applied Cryptography"
    //
    // It requires that y[t] is not zero, which it isn't due to our invariant
    // that we don't have unnecessary zeros at the end of the array. We note
    // that it's also very convienent if the top bit of y[t] is set, as well,
    // so we shift everything left so that things work out.
    let mut xbuffer = Vec::with_capacity(inx.len() + 2);
    let mut ybuffer = Vec::with_capacity(iny.len() + 2);
    xbuffer.extend_from_slice(&inx);
    ybuffer.extend_from_slice(&iny);
    let mut x = UCN{ contents: xbuffer };
    let mut y = UCN{ contents: ybuffer };
    let additional_shift = iny[iny.len() - 1].leading_zeros() as usize;
    x <<= additional_shift;
    y <<= additional_shift;
    // Once we've done this, we should be good to go with our mostly-correct
    // x and y. The only trick is that the algorithm requires that n >= t. If
    // this is not true, then the answer is zero, because the divisor is greater
    // than the dividend.
    let n = x.contents.len();
    let t = y.contents.len();
    if n < t {
        remainder.extend_from_slice(&inx);
        return;
    }
    // Also, it's real convient for n and t to be greater than one, which we
    // achieve by pushing a zero into the low digit. Because we do this, we
    // don't have to do a lot of testing against negative indices later.
    x.contents.insert(0,0);
    y.contents.insert(0,0);
    // 1. For j from 0 to (n-t) do: qj <- 0.
    let mut q = Vec::with_capacity(n - t + 1);
    q.resize(n - t + 1, 0);
    // 2. While (x >= yb^(n-t)) do the following:
    //      q_(n-t) <- q_(n-t) + 1
    //      x       <- x - yb^(n-t)
    let ybnt = &y << (64 * (n - t));
    while &x >= &ybnt {
        q[n-t] = q[n-t] + 1;
        x -= &ybnt;
    }
    // 3. For i from n down to (t + 1) do the following:
    let mut i = n;
    while i >= (t + 1) {
        // 3.1. if xi = yt, then set q_(i-t-1) <- b - 1; otherwise set
        //      q_(i-t-1) <- floor((x_i * b + x_(i-1)) /y_t).
        if x.contents[i] == y.contents[t] {
            q[i-t-1] = 0xFFFFFFFFFFFFFFFF;
        } else {
            let top = ((x.contents[i] as u128)<<64) + (x.contents[i-1] as u128);
            let bot = y.contents[t] as u128;
            let solution = top / bot;
            q[i-t-1] = solution as u64;
        }
        // 3.2. While (q_(i-t-1)(y_t * b + y_(t-1)) > x_i(b2) + x_(i-1)b +
        //      x_(i-2)) do:
        //        q_(i - t - 1) <- q_(i - t 1) - 1.
        loop {
            let qit1 = UCN{ contents: vec![q[i - t - 1]] };
            let ytbyt1 = UCN{ contents: vec![y.contents[t-1], y.contents[t]] };
            let left = qit1 * ytbyt1;
            let right = UCN{ contents: vec![x.contents[i-2],
                                            x.contents[i-1],
                                            x.contents[i]] };

            if left <= right {
                break
            }

            q[i - t - 1] -= 1;
        }
        // 3.3. x <- x - q_(i - t - 1) * y * b^(i-t-1)
        let qit1 = UCN{ contents: vec![q[i - t - 1]] };
        let ybit1 = &y << (64 * (i - t - 1));
        let subbit = &qit1 * &ybit1;
        if subbit <= x {
            x -= subbit;
        } else {
            // 3.4. if x < 0 then set z <- x + yb^(i-t-1) and
            //                        q_(i-t-1) <- q(i-t-1) - 1
            x -= subbit - ybit1;
            q[i - t - 1] -= 1;
        }
        i -= 1;
    }
    // 4. r <- x
    x >>= additional_shift;
    if x.contents.len() > 0 {
        // remember, we added a zero to the front of
        // everything earlier; this removes it.
        x.contents.remove(0);
    }
    remainder.append(&mut x.contents);
    // 5. return (q,r)
    while (q.len() > 0) && (q[q.len() - 1] == 0) {
        q.pop();
    }
    quotient.append(&mut q);
}

impl<'a> DivAssign<&'a UCN> for UCN {
    fn div_assign(&mut self, rhs: &UCN) {
        let copy = self.contents.clone();
        let mut dead = Vec::new();
        divmod(&mut self.contents, &mut dead, &copy, &rhs.contents);
    }
}

impl<'a> RemAssign<&'a UCN> for UCN {
    fn rem_assign(&mut self, rhs: &UCN) {
        let copy = self.contents.clone();
        let mut dead = Vec::new();
        divmod(&mut dead, &mut self.contents, &copy, &rhs.contents);
    }
}

derive_arithmetic_operators!(UCN, Add, add, AddAssign, add_assign);
derive_arithmetic_operators!(UCN, Sub, sub, SubAssign, sub_assign);
derive_arithmetic_operators!(UCN, Mul, mul, MulAssign, mul_assign);
derive_arithmetic_operators!(UCN, Div, div, DivAssign, div_assign);
derive_arithmetic_operators!(UCN, Rem, rem, RemAssign, rem_assign);

//------------------------------------------------------------------------------
//
//  Tests!
//
//------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use std::fs::File;
    use std::io::Read;
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
            let lenopts = [4,8,16,32,48,64,112,128,240];
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
        fn add_associative(a: UCN, b: UCN, c: UCN) -> bool {
            ((&a + &b) + &c) == (&a + (&b + &c))
        }
        fn mul_associative(a: UCN, b: UCN, c: UCN) -> bool {
            ((&a * &b) * &c) == (&a * (&b * &c))
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
        fn add_commutative(a: UCN, b: UCN) -> bool {
            let ab = &a + &b;
            let ba = &b + &a;
            (ab == ba)
        }
        fn mul_commutative(a: UCN, b: UCN) -> bool {
            let ab = &a * &b;
            let ba = &b * &a;
            (ab == ba)
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
            (&a >> 0) == a
        }
        fn add_identity(a: UCN) -> bool {
            (&a + &UCN{ contents: vec![] }) == a
        }
        fn sub_identity(a: UCN) -> bool {
            (&a - &UCN{ contents: vec![] }) == a
        }
        fn mul_identity(a: UCN) -> bool {
            let one = UCN{ contents: vec![1] };
            (&a * &one) == a
        }
        fn div_identity(a: UCN) -> bool {
            let one = UCN{ contents: vec![1] };
            (&a / &one) == a
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
            let left = &a << b;
            let right = &left >> b;
            right == a
        }
        fn sub_annihilation(a: UCN) -> bool {
            (&a - &a) == UCN{ contents: vec![] }
        }
        fn mul_annihilation(a: UCN) -> bool {
            let zero = UCN{ contents: vec![] };
            (&a * &zero) == zero
        }
    }

    quickcheck! {
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
    }

    quickcheck! {
        fn mod_plus1_identity(a: UCN) -> bool {
            let one = UCN{ contents: vec![1] };
            let ap1 = &a + &one;
            (&a % ap1) == a
        }
        fn mod_min1_is_one(a: UCN) -> bool {
            let one = UCN{ contents: vec![1] };
            let am1 = &a - &one;
            (&a % am1) == one
        }
        #[should_panic]
        fn div0_fails(a: UCN) -> bool {
            (&a / &UCN{ contents: vec![] }) == a
        }
        fn euclid_is_alive(a: UCN, b: UCN) -> bool {
            let zero = UCN{ contents: vec![] };
            if &b == &zero {
                return true;
            }
            let q = &a / &b;
            let r = &a % &b;
            let res = (b * q) + r;
            a == res
        }
    }

    fn gold_test<F>(name: &str, f: F)
     where
      F: Fn(UCN,UCN) -> UCN
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
            let x = UCN::from_str(&xstr[3..]);
            let y = UCN::from_str(&ystr[3..]);
            let z = UCN::from_str(&zstr[3..]);
            assert_eq!(f(x,y), z);
        }
    }

    #[test]
    fn add_tests() {
        gold_test("tests/add_tests.txt", |x,y| x + y);
    }

    #[test]
    fn sub_tests() {
        gold_test("tests/sub_tests.txt", |x,y| x - y);
    }

    #[test]
    fn mul_tests() {
        gold_test("tests/mul_tests.txt", |x,y| x * y);
    }

    #[test]
    fn div_tests() {
        gold_test("tests/div_tests.txt", |x,y| x / y);
    }

    #[test]
    fn mod_tests() {
        gold_test("tests/mod_tests.txt", |x,y| x % y);
    }

    #[test]
    fn modexp_tests() {
        let mut file = File::open("tests/modpow_tests.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut iter = contents.lines();

        while let Some(xstr) = iter.next() {
            let ystr = iter.next().unwrap();
            let zstr = iter.next().unwrap();
            let rstr = iter.next().unwrap();

            assert!(xstr.starts_with("x: "));
            assert!(ystr.starts_with("y: "));
            assert!(zstr.starts_with("z: "));
            assert!(rstr.starts_with("r: "));
            let x = UCN::from_str(&xstr[3..]);
            let y = UCN::from_str(&ystr[3..]);
            let z = UCN::from_str(&zstr[3..]);
            let r = UCN::from_str(&rstr[3..]);
            assert_eq!(x.modexp(&y, &z), r);
        }
    }

    quickcheck! {
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
        fn shift_multiply_equiv(a: UCN, b: u8) -> bool {
            let one = UCN{ contents: vec![1] };
            let pow2 = one << b;
            (&a << b) == (&a * pow2)
        }
        fn shl_mul_equiv(a: UCN) -> bool {
            (&a << 1) == (&a * UCN::from(2 as u64)) &&
            (&a << 3) == (&a * UCN::from(8 as u64)) &&
            (&a << 4) == (&a * UCN::from(16 as u64)) &&
            (&a << 43) == (&a * UCN::from(8796093022208 as u64))
        }
        fn shr_div_equiv(a: UCN) -> bool {
            (&a >> 1) == (&a / UCN::from(2 as u64)) &&
            (&a >> 3) == (&a / UCN::from(8 as u64)) &&
            (&a >> 4) == (&a / UCN::from(16 as u64)) &&
            (&a >> 43) == (&a / UCN::from(8796093022208 as u64))
        }
    }
}
