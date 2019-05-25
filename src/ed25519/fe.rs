#[cfg(test)]
use byteorder::{LittleEndian,NativeEndian,ReadBytesExt};
#[cfg(test)]
use cryptonum::unsigned::{Decoder,U192};
#[cfg(test)]
use ed25519::point::curve25519_scalar_mask;
#[cfg(test)]
use quickcheck::{Arbitrary,Gen};
#[cfg(test)]
use std::io::Cursor;
#[cfg(test)]
use testing::run_test;

use std::ops::*;

// This is all an extremely straightforward translation of the usual C
// implementation, as linked in ring and other libraries.

const NUM_ELEMENT_LIMBS: usize = 10;

#[derive(Clone,Debug,PartialEq)]
pub struct FieldElement
{
    pub(crate) value: [i32; NUM_ELEMENT_LIMBS]
}

impl FieldElement
{
    pub fn new() -> FieldElement
    {
        FieldElement{ value: [0; NUM_ELEMENT_LIMBS] }
    }

    pub fn zero() -> FieldElement
    {
        FieldElement{ value: [0; NUM_ELEMENT_LIMBS] }
    }

    pub fn one() -> FieldElement
    {
        let mut res = FieldElement::zero();
        res.value[0] = 1;
        res
    }

    pub fn overwrite_with(&mut self, other: &FieldElement)
    {
        self.value.copy_from_slice(&other.value);
    }

    pub fn from_bytes(s: &[u8]) -> FieldElement
    {
        /* Ignores top bit of h. */
        let mut h0 = load4(s) as i64;
        let mut h1 = (load3(&s[4..]) << 6) as i64;
        let mut h2 = (load3(&s[7..]) << 5) as i64;
        let mut h3 = (load3(&s[10..]) << 3) as i64;
        let mut h4 = (load3(&s[13..]) << 2) as i64;
        let mut h5 = load4(&s[16..]) as i64;
        let mut h6 = (load3(&s[20..]) << 7) as i64;
        let mut h7 = (load3(&s[23..]) << 5) as i64;
        let mut h8 = (load3(&s[26..]) << 4) as i64;
        let mut h9 = ((load3(&s[29..]) & 8388607) << 2) as i64;

        let carry9 = h9 + (1 << 24); h0 += (carry9 >> 25) * 19; h9 -= carry9 & KTOP_39BITS;
        let carry1 = h1 + (1 << 24); h2 += carry1 >> 25; h1 -= carry1 & KTOP_39BITS;
        let carry3 = h3 + (1 << 24); h4 += carry3 >> 25; h3 -= carry3 & KTOP_39BITS;
        let carry5 = h5 + (1 << 24); h6 += carry5 >> 25; h5 -= carry5 & KTOP_39BITS;
        let carry7 = h7 + (1 << 24); h8 += carry7 >> 25; h7 -= carry7 & KTOP_39BITS;

        let carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
        let carry2 = h2 + (1 << 25); h3 += carry2 >> 26; h2 -= carry2 & KTOP_38BITS;
        let carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
        let carry6 = h6 + (1 << 25); h7 += carry6 >> 26; h6 -= carry6 & KTOP_38BITS;
        let carry8 = h8 + (1 << 25); h9 += carry8 >> 26; h8 -= carry8 & KTOP_38BITS;

        FieldElement{ value: [h0 as i32, h1 as i32, h2 as i32, h3 as i32,
                              h4 as i32, h5 as i32, h6 as i32, h7 as i32,
                              h8 as i32, h9 as i32] }
    }

    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut h0 = self.value[0];
        let mut h1 = self.value[1];
        let mut h2 = self.value[2];
        let mut h3 = self.value[3];
        let mut h4 = self.value[4];
        let mut h5 = self.value[5];
        let mut h6 = self.value[6];
        let mut h7 = self.value[7];
        let mut h8 = self.value[8];
        let mut h9 = self.value[9];

        let mut q = (19 * h9 + ((1i32) << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
        h0 += 19 * q;
        /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
        h1 += h0 >> 26; h0 &= KBOTTOM_26BITS as i32;
        h2 += h1 >> 25; h1 &= KBOTTOM_25BITS as i32;
        h3 += h2 >> 26; h2 &= KBOTTOM_26BITS as i32;
        h4 += h3 >> 25; h3 &= KBOTTOM_25BITS as i32;
        h5 += h4 >> 26; h4 &= KBOTTOM_26BITS as i32;
        h6 += h5 >> 25; h5 &= KBOTTOM_25BITS as i32;
        h7 += h6 >> 26; h6 &= KBOTTOM_26BITS as i32;
        h8 += h7 >> 25; h7 &= KBOTTOM_25BITS as i32;
        h9 += h8 >> 26; h8 &= KBOTTOM_26BITS as i32;
                        h9 &= KBOTTOM_25BITS as i32;
                        /* h10 = carry9 */

        /* Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
         * Have h0+...+2^230 h9 between 0 and 2^255-1;
         * evidently 2^255 h10-2^255 q = 0.
         * Goal: Output h0+...+2^230 h9.  */
        vec![ (h0 >> 0) as u8,
              (h0 >> 8) as u8,
              (h0 >> 16) as u8,
              ((h0 >> 24) | (((h1 as u32) << 2) as i32)) as u8,
              (h1 >> 6) as u8,
              (h1 >> 14) as u8,
              ((h1 >> 22) | (((h2 as u32) << 3) as i32)) as u8,
              (h2 >> 5) as u8,
              (h2 >> 13) as u8,
              ((h2 >> 21) | (((h3 as u32) << 5) as i32)) as u8,
              (h3 >> 3) as u8,
              (h3 >> 11) as u8,
              ((h3 >> 19) | (((h4 as u32) << 6) as i32)) as u8,
              (h4 >> 2) as u8,
              (h4 >> 10) as u8,
              (h4 >> 18) as u8,
              (h5 >> 0) as u8,
              (h5 >> 8) as u8,
              (h5 >> 16) as u8,
              ((h5 >> 24) | (((h6 as u32) << 1) as i32)) as u8,
              (h6 >> 7) as u8,
              (h6 >> 15) as u8,
              ((h6 >> 23) | (((h7 as u32) << 3) as i32)) as u8,
              (h7 >> 5) as u8,
              (h7 >> 13) as u8,
              ((h7 >> 21) | (((h8 as u32) << 4) as i32)) as u8,
              (h8 >> 4) as u8,
              (h8 >> 12) as u8,
              ((h8 >> 20) | (((h9 as u32) << 6) as i32)) as u8,
              (h9 >> 2) as u8,
              (h9 >> 10) as u8,
              (h9 >> 18) as u8
            ]
    }
}

pub const KBOTTOM_25BITS : i64 = 0x1ffffffi64;
pub const KBOTTOM_26BITS : i64 = 0x3ffffffi64;
pub const KTOP_39BITS    : i64 = 0xfffffffffe000000u64 as i64;
pub const KTOP_38BITS    : i64 = 0xfffffffffc000000u64 as i64;

pub fn load3(x: &[u8]) -> u64
{
    (x[0] as u64) | ((x[1] as u64) << 8) | ((x[2] as u64) << 16)
}

pub fn load4(x: &[u8]) -> u64
{
    (x[0] as u64)         | ((x[1] as u64) << 8) |
    ((x[2] as u64) << 16) | ((x[3] as u64) << 24)
}

#[cfg(test)]
#[test]
fn loads() {
    let fname = "testdata/ed25519/load.test";
    run_test(fname.to_string(), 3, |case| {
        let (negx, xbytes) = case.get("x").unwrap();
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!negx && !nega && !negb);
        let res3 = u64::from(U192::from_bytes(abytes));
        let res4 = u64::from(U192::from_bytes(bbytes));
        assert_eq!(res3, load3(&xbytes), "load3");
        assert_eq!(res4, load4(&xbytes), "load4");
    });
}

#[cfg(test)]
#[test]
fn from_to_bytes() {
    let fname = "testdata/ed25519/bytes.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!nega && !negb);
        let     e      = FieldElement::from_bytes(abytes);
        let mut target = FieldElement::new();
        let mut cursor = Cursor::new(bbytes);
        cursor.read_i32_into::<NativeEndian>(&mut target.value).unwrap();
        assert_eq!(e, target, "from bytes");
        let bytes = e.to_bytes();
        assert_eq!(&bytes, abytes, "to bytes");
    });
}

#[cfg(test)]
#[derive(Clone,Debug)]
struct ValidFieldElement {
    values: FieldElement
}

#[cfg(test)]
impl Arbitrary for ValidFieldElement {
    fn arbitrary<G: Gen>(g: &mut G) -> ValidFieldElement
    {
        let mut bytes = [0; 32];
        g.fill_bytes(&mut bytes);
        curve25519_scalar_mask(&mut bytes);
        ValidFieldElement{
            values: FieldElement::from_bytes(&bytes)
        }
    }
}

#[cfg(test)]
pub fn test_from_bytes(x: &[u8]) -> FieldElement
{
    let mut res = FieldElement::new();
    let mut helper = Cursor::new(x);
    helper.read_i32_into::<LittleEndian>(&mut res.value).unwrap();
    res
}

#[cfg(test)]
quickcheck! {
    // this is somewhat self referential, given the definition of arbitrary,
    // but more testing is more good
    fn from_to_bytes_roundtrip(e: ValidFieldElement) -> bool {
        let bytes = e.values.to_bytes();
        let trans = FieldElement::from_bytes(&bytes);
        trans == e.values
    }
}

impl<'a> AddAssign<&'a FieldElement> for FieldElement
{
    fn add_assign(&mut self, v: &FieldElement)
    {
        for i in 0..10 {
            self.value[i] = v.value[i] + self.value[i];
        }
    }
}

impl<'a,'b> Add<&'a FieldElement> for &'b FieldElement
{
    type Output = FieldElement;

    fn add(self, g: &FieldElement) -> FieldElement
    {
        let mut res = self.clone();
        res += g;
        res
    }
}

impl<'a> SubAssign<&'a FieldElement> for FieldElement
{
    fn sub_assign(&mut self, v: &FieldElement)
    {
        for i in 0..10 {
            self.value[i] = self.value[i] - v.value[i];
        }
    }
}

impl<'a,'b> Sub<&'a FieldElement> for &'b FieldElement
{
    type Output = FieldElement;

    fn sub(self, g: &FieldElement) -> FieldElement
    {
        let mut res = self.clone();
        res -= g;
        res
    }
}

#[cfg(test)]
#[test]
fn addsub() {
    let fname = "testdata/ed25519/addsub.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let a = test_from_bytes(&abytes);
        let b = test_from_bytes(&bbytes);
        let c = test_from_bytes(&cbytes);
        let d = test_from_bytes(&dbytes);
        let r = &a + &b;
        let s = &a - &b;
        assert_eq!(r, c, "field addition");
        assert_eq!(s, d, "field subtraction");
    });
}

impl<'a> MulAssign<&'a FieldElement> for FieldElement
{
    fn mul_assign(&mut self, v: &FieldElement)
    {
        let f0    : i32 = self.value[0];
        let f1    : i32 = self.value[1];
        let f2    : i32 = self.value[2];
        let f3    : i32 = self.value[3];
        let f4    : i32 = self.value[4];
        let f5    : i32 = self.value[5];
        let f6    : i32 = self.value[6];
        let f7    : i32 = self.value[7];
        let f8    : i32 = self.value[8];
        let f9    : i32 = self.value[9];
        let g0    : i32 = v.value[0];
        let g1    : i32 = v.value[1];
        let g2    : i32 = v.value[2];
        let g3    : i32 = v.value[3];
        let g4    : i32 = v.value[4];
        let g5    : i32 = v.value[5];
        let g6    : i32 = v.value[6];
        let g7    : i32 = v.value[7];
        let g8    : i32 = v.value[8];
        let g9    : i32 = v.value[9];
        let g1_19 : i32 = 19 * g1; /* 1.959375*2^29 */
        let g2_19 : i32 = 19 * g2; /* 1.959375*2^30; still ok */
        let g3_19 : i32 = 19 * g3;
        let g4_19 : i32 = 19 * g4;
        let g5_19 : i32 = 19 * g5;
        let g6_19 : i32 = 19 * g6;
        let g7_19 : i32 = 19 * g7;
        let g8_19 : i32 = 19 * g8;
        let g9_19 : i32 = 19 * g9;
        let f1_2  : i32 = 2 * f1;
        let f3_2  : i32 = 2 * f3;
        let f5_2  : i32 = 2 * f5;
        let f7_2  : i32 = 2 * f7;
        let f9_2  : i32 = 2 * f9;

        let f0g0    : i64 = (f0 as i64)   * (g0 as i64);
        let f0g1    : i64 = (f0 as i64)   * (g1 as i64);
        let f0g2    : i64 = (f0 as i64)   * (g2 as i64);
        let f0g3    : i64 = (f0 as i64)   * (g3 as i64);
        let f0g4    : i64 = (f0 as i64)   * (g4 as i64);
        let f0g5    : i64 = (f0 as i64)   * (g5 as i64);
        let f0g6    : i64 = (f0 as i64)   * (g6 as i64);
        let f0g7    : i64 = (f0 as i64)   * (g7 as i64);
        let f0g8    : i64 = (f0 as i64)   * (g8 as i64);
        let f0g9    : i64 = (f0 as i64)   * (g9 as i64);
        let f1g0    : i64 = (f1 as i64)   * (g0 as i64);
        let f1g1_2  : i64 = (f1_2 as i64) * (g1 as i64);
        let f1g2    : i64 = (f1 as i64)   * (g2 as i64);
        let f1g3_2  : i64 = (f1_2 as i64) * (g3 as i64);
        let f1g4    : i64 = (f1 as i64)   * (g4 as i64);
        let f1g5_2  : i64 = (f1_2 as i64) * (g5 as i64);
        let f1g6    : i64 = (f1 as i64)   * (g6 as i64);
        let f1g7_2  : i64 = (f1_2 as i64) * (g7 as i64);
        let f1g8    : i64 = (f1 as i64)   * (g8 as i64);
        let f1g9_38 : i64 = (f1_2 as i64) * (g9_19 as i64);
        let f2g0    : i64 = (f2 as i64)   * (g0 as i64);
        let f2g1    : i64 = (f2 as i64)   * (g1 as i64);
        let f2g2    : i64 = (f2 as i64)   * (g2 as i64);
        let f2g3    : i64 = (f2 as i64)   * (g3 as i64);
        let f2g4    : i64 = (f2 as i64)   * (g4 as i64);
        let f2g5    : i64 = (f2 as i64)   * (g5 as i64);
        let f2g6    : i64 = (f2 as i64)   * (g6 as i64);
        let f2g7    : i64 = (f2 as i64)   * (g7 as i64);
        let f2g8_19 : i64 = (f2 as i64)   * (g8_19 as i64);
        let f2g9_19 : i64 = (f2 as i64)   * (g9_19 as i64);
        let f3g0    : i64 = (f3 as i64)   * (g0 as i64);
        let f3g1_2  : i64 = (f3_2 as i64) * (g1 as i64);
        let f3g2    : i64 = (f3 as i64)   * (g2 as i64);
        let f3g3_2  : i64 = (f3_2 as i64) * (g3 as i64);
        let f3g4    : i64 = (f3 as i64)   * (g4 as i64);
        let f3g5_2  : i64 = (f3_2 as i64) * (g5 as i64);
        let f3g6    : i64 = (f3 as i64)   * (g6 as i64);
        let f3g7_38 : i64 = (f3_2 as i64) * (g7_19 as i64);
        let f3g8_19 : i64 = (f3 as i64)   * (g8_19 as i64);
        let f3g9_38 : i64 = (f3_2 as i64) * (g9_19 as i64);
        let f4g0    : i64 = (f4 as i64)   * (g0 as i64);
        let f4g1    : i64 = (f4 as i64)   * (g1 as i64);
        let f4g2    : i64 = (f4 as i64)   * (g2 as i64);
        let f4g3    : i64 = (f4 as i64)   * (g3 as i64);
        let f4g4    : i64 = (f4 as i64)   * (g4 as i64);
        let f4g5    : i64 = (f4 as i64)   * (g5 as i64);
        let f4g6_19 : i64 = (f4 as i64)   * (g6_19 as i64);
        let f4g7_19 : i64 = (f4 as i64)   * (g7_19 as i64);
        let f4g8_19 : i64 = (f4 as i64)   * (g8_19 as i64);
        let f4g9_19 : i64 = (f4 as i64)   * (g9_19 as i64);
        let f5g0    : i64 = (f5 as i64)   * (g0 as i64);
        let f5g1_2  : i64 = (f5_2 as i64) * (g1 as i64);
        let f5g2    : i64 = (f5 as i64)   * (g2 as i64);
        let f5g3_2  : i64 = (f5_2 as i64) * (g3 as i64);
        let f5g4    : i64 = (f5 as i64)   * (g4 as i64);
        let f5g5_38 : i64 = (f5_2 as i64) * (g5_19 as i64);
        let f5g6_19 : i64 = (f5 as i64)   * (g6_19 as i64);
        let f5g7_38 : i64 = (f5_2 as i64) * (g7_19 as i64);
        let f5g8_19 : i64 = (f5 as i64)   * (g8_19 as i64);
        let f5g9_38 : i64 = (f5_2 as i64) * (g9_19 as i64);
        let f6g0    : i64 = (f6 as i64)   * (g0 as i64);
        let f6g1    : i64 = (f6 as i64)   * (g1 as i64);
        let f6g2    : i64 = (f6 as i64)   * (g2 as i64);
        let f6g3    : i64 = (f6 as i64)   * (g3 as i64);
        let f6g4_19 : i64 = (f6 as i64)   * (g4_19 as i64);
        let f6g5_19 : i64 = (f6 as i64)   * (g5_19 as i64);
        let f6g6_19 : i64 = (f6 as i64)   * (g6_19 as i64);
        let f6g7_19 : i64 = (f6 as i64)   * (g7_19 as i64);
        let f6g8_19 : i64 = (f6 as i64)   * (g8_19 as i64);
        let f6g9_19 : i64 = (f6 as i64)   * (g9_19 as i64);
        let f7g0    : i64 = (f7 as i64)   * (g0 as i64);
        let f7g1_2  : i64 = (f7_2 as i64) * (g1 as i64);
        let f7g2    : i64 = (f7 as i64)   * (g2 as i64);
        let f7g3_38 : i64 = (f7_2 as i64) * (g3_19 as i64);
        let f7g4_19 : i64 = (f7 as i64)   * (g4_19 as i64);
        let f7g5_38 : i64 = (f7_2 as i64) * (g5_19 as i64);
        let f7g6_19 : i64 = (f7 as i64)   * (g6_19 as i64);
        let f7g7_38 : i64 = (f7_2 as i64) * (g7_19 as i64);
        let f7g8_19 : i64 = (f7 as i64)   * (g8_19 as i64);
        let f7g9_38 : i64 = (f7_2 as i64) * (g9_19 as i64);
        let f8g0    : i64 = (f8 as i64)   * (g0 as i64);
        let f8g1    : i64 = (f8 as i64)   * (g1 as i64);
        let f8g2_19 : i64 = (f8 as i64)   * (g2_19 as i64);
        let f8g3_19 : i64 = (f8 as i64)   * (g3_19 as i64);
        let f8g4_19 : i64 = (f8 as i64)   * (g4_19 as i64);
        let f8g5_19 : i64 = (f8 as i64)   * (g5_19 as i64);
        let f8g6_19 : i64 = (f8 as i64)   * (g6_19 as i64);
        let f8g7_19 : i64 = (f8 as i64)   * (g7_19 as i64);
        let f8g8_19 : i64 = (f8 as i64)   * (g8_19 as i64);
        let f8g9_19 : i64 = (f8 as i64)   * (g9_19 as i64);
        let f9g0    : i64 = (f9 as i64)   * (g0 as i64);
        let f9g1_38 : i64 = (f9_2 as i64) * (g1_19 as i64);
        let f9g2_19 : i64 = (f9 as i64)   * (g2_19 as i64);
        let f9g3_38 : i64 = (f9_2 as i64) * (g3_19 as i64);
        let f9g4_19 : i64 = (f9 as i64)   * (g4_19 as i64);
        let f9g5_38 : i64 = (f9_2 as i64) * (g5_19 as i64);
        let f9g6_19 : i64 = (f9 as i64)   * (g6_19 as i64);
        let f9g7_38 : i64 = (f9_2 as i64) * (g7_19 as i64);
        let f9g8_19 : i64 = (f9 as i64)   * (g8_19 as i64);
        let f9g9_38 : i64 = (f9_2 as i64) * (g9_19 as i64);
        let mut h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
        let mut h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
        let mut h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
        let mut h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
        let mut h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
        let mut h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
        let mut h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
        let mut h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
        let mut h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
        let mut h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
        let mut carry0;
        let     carry1;
        let     carry2;
        let     carry3;
        let mut carry4;
        let     carry5;
        let     carry6;
        let     carry7;
        let     carry8;
        let     carry9;

        /* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
         *   i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
         * |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
         *   i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */

        carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
        carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
        /* |h0| <= 2^25 */
        /* |h4| <= 2^25 */
        /* |h1| <= 1.71*2^59 */
        /* |h5| <= 1.71*2^59 */

        carry1 = h1 + (1 << 24); h2 += carry1 >> 25; h1 -= carry1 & KTOP_39BITS;
        carry5 = h5 + (1 << 24); h6 += carry5 >> 25; h5 -= carry5 & KTOP_39BITS;
        /* |h1| <= 2^24; from now on fits into int32 */
        /* |h5| <= 2^24; from now on fits into int32 */
        /* |h2| <= 1.41*2^60 */
        /* |h6| <= 1.41*2^60 */

        carry2 = h2 + (1 << 25); h3 += carry2 >> 26; h2 -= carry2 & KTOP_38BITS;
        carry6 = h6 + (1 << 25); h7 += carry6 >> 26; h6 -= carry6 & KTOP_38BITS;
        /* |h2| <= 2^25; from now on fits into int32 unchanged */
        /* |h6| <= 2^25; from now on fits into int32 unchanged */
        /* |h3| <= 1.71*2^59 */
        /* |h7| <= 1.71*2^59 */

        carry3 = h3 + (1 << 24); h4 += carry3 >> 25; h3 -= carry3 & KTOP_39BITS;
        carry7 = h7 + (1 << 24); h8 += carry7 >> 25; h7 -= carry7 & KTOP_39BITS;
        /* |h3| <= 2^24; from now on fits into int32 unchanged */
        /* |h7| <= 2^24; from now on fits into int32 unchanged */
        /* |h4| <= 1.72*2^34 */
        /* |h8| <= 1.41*2^60 */

        carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
        carry8 = h8 + (1 << 25); h9 += carry8 >> 26; h8 -= carry8 & KTOP_38BITS;
        /* |h4| <= 2^25; from now on fits into int32 unchanged */
        /* |h8| <= 2^25; from now on fits into int32 unchanged */
        /* |h5| <= 1.01*2^24 */
        /* |h9| <= 1.71*2^59 */

        carry9 = h9 + (1 << 24); h0 += (carry9 >> 25) * 19; h9 -= carry9 & KTOP_39BITS;
        /* |h9| <= 2^24; from now on fits into int32 unchanged */
        /* |h0| <= 1.1*2^39 */

        carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
        /* |h0| <= 2^25; from now on fits into int32 unchanged */
        /* |h1| <= 1.01*2^24 */

        self.value[0] = h0 as i32;
        self.value[1] = h1 as i32;
        self.value[2] = h2 as i32;
        self.value[3] = h3 as i32;
        self.value[4] = h4 as i32;
        self.value[5] = h5 as i32;
        self.value[6] = h6 as i32;
        self.value[7] = h7 as i32;
        self.value[8] = h8 as i32;
        self.value[9] = h9 as i32;
    }
}

impl<'a,'b> Mul<&'a FieldElement> for &'b FieldElement
{
    type Output = FieldElement;

    fn mul(self, g: &FieldElement) -> FieldElement
    {
        let mut res = self.clone();
        res *= g;
        res
    }
}


#[cfg(test)]
#[test]
fn mul() {
    let fname = "testdata/ed25519/mul.test";
    run_test(fname.to_string(), 3, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negb && !negc);
        let a = test_from_bytes(&abytes);
        let b = test_from_bytes(&bbytes);
        let c = test_from_bytes(&cbytes);
        let r = &a * &b;
        assert_eq!(r, c);
    });
}

pub fn fe_square(h: &mut FieldElement, f: &FieldElement)
{
  let f0      : i32 = f.value[0];
  let f1      : i32 = f.value[1];
  let f2      : i32 = f.value[2];
  let f3      : i32 = f.value[3];
  let f4      : i32 = f.value[4];
  let f5      : i32 = f.value[5];
  let f6      : i32 = f.value[6];
  let f7      : i32 = f.value[7];
  let f8      : i32 = f.value[8];
  let f9      : i32 = f.value[9];
  let f0_2    : i32 = 2 * f0;
  let f1_2    : i32 = 2 * f1;
  let f2_2    : i32 = 2 * f2;
  let f3_2    : i32 = 2 * f3;
  let f4_2    : i32 = 2 * f4;
  let f5_2    : i32 = 2 * f5;
  let f6_2    : i32 = 2 * f6;
  let f7_2    : i32 = 2 * f7;
  let f5_38   : i32 = 38 * f5; /* 1.959375*2^30 */
  let f6_19   : i32 = 19 * f6; /* 1.959375*2^30 */
  let f7_38   : i32 = 38 * f7; /* 1.959375*2^30 */
  let f8_19   : i32 = 19 * f8; /* 1.959375*2^30 */
  let f9_38   : i32 = 38 * f9; /* 1.959375*2^30 */
  let f0f0    : i64 = (f0 as i64)   * (f0 as i64);
  let f0f1_2  : i64 = (f0_2 as i64) * (f1 as i64);
  let f0f2_2  : i64 = (f0_2 as i64) * (f2 as i64);
  let f0f3_2  : i64 = (f0_2 as i64) * (f3 as i64);
  let f0f4_2  : i64 = (f0_2 as i64) * (f4 as i64);
  let f0f5_2  : i64 = (f0_2 as i64) * (f5 as i64);
  let f0f6_2  : i64 = (f0_2 as i64) * (f6 as i64);
  let f0f7_2  : i64 = (f0_2 as i64) * (f7 as i64);
  let f0f8_2  : i64 = (f0_2 as i64) * (f8 as i64);
  let f0f9_2  : i64 = (f0_2 as i64) * (f9 as i64);
  let f1f1_2  : i64 = (f1_2 as i64) * (f1 as i64);
  let f1f2_2  : i64 = (f1_2 as i64) * (f2 as i64);
  let f1f3_4  : i64 = (f1_2 as i64) * (f3_2 as i64);
  let f1f4_2  : i64 = (f1_2 as i64) * (f4 as i64);
  let f1f5_4  : i64 = (f1_2 as i64) * (f5_2 as i64);
  let f1f6_2  : i64 = (f1_2 as i64) * (f6 as i64);
  let f1f7_4  : i64 = (f1_2 as i64) * (f7_2 as i64);
  let f1f8_2  : i64 = (f1_2 as i64) * (f8 as i64);
  let f1f9_76 : i64 = (f1_2 as i64) * (f9_38 as i64);
  let f2f2    : i64 = (f2 as i64)   * (f2 as i64);
  let f2f3_2  : i64 = (f2_2 as i64) * (f3 as i64);
  let f2f4_2  : i64 = (f2_2 as i64) * (f4 as i64);
  let f2f5_2  : i64 = (f2_2 as i64) * (f5 as i64);
  let f2f6_2  : i64 = (f2_2 as i64) * (f6 as i64);
  let f2f7_2  : i64 = (f2_2 as i64) * (f7 as i64);
  let f2f8_38 : i64 = (f2_2 as i64) * (f8_19 as i64);
  let f2f9_38 : i64 = (f2 as i64)   * (f9_38 as i64);
  let f3f3_2  : i64 = (f3_2 as i64) * (f3 as i64);
  let f3f4_2  : i64 = (f3_2 as i64) * (f4 as i64);
  let f3f5_4  : i64 = (f3_2 as i64) * (f5_2 as i64);
  let f3f6_2  : i64 = (f3_2 as i64) * (f6 as i64);
  let f3f7_76 : i64 = (f3_2 as i64) * (f7_38 as i64);
  let f3f8_38 : i64 = (f3_2 as i64) * (f8_19 as i64);
  let f3f9_76 : i64 = (f3_2 as i64) * (f9_38 as i64);
  let f4f4    : i64 = (f4 as i64)   * (f4 as i64);
  let f4f5_2  : i64 = (f4_2 as i64) * (f5 as i64);
  let f4f6_38 : i64 = (f4_2 as i64) * (f6_19 as i64);
  let f4f7_38 : i64 = (f4 as i64)   * (f7_38 as i64);
  let f4f8_38 : i64 = (f4_2 as i64) * (f8_19 as i64);
  let f4f9_38 : i64 = (f4 as i64)   * (f9_38 as i64);
  let f5f5_38 : i64 = (f5 as i64)   * (f5_38 as i64);
  let f5f6_38 : i64 = (f5_2 as i64) * (f6_19 as i64);
  let f5f7_76 : i64 = (f5_2 as i64) * (f7_38 as i64);
  let f5f8_38 : i64 = (f5_2 as i64) * (f8_19 as i64);
  let f5f9_76 : i64 = (f5_2 as i64) * (f9_38 as i64);
  let f6f6_19 : i64 = (f6 as i64)   * (f6_19 as i64);
  let f6f7_38 : i64 = (f6 as i64)   * (f7_38 as i64);
  let f6f8_38 : i64 = (f6_2 as i64) * (f8_19 as i64);
  let f6f9_38 : i64 = (f6 as i64)   * (f9_38 as i64);
  let f7f7_38 : i64 = (f7 as i64)   * (f7_38 as i64);
  let f7f8_38 : i64 = (f7_2 as i64) * (f8_19 as i64);
  let f7f9_76 : i64 = (f7_2 as i64) * (f9_38 as i64);
  let f8f8_19 : i64 = (f8 as i64)   * (f8_19 as i64);
  let f8f9_38 : i64 = (f8 as i64)   * (f9_38 as i64);
  let f9f9_38 : i64 = (f9 as i64)   * (f9_38 as i64);
  let mut h0     : i64 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  let mut h1     : i64 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  let mut h2     : i64 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  let mut h3     : i64 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  let mut h4     : i64 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  let mut h5     : i64 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  let mut h6     : i64 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  let mut h7     : i64 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  let mut h8     : i64 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  let mut h9     : i64 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  let mut carry0 : i64;
  let     carry1 : i64;
  let     carry2 : i64;
  let     carry3 : i64;
  let mut carry4 : i64;
  let     carry5 : i64;
  let     carry6 : i64;
  let     carry7 : i64;
  let     carry8 : i64;
  let     carry9 : i64;

  carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
  carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
  carry1 = h1 + (1 << 24); h2 += carry1 >> 25; h1 -= carry1 & KTOP_39BITS;
  carry5 = h5 + (1 << 24); h6 += carry5 >> 25; h5 -= carry5 & KTOP_39BITS;
  carry2 = h2 + (1 << 25); h3 += carry2 >> 26; h2 -= carry2 & KTOP_38BITS;
  carry6 = h6 + (1 << 25); h7 += carry6 >> 26; h6 -= carry6 & KTOP_38BITS;
  carry3 = h3 + (1 << 24); h4 += carry3 >> 25; h3 -= carry3 & KTOP_39BITS;
  carry7 = h7 + (1 << 24); h8 += carry7 >> 25; h7 -= carry7 & KTOP_39BITS;
  carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
  carry8 = h8 + (1 << 25); h9 += carry8 >> 26; h8 -= carry8 & KTOP_38BITS;
  carry9 = h9 + (1 << 24); h0 += (carry9 >> 25) * 19; h9 -= carry9 & KTOP_39BITS;
  carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;

  h.value[0] = h0 as i32;
  h.value[1] = h1 as i32;
  h.value[2] = h2 as i32;
  h.value[3] = h3 as i32;
  h.value[4] = h4 as i32;
  h.value[5] = h5 as i32;
  h.value[6] = h6 as i32;
  h.value[7] = h7 as i32;
  h.value[8] = h8 as i32;
  h.value[9] = h9 as i32;
}

#[cfg(test)]
#[test]
fn square() {
    let fname = "testdata/ed25519/square.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let     a = test_from_bytes(&abytes);
        let     c = test_from_bytes(&cbytes);
        let mut r = FieldElement::new();
        fe_square(&mut r, &a);
        assert_eq!(r, c);
    });
}

pub fn fe_invert(z: &FieldElement) -> FieldElement
{
  let mut t0   = FieldElement::new();
  let mut t1   = FieldElement::new();
  let mut t2   = FieldElement::new();
  let mut t3   = FieldElement::new();
  let mut temp = FieldElement::new();
  let mut out  = FieldElement::new();

  fe_square(&mut t0, &z);
  fe_square(&mut t1, &t0);
  for _ in 1..2 {
      temp.overwrite_with(&t1);
      fe_square(&mut t1, &temp);
  }
  t1 *= &z;
  t0 *= &t1;
  fe_square(&mut t2, &t0);
  t1 *= &t2;
  fe_square(&mut t2, &t1);
  for _ in 1..5 {
      temp.overwrite_with(&t2);
      fe_square(&mut t2, &temp);
  }
  t1 *= &t2;
  fe_square(&mut t2, &t1);
  for _ in 1..10 {
      temp.overwrite_with(&t2);
      fe_square(&mut t2, &temp);
  }
  t2 *= &t1;
  fe_square(&mut t3, &t2);
  for _ in 1..20 {
      temp.overwrite_with(&t3);
      fe_square(&mut t3, &temp);
  }
  t2 *= &t3;
  temp.overwrite_with(&t2);
  fe_square(&mut t2, &temp);
  for _ in 1..10 {
      temp.overwrite_with(&t2);
      fe_square(&mut t2, &temp);
  }
  t1 *= &t2;
  fe_square(&mut t2, &t1);
  for _ in 1..50 {
      temp.overwrite_with(&t2);
      fe_square(&mut t2, &temp);
  }
  t2 *= &t1;
  fe_square(&mut t3, &t2);
  for _ in 1..100 {
      temp.overwrite_with(&t3);
      fe_square(&mut t3, &temp);
  }
  t2 *= &t3;
  temp.overwrite_with(&t2);
  fe_square(&mut t2, &temp);
  for _ in 1..50 {
      temp.overwrite_with(&t2);
      fe_square(&mut t2, &temp);
  }
  t1 *= &t2;
  temp.overwrite_with(&t1);
  fe_square(&mut t1, &temp);
  for _ in 1..5 {
      temp.overwrite_with(&t1);
      fe_square(&mut t1, &temp);
  }
  &t1 * &t0
}

#[cfg(test)]
#[test]
fn invert() {
    let fname = "testdata/ed25519/invert.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let a = test_from_bytes(&abytes);
        let c = test_from_bytes(&cbytes);
        let r = fe_invert(&a);
        assert_eq!(r, c);
    });
}

pub fn fe_neg(h: &mut FieldElement, f: &FieldElement)
{
    for i in 0..NUM_ELEMENT_LIMBS {
        h.value[i] = -f.value[i];
    }
}

#[cfg(test)]
#[test]
fn negate() {
    let fname = "testdata/ed25519/negate.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let a = test_from_bytes(&abytes);
        let c = test_from_bytes(&cbytes);
        let mut r = FieldElement::new();
        fe_neg(&mut r, &a);
        assert_eq!(r, c);
    });
}

pub fn fe_cmov(f: &mut FieldElement, g: &FieldElement, bl: bool)
{
    let b = if bl { -1 } else { 0 };
    for i in 0..10 {
        let mut x = f.value[i] ^ g.value[i];
        x &= b;
        f.value[i] ^= x;
    }
}

#[cfg(test)]
#[test]
fn cmov() {
    let fname = "testdata/ed25519/cmov.test";
    run_test(fname.to_string(), 3, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negb && !negc);
        let a = test_from_bytes(&abytes);
        let b = bbytes.len() > 1;
        let c = test_from_bytes(&cbytes);
        let mut r = FieldElement::new();
        fe_cmov(&mut r, &a, b);
        assert_eq!(r, c);
    });
}

pub fn fe_isnonzero(f: &FieldElement) -> bool
{
    let s = f.to_bytes();
    let mut res = false;
    for i in 0..32 {
        res |= s[i] != 0;
    }
    res
}

pub fn fe_isnegative(f: &FieldElement) -> bool
{
    let s = f.to_bytes();
    s[0] & 1 == 1
}

#[cfg(test)]
#[test]
fn is_tests() {
    let fname = "testdata/ed25519/istests.test";
    run_test(fname.to_string(), 3, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negz, zbytes) = case.get("z").unwrap();
        let (negn, nbytes) = case.get("n").unwrap();

        assert!(!nega && !negz && !negn);
        let a = test_from_bytes(&abytes);
        println!("a: {:?}", a);
        let z = zbytes.len() > 1;
        let n = nbytes.len() > 1;
        assert_eq!(z, fe_isnonzero(&a));
        assert_eq!(n, fe_isnegative(&a));
    });
}

pub fn fe_sq2(h: &mut FieldElement, f: &FieldElement)
{
    let f0 = f.value[0];
    let f1 = f.value[1];
    let f2 = f.value[2];
    let f3 = f.value[3];
    let f4 = f.value[4];
    let f5 = f.value[5];
    let f6 = f.value[6];
    let f7 = f.value[7];
    let f8 = f.value[8];
    let f9 = f.value[9];
    let f0_2 = 2 * f0;
    let f1_2 = 2 * f1;
    let f2_2 = 2 * f2;
    let f3_2 = 2 * f3;
    let f4_2 = 2 * f4;
    let f5_2 = 2 * f5;
    let f6_2 = 2 * f6;
    let f7_2 = 2 * f7;
    let f5_38 = 38 * f5; /* 1.959375*2^30 */
    let f6_19 = 19 * f6; /* 1.959375*2^30 */
    let f7_38 = 38 * f7; /* 1.959375*2^30 */
    let f8_19 = 19 * f8; /* 1.959375*2^30 */
    let f9_38 = 38 * f9; /* 1.959375*2^30 */
    let f0f0    = (f0    as i64) * (f0 as i64);
    let f0f1_2  = (f0_2  as i64) * (f1 as i64);
    let f0f2_2  = (f0_2  as i64) * (f2 as i64);
    let f0f3_2  = (f0_2  as i64) * (f3 as i64);
    let f0f4_2  = (f0_2  as i64) * (f4 as i64);
    let f0f5_2  = (f0_2  as i64) * (f5 as i64);
    let f0f6_2  = (f0_2  as i64) * (f6 as i64);
    let f0f7_2  = (f0_2  as i64) * (f7 as i64);
    let f0f8_2  = (f0_2  as i64) * (f8 as i64);
    let f0f9_2  = (f0_2  as i64) * (f9 as i64);
    let f1f1_2  = (f1_2  as i64) * (f1 as i64);
    let f1f2_2  = (f1_2  as i64) * (f2 as i64);
    let f1f3_4  = (f1_2  as i64) * (f3_2 as i64);
    let f1f4_2  = (f1_2  as i64) * (f4 as i64);
    let f1f5_4  = (f1_2  as i64) * (f5_2 as i64);
    let f1f6_2  = (f1_2  as i64) * (f6 as i64);
    let f1f7_4  = (f1_2  as i64) * (f7_2 as i64);
    let f1f8_2  = (f1_2  as i64) * (f8 as i64);
    let f1f9_76 = (f1_2  as i64) * (f9_38 as i64);
    let f2f2    = (f2    as i64) * (f2 as i64);
    let f2f3_2  = (f2_2  as i64) * (f3 as i64);
    let f2f4_2  = (f2_2  as i64) * (f4 as i64);
    let f2f5_2  = (f2_2  as i64) * (f5 as i64);
    let f2f6_2  = (f2_2  as i64) * (f6 as i64);
    let f2f7_2  = (f2_2  as i64) * (f7 as i64);
    let f2f8_38 = (f2_2  as i64) * (f8_19 as i64);
    let f2f9_38 = (f2    as i64) * (f9_38 as i64);
    let f3f3_2  = (f3_2  as i64) * (f3 as i64);
    let f3f4_2  = (f3_2  as i64) * (f4 as i64);
    let f3f5_4  = (f3_2  as i64) * (f5_2 as i64);
    let f3f6_2  = (f3_2  as i64) * (f6 as i64);
    let f3f7_76 = (f3_2  as i64) * (f7_38 as i64);
    let f3f8_38 = (f3_2  as i64) * (f8_19 as i64);
    let f3f9_76 = (f3_2  as i64) * (f9_38 as i64);
    let f4f4    = (f4    as i64) * (f4 as i64);
    let f4f5_2  = (f4_2  as i64) * (f5 as i64);
    let f4f6_38 = (f4_2  as i64) * (f6_19 as i64);
    let f4f7_38 = (f4    as i64) * (f7_38 as i64);
    let f4f8_38 = (f4_2  as i64) * (f8_19 as i64);
    let f4f9_38 = (f4    as i64) * (f9_38 as i64);
    let f5f5_38 = (f5    as i64) * (f5_38 as i64);
    let f5f6_38 = (f5_2  as i64) * (f6_19 as i64);
    let f5f7_76 = (f5_2  as i64) * (f7_38 as i64);
    let f5f8_38 = (f5_2  as i64) * (f8_19 as i64);
    let f5f9_76 = (f5_2  as i64) * (f9_38 as i64);
    let f6f6_19 = (f6    as i64) * (f6_19 as i64);
    let f6f7_38 = (f6    as i64) * (f7_38 as i64);
    let f6f8_38 = (f6_2  as i64) * (f8_19 as i64);
    let f6f9_38 = (f6    as i64) * (f9_38 as i64);
    let f7f7_38 = (f7    as i64) * (f7_38 as i64);
    let f7f8_38 = (f7_2  as i64) * (f8_19 as i64);
    let f7f9_76 = (f7_2  as i64) * (f9_38 as i64);
    let f8f8_19 = (f8    as i64) * (f8_19 as i64);
    let f8f9_38 = (f8    as i64) * (f9_38 as i64);
    let f9f9_38 = (f9    as i64) * (f9_38 as i64);
    let mut h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
    let mut h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
    let mut h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
    let mut h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
    let mut h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
    let mut h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
    let mut h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
    let mut h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
    let mut h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
    let mut h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
    let mut carry0;
    let     carry1;
    let     carry2;
    let     carry3;
    let mut carry4;
    let     carry5;
    let     carry6;
    let     carry7;
    let     carry8;
    let     carry9;

    h0 += h0;
    h1 += h1;
    h2 += h2;
    h3 += h3;
    h4 += h4;
    h5 += h5;
    h6 += h6;
    h7 += h7;
    h8 += h8;
    h9 += h9;

    carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
    carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;

    carry1 = h1 + (1 << 24); h2 += carry1 >> 25; h1 -= carry1 & KTOP_39BITS;
    carry5 = h5 + (1 << 24); h6 += carry5 >> 25; h5 -= carry5 & KTOP_39BITS;

    carry2 = h2 + (1 << 25); h3 += carry2 >> 26; h2 -= carry2 & KTOP_38BITS;
    carry6 = h6 + (1 << 25); h7 += carry6 >> 26; h6 -= carry6 & KTOP_38BITS;

    carry3 = h3 + (1 << 24); h4 += carry3 >> 25; h3 -= carry3 & KTOP_39BITS;
    carry7 = h7 + (1 << 24); h8 += carry7 >> 25; h7 -= carry7 & KTOP_39BITS;

    carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
    carry8 = h8 + (1 << 25); h9 += carry8 >> 26; h8 -= carry8 & KTOP_38BITS;

    carry9 = h9 + (1 << 24); h0 += (carry9 >> 25) * 19; h9 -= carry9 & KTOP_39BITS;

    carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;

    h.value[0] = h0 as i32;
    h.value[1] = h1 as i32;
    h.value[2] = h2 as i32;
    h.value[3] = h3 as i32;
    h.value[4] = h4 as i32;
    h.value[5] = h5 as i32;
    h.value[6] = h6 as i32;
    h.value[7] = h7 as i32;
    h.value[8] = h8 as i32;
    h.value[9] = h9 as i32;
}

#[cfg(test)]
#[test]
fn square2() {
    let fname = "testdata/ed25519/square2.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let     a = test_from_bytes(&abytes);
        let     c = test_from_bytes(&cbytes);
        let mut r = FieldElement::new();
        fe_sq2(&mut r, &a);
        assert_eq!(r, c);
    });
}

pub fn fe_pow22523(z: &FieldElement) -> FieldElement
{
  let mut t0 = FieldElement::new();
  let mut t1 = FieldElement::new();
  let mut t2 = FieldElement::new();
  let mut temp;

  fe_square(&mut t0, &z);
  fe_square(&mut t1, &t0);
  for _ in 1..2 {
      let temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t1 *= &z;
  t0 *= &t1;
  temp = t0.clone();
  fe_square(&mut t0, &temp);
  t0 *= &t1;
  fe_square(&mut t1, &t0);
  for _ in 1..5 {
      temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t0 *= &t1;
  fe_square(&mut t1, &t0);
  for _ in 1..10 {
      temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t1 *= &t0;
  fe_square(&mut t2, &t1);
  for _ in 1..20 {
      temp = t2.clone();
      fe_square(&mut t2, &temp);
  }
  t1 *= &t2;
  temp = t1.clone();
  fe_square(&mut t1, &temp);
  for _ in 1..10 {
      temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t0 *= &t1;
  fe_square(&mut t1, &t0);
  for _ in 1..50 {
      temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t1 *= &t0;
  fe_square(&mut t2, &t1);
  for _ in 1..100 {
      temp = t2.clone();
      fe_square(&mut t2, &temp);
  }
  t1 *= &t2;
  temp = t1.clone();
  fe_square(&mut t1, &temp);
  for _ in 1..50 {
      temp = t1.clone();
      fe_square(&mut t1, &temp);
  }
  t0 *= &t1;
  temp = t0.clone();
  fe_square(&mut t0, &temp);
  for _ in 1..2 {
      temp = t0.clone();
      fe_square(&mut t0, &temp);
  }
  &t0 * &z
}

#[cfg(test)]
#[test]
fn pow22523() {
    let fname = "testdata/ed25519/pow22523.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let a = test_from_bytes(&abytes);
        let c = test_from_bytes(&cbytes);
        let r = fe_pow22523(&a);
        assert_eq!(r, c);
    });
}
