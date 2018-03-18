macro_rules! construct_unsigned {
    ($type: ident, $barrett: ident, $modname: ident, $count: expr) => {
        #[derive(Clone)]
        pub struct $type {
            contents: [u64; $count]
        }

        pub struct $barrett {
            k: usize,
            progenitor: $type,
            contents: [u64; $count + 1]
        }

        impl PartialEq for $type {
            fn eq(&self, other: &$type) -> bool {
                for i in 0..$count {
                    if self.contents[i] != other.contents[i] {
                        return false;
                    }
                }
                true
            }
        }

        impl Eq for $type {}

        impl Debug for $type {
            fn fmt(&self, f: &mut Formatter) -> Result<(),Error> {
                f.write_str("CryptoNum{{ ")?;
                f.debug_list().entries(self.contents.iter()).finish()?;
                f.write_str(" }}")
            }
        }

        impl Debug for $barrett {
            fn fmt(&self, f: &mut Formatter) -> Result<(),Error> {
                f.write_str("BarrettMu{{ ")?;
                f.write_fmt(format_args!("k = {}, ", self.k))?;
                f.write_fmt(format_args!("progen = {:?}, ",self.progenitor))?;
                f.write_str("contents: ")?;
                f.debug_list().entries(self.contents.iter()).finish()?;
                f.write_str(" }}")
            }
        }

        generate_unsigned_conversions!($type, $count);

        impl PartialOrd for $type {
            fn partial_cmp(&self, other: &$type) -> Option<Ordering> {
                Some(generic_cmp(&self.contents, &other.contents))
            }
        }

        impl Ord for $type {
            fn cmp(&self, other: &$type) -> Ordering {
                generic_cmp(&self.contents, &other.contents)
            }
        }

        impl Not for $type {
            type Output = $type;

            fn not(self) -> $type {
                let mut output = self.clone();
                generic_not(&mut output.contents);
                output
            }
        }

        impl<'a> Not for &'a $type {
            type Output = $type;

            fn not(self) -> $type {
                let mut output = self.clone();
                generic_not(&mut output.contents);
                output
            }
        }

        define_arithmetic!($type,BitOrAssign,bitor_assign,BitOr,bitor,self,other,{
            generic_bitor(&mut self.contents, &other.contents);
        });
        define_arithmetic!($type,BitAndAssign,bitand_assign,BitAnd,bitand,self,other,{
            generic_bitand(&mut self.contents, &other.contents);
        });
        define_arithmetic!($type,BitXorAssign,bitxor_assign,BitXor,bitxor,self,other,{
            generic_bitxor(&mut self.contents, &other.contents);
        });
        define_arithmetic!($type,AddAssign,add_assign,Add,add,self,other,{
            generic_add(&mut self.contents, &other.contents);
        });
        define_arithmetic!($type,SubAssign,sub_assign,Sub,sub,self,other,{
            generic_sub(&mut self.contents, &other.contents);
        });
        define_arithmetic!($type,MulAssign,mul_assign,Mul,mul,self,other,{
            let copy = self.contents.clone();
            generic_mul(&mut self.contents, &copy, &other.contents);
        });
        define_arithmetic!($type,DivAssign,div_assign,Div,div,self,other,{
            let mut dead = [0; $count];
            let     copy = self.contents.clone();
            generic_div(&copy, &other.contents,
                        &mut self.contents, &mut dead);
        });
        define_arithmetic!($type,RemAssign,rem_assign,Rem,rem,self,other,{
            let mut dead = [0; $count];
            let     copy = self.contents.clone();
            generic_div(&copy, &other.contents,
                        &mut dead, &mut self.contents);
        });

        shifts!($type, usize);
        shifts!($type, u64);
        shifts!($type, i64);
        shifts!($type, u32);
        shifts!($type, i32);
        shifts!($type, u16);
        shifts!($type, i16);
        shifts!($type, u8);
        shifts!($type, i8);

        impl CryptoNumBase for $type {
            fn zero() -> $type {
                $type { contents: [0; $count] }
            }

            fn max_value() -> $type {
                $type { contents: [0xFFFFFFFFFFFFFFFF; $count] }
            }

            fn is_zero(&self) -> bool {
                for x in self.contents.iter() {
                    if *x != 0 {
                        return false;
                    }
                }
                true
            }

            fn is_odd(&self) -> bool {
                (self.contents[0] & 1) == 1
            }

            fn is_even(&self) -> bool {
                (self.contents[0] & 1) == 0
            }
        }

        impl CryptoNumSerialization for $type {
            fn bit_size(&self) -> usize {
                $count * 64
            }

            fn byte_size(&self) -> usize {
                $count * 8
            }

            fn to_bytes(&self) -> Vec<u8> {
                let mut res = Vec::with_capacity($count * 8);
                for x in self.contents.iter() {
                    res.push( (x >> 56) as u8 );
                    res.push( (x >> 48) as u8 );
                    res.push( (x >> 40) as u8 );
                    res.push( (x >> 32) as u8 );
                    res.push( (x >> 24) as u8 );
                    res.push( (x >> 16) as u8 );
                    res.push( (x >>  8) as u8 );
                    res.push( (x >>  0) as u8 );
                }
                res
            }

            fn from_bytes(x: &[u8]) -> $type {
                let mut res = $type::zero();
                let mut i = 0;

                assert!(x.len() >= ($count * 8));
                for chunk in x.chunks(8) {
                    assert!(chunk.len() == 8);
                    res.contents[i] = ((chunk[0] as u64) << 56) |
                                      ((chunk[1] as u64) << 48) |
                                      ((chunk[2] as u64) << 40) |
                                      ((chunk[3] as u64) << 32) |
                                      ((chunk[4] as u64) << 24) |
                                      ((chunk[5] as u64) << 16) |
                                      ((chunk[6] as u64) <<  8) |
                                      ((chunk[7] as u64) <<  0);
                    i += 1;
                }
                assert!(i == $count);
                res
            }
        }

        derive_barrett!($type, $barrett, $count);
        derive_modulo_operations!($type);
        derive_prime_operations!($type);

        impl Into<BigInt> for $type {
            fn into(self) -> BigInt {
                panic!("into bigint")
            }
        }

        impl Into<BigUint> for $type {
            fn into(self) -> BigUint {
                panic!("into big uint")
            }
        }

        impl From<BigInt> for $type {
            fn from(_x: BigInt) -> Self {
                panic!("from bigint")
            }
        }

        impl From<BigUint> for $type {
            fn from(_x: BigUint) -> Self {
                panic!("from biguint")
            }
        }

        #[cfg(test)]
        mod $modname {
            use quickcheck::{Arbitrary,Gen};
            use super::*;

            impl Arbitrary for $type {
                fn arbitrary<G: Gen>(g: &mut G) -> $type {
                    let mut res = [0; $count];

                    for i in 0..$count {
                        res[i] = g.next_u64();
                    }
                    $type{ contents: res }
                }
            }

            #[test]
            fn test_builders() {
                let mut buffer = [0; $count];
                assert_eq!($type{ contents: buffer }, $type::from(0 as u8));
                buffer[0] = 0x7F;
                assert_eq!($type{ contents: buffer }, $type::from(0x7F as u8));
                buffer[0] = 0x7F7F;
                assert_eq!($type{ contents: buffer }, $type::from(0x7F7F as u16));
                buffer[0] = 0xCA5CADE5;
                assert_eq!($type{ contents: buffer },
                           $type::from(0xCA5CADE5 as u32));
                assert_eq!($type{ contents: buffer },
                           $type::from(0xCA5CADE5 as u32));
                buffer[0] = 0xFFFFFFFFFFFFFFFF;
                assert_eq!($type{ contents: buffer },
                           $type::from(0xFFFFFFFFFFFFFFFF as u64));
            }

            #[test]
            fn test_max() {
                let max64: u64 = $type::from(u64::max_value()).into();
                assert_eq!(max64, u64::max_value());
                let max64v: u64 = $type::max_value().into();
                assert_eq!(max64v, u64::max_value());
                assert_eq!($type::max_value() + $type::from(1 as u8), $type::zero());
            }

            quickcheck! {
                fn builder_u8_upgrade_u16(x: u8) -> bool {
                    $type::from(x) == $type::from(x as u16)
                }
                fn builder_u16_upgrade_u32(x: u16) -> bool {
                    $type::from(x) == $type::from(x as u32)
                }
                fn builder_u32_upgrade_u64(x: u32) -> bool {
                    $type::from(x) == $type::from(x as u64)
                }
                fn builder_u8_roundtrips(x: u8) -> bool {
                    let thereback: u8 = $type::from(x).into();
                    x == thereback
                }
                fn builder_u16_roundtrips(x: u16) -> bool {
                    let thereback: u16 = $type::from(x).into();
                    x == thereback
                }
                fn builder_u32_roundtrips(x: u32) -> bool {
                    let thereback: u32 = $type::from(x).into();
                    x == thereback
                }
                fn builder_u64_roundtrips(x: u64) -> bool {
                    let thereback: u64 = $type::from(x).into();
                    x == thereback
                }
            }

            quickcheck! {
                fn partial_ord64_works(x: u64, y: u64) -> bool {
                    let xbig = $type::from(x);
                    let ybig = $type::from(y);
                    xbig.partial_cmp(&ybig) == x.partial_cmp(&y)
                }
                fn ord64_works(x: u64, y: u64) -> bool {
                    let xbig = $type::from(x);
                    let ybig = $type::from(y);
                    xbig.cmp(&ybig) == x.cmp(&y)
                }
            }

            quickcheck! {
                fn and_annulment(x: $type) -> bool {
                    (x & $type::zero()) == $type::zero()
                }
                fn or_annulment(x: $type) -> bool {
                    (x | $type::max_value()) == $type::max_value()
                }
                fn and_identity(x: $type) -> bool {
                    (&x & $type::max_value()) == x
                }
                fn or_identity(x: $type) -> bool {
                    (&x | $type::zero()) == x
                }
                fn and_idempotent(x: $type) -> bool {
                    (&x & &x) == x
                }
                fn or_idempotent(x: $type) -> bool {
                    (&x | &x) == x
                }
                fn and_complement(x: $type) -> bool {
                    (&x & &x) == x
                }
                fn or_complement(x: $type) -> bool {
                    (&x | !&x) == $type::max_value()
                }
                fn and_commutative(x: $type, y: $type) -> bool {
                    (&x & &y) == (&y & &x)
                }
                fn or_commutative(x: $type, y: $type) -> bool {
                    (&x | &y) == (&y | &x)
                }
                fn double_negation(x: $type) -> bool {
                    !!&x == x
                }
                fn or_distributive(a: $type, b: $type, c: $type) -> bool {
                    (&a & (&b | &c)) == ((&a & &b) | (&a & &c))
                }
                fn and_distributive(a: $type, b: $type, c: $type) -> bool {
                    (&a | (&b & &c)) == ((&a | &b) & (&a | &c))
                }
                fn or_absorption(a: $type, b: $type) -> bool {
                    (&a | (&a & &b)) == a
                }
                fn and_absorption(a: $type, b: $type) -> bool {
                    (&a & (&a | &b)) == a
                }
                fn or_associative(a: $type, b: $type, c: $type) -> bool {
                    (&a | (&b | &c)) == ((&a | &b) | &c)
                }
                fn and_associative(a: $type, b: $type, c: $type) -> bool {
                    (&a & (&b & &c)) == ((&a & &b) & &c)
                }
                fn xor_as_defined(a: $type, b: $type) -> bool {
                    (&a ^ &b) == ((&a | &b) & !(&a & &b))
                }
                fn small_or_check(x: u64, y: u64) -> bool {
                    let x512 = $type::from(x);
                    let y512 = $type::from(y);
                    let z512 = x512 | y512;
                    let res: u64 = z512.into();
                    res == (x | y)
                }
                fn small_and_check(x: u64, y: u64) -> bool {
                    let x512 = $type::from(x);
                    let y512 = $type::from(y);
                    let z512 = x512 & y512;
                    let res: u64 = z512.into();
                    res == (x & y)
                }
                fn small_xor_check(x: u64, y: u64) -> bool {
                    let x512 = $type::from(x);
                    let y512 = $type::from(y);
                    let z512 = x512 ^ y512;
                    let res: u64 = z512.into();
                    res == (x ^ y)
                }
                fn small_neg_check(x: u64) -> bool {
                    let x512 = $type::from(x);
                    let z512 = !x512;
                    let res: u64 = z512.into();
                    res == !x
                }
            }

            #[test]
            fn shl_tests() {
                let ones = [1; $count];
                assert_eq!($type{ contents: ones.clone() } << 0,
                           $type{ contents: ones.clone() });
                let mut notones = [0; $count];
                for i in 0..$count {
                    notones[i] = (i + 1) as u64;
                }
                assert_eq!($type{ contents: notones.clone() } << 0,
                           $type{ contents: notones.clone() });
                assert_eq!($type{ contents: ones.clone() } << ($count * 64),
                           $type::zero());
                assert_eq!($type::from(2 as u8) << 1, $type::from(4 as u8));
                let mut buffer = [0; $count];
                buffer[1] = 1;
                assert_eq!($type::from(1 as u8) << 64,
                           $type{ contents: buffer.clone() });
                buffer[0] = 0xFFFFFFFFFFFFFFFE;
                assert_eq!($type::from(0xFFFFFFFFFFFFFFFF as u64) << 1,
                           $type{ contents: buffer.clone() });
                buffer[0] = 0;
                buffer[1] = 4;
                assert_eq!($type::from(1 as u8) << 66,
                           $type{ contents: buffer.clone() });
                assert_eq!($type::from(1 as u8) << 1, $type::from(2 as u8));
            }

            #[test]
            fn shr_tests() {
                let ones  = [1; $count];
                assert_eq!($type{ contents: ones.clone() } >> 0,
                           $type{ contents: ones.clone() });
                let mut notones = [0; $count];
                for i in 0..$count {
                    notones[i] = (i + 1) as u64;
                }
                assert_eq!($type{ contents: ones.clone() } >> 0,
                           $type{ contents: ones.clone() });
                assert_eq!($type{ contents: ones.clone() } >> ($count * 64),
                           $type::zero());
                assert_eq!($type::from(2 as u8) >> 1,
                           $type::from(1 as u8));
                let mut oneleft = [0; $count];
                oneleft[1] = 1;
                assert_eq!($type{ contents: oneleft.clone() } >> 1,
                           $type::from(0x8000000000000000 as u64));
                assert_eq!($type{ contents: oneleft.clone() } >> 64,
                           $type::from(1 as u64));
                oneleft[1] = 4;
                assert_eq!($type{ contents: oneleft.clone() } >> 66,
                           $type::from(1 as u64));
            }

            quickcheck! {
                fn shift_mask_equivr(x: $type, in_shift: usize) -> bool {
                    let shift       = in_shift % ($count * 64);
                    let mask        = $type::max_value() << shift;
                    let masked_x    = &x & mask;
                    let shift_maskr = (x >> shift) << shift;
                    shift_maskr == masked_x
                }
                fn shift_mask_equivl(x: $type, in_shift: usize) -> bool {
                    let shift       = in_shift % ($count * 64);
                    let mask        = $type::max_value() >> shift;
                    let masked_x    = &x & mask;
                    let shift_maskl = (x << shift) >> shift;
                    shift_maskl == masked_x
                }
            }

            #[test]
            fn add_tests() {
                let ones = [1; $count];
                let twos = [2; $count];
                assert_eq!($type{ contents: ones.clone() } +
                           $type{ contents: ones.clone() },
                           $type{ contents: twos.clone() });
                let mut buffer = [0; $count];
                buffer[1] = 1;
                assert_eq!($type::from(1 as u64) +
                           $type::from(0xFFFFFFFFFFFFFFFF as u64),
                           $type{ contents: buffer.clone() });
                let mut high = [0; $count];
                high[$count - 1] = 0xFFFFFFFFFFFFFFFF;
                buffer[1] = 0;
                buffer[$count - 1] = 1;
                assert_eq!($type{ contents: buffer } + $type{ contents: high },
                           $type{ contents: [0; $count] });
            }

            quickcheck! {
                fn add_symmetry(a: $type, b: $type) -> bool {
                    (&a + &b) == (&b + &a)
                }
                fn add_commutivity(a: $type, b: $type, c: $type) -> bool {
                    (&a + (&b + &c)) == ((&a + &b) + &c)
                }
                fn add_identity(a: $type) -> bool {
                    (&a + $type::zero()) == a
                }
            }

            #[test]
            fn sub_tests() {
                let ones = [1; $count];
                assert_eq!($type{ contents: ones.clone() } -
                           $type{ contents: ones.clone() },
                           $type::zero());
                let mut buffer = [0; $count];
                buffer[1] = 1;
                assert_eq!($type{contents:buffer.clone()} - $type::from(1 as u8),
                           $type::from(0xFFFFFFFFFFFFFFFF as u64));
                assert_eq!($type::zero() - $type::from(1 as u8),
                           $type::max_value());
            }

            quickcheck! {
                fn sub_destroys(a: $type) -> bool {
                    (&a - &a) == $type::zero()
                }
                fn sub_add_ident(a: $type, b: $type) -> bool {
                    ((&a - &b) + &b) == a
                }
            }

            #[test]
            fn mul_tests() {
                assert_eq!($type::from(1 as u8) * $type::from(1 as u8),
                           $type::from(1 as u8));
                assert_eq!($type::from(1 as u8) * $type::from(0 as u8),
                           $type::from(0 as u8));
                assert_eq!($type::from(1 as u8) * $type::from(2 as u8),
                           $type::from(2 as u8));
                let mut temp = $type::zero();
                temp.contents[0] = 1;
                temp.contents[1] = 0xFFFFFFFFFFFFFFFE;
                assert_eq!($type::from(0xFFFFFFFFFFFFFFFF as u64) *
                           $type::from(0xFFFFFFFFFFFFFFFF as u64),
                           temp);
                let effs = $type{ contents: [0xFFFFFFFFFFFFFFFF; $count] };
                assert_eq!($type::from(1 as u8) * &effs, effs);
                temp = effs.clone();
                temp.contents[0] = temp.contents[0] - 1;
                assert_eq!($type::from(2 as u8) * &effs, temp);
            }

            quickcheck! {
                fn mul_symmetry(a: $type, b: $type) -> bool {
                    (&a * &b) == (&b * &a)
                }
                fn mul_commutivity(a: $type, b: $type, c: $type) -> bool {
                    (&a * (&b * &c)) == ((&a * &b) * &c)
                }
                fn mul_identity(a: $type) -> bool {
                    (&a * $type::from(1 as u8)) == a
                }
                fn mul_zero(a: $type) -> bool {
                    (&a * $type::zero()) == $type::zero()
                }
            }

            quickcheck! {
                fn addmul_distribution(a: $type, b: $type, c: $type) -> bool {
                    (&a * (&b + &c)) == ((&a * &b) + (&a * &c))
                }
                fn submul_distribution(a: $type, b: $type, c: $type) -> bool {
                    (&a * (&b - &c)) == ((&a * &b) - (&a * &c))
                }
                fn mul2shift1_equiv(a: $type) -> bool {
                    (&a << 1) == (&a * $type::from(2 as u8))
                }
                fn mul16shift4_equiv(a: $type) -> bool {
                    (&a << 4) == (&a * $type::from(16 as u8))
                }
            }

            #[test]
            fn div_tests() {
                assert_eq!($type::from(2 as u8) / $type::from(2 as u8),
                           $type::from(1 as u8));
                assert_eq!($type::from(2 as u8) / $type::from(1 as u8),
                           $type::from(2 as u8));
                assert_eq!($type::from(4 as u8) / $type::from(3 as u8),
                           $type::from(1 as u8));
                assert_eq!($type::from(4 as u8) / $type::from(5 as u8),
                           $type::from(0 as u8));
                assert_eq!($type::from(4 as u8) / $type::from(4 as u8),
                           $type::from(1 as u8));
                let mut temp1 = $type::zero();
                let mut temp2 = $type::zero();
                temp1.contents[$count - 1] = 4;
                temp2.contents[$count - 1] = 4;
                assert_eq!(&temp1 / temp2, $type::from(1 as u8));
                assert_eq!(&temp1 / $type::from(1 as u8), temp1);
                temp1.contents[$count - 1] = u64::max_value();
                assert_eq!(&temp1 / $type::from(1 as u8), temp1);
            }

            #[test]
            #[should_panic]
            fn div0_fails() {
                $type::from(0xabcd as u16) / $type::zero();
            }

            #[test]
            fn mod_tests() {
                assert_eq!($type::from(4 as u16) % $type::from(5 as u16),
                           $type::from(4 as u16));
                assert_eq!($type::from(5 as u16) % $type::from(4 as u16),
                           $type::from(1 as u16));
                let fives = $type{ contents: [5; $count] };
                let fours = $type{ contents: [4; $count] };
                let ones  = $type{ contents: [1; $count] };
                assert_eq!(fives % fours, ones);
            }

            quickcheck! {
                #[ignore]
                fn div_identity(a: $type) -> bool {
                    &a / $type::from(1 as u16) == a
                }
                fn div_self_is_one(a: $type) -> bool {
                    if a == $type::zero() {
                        return true;
                    }
                    &a / &a == $type::from(1 as u16)
                }
                fn euclid_is_alive(a: $type, b: $type) -> bool {
                    let q = &a / &b;
                    let r = &a % &b;
                    a == ((b * q) + r)
                }
            }

            quickcheck! {
                fn serialization_inverts(a: $type) -> bool {
                    let bytes = a.to_bytes();
                    let b = $type::from_bytes(&bytes);
                    a == b
                }
            }

            quickcheck! {
                fn fastmod_works(a: $type, b: $type) -> bool {
                    assert!(b != $type::zero());
                    match b.barrett_mu() {
                        None =>
                            true,
                        Some(barrett) => {
                            a.fastmod(&barrett) == (&a % &b)
                        }
                    }
                }
            }
        }
    };
}

macro_rules! shifts {
    ($type: ident, $shtype: ty) => {
        shifts!($type, $shtype, ShlAssign, shl_assign, Shl, shl, generic_shl);
        shifts!($type, $shtype, ShrAssign, shr_assign, Shr, shr, generic_shr);
    };

    ($type: ident, $shtype: ty, $asncl: ident, $asnfn: ident,
     $cl: ident, $fn: ident, $impl: ident) => {
        impl $asncl<$shtype> for $type {
            fn $asnfn(&mut self, amount: $shtype) {
                let copy = self.contents.clone();
                $impl(&mut self.contents, &copy, amount as usize);
            }
        }

        impl $cl<$shtype> for $type {
            type Output = $type;

            fn $fn(self, rhs: $shtype) -> $type {
                let mut res = self.clone();
                $impl(&mut res.contents, &self.contents, rhs as usize);
                res
            }
        }

        impl<'a> $cl<$shtype> for &'a $type {
            type Output = $type;

            fn $fn(self, rhs: $shtype) -> $type {
                let mut res = self.clone();
                $impl(&mut res.contents, &self.contents, rhs as usize);
                res
            }
        }
    }
}
