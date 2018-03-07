macro_rules! construct_unsigned {
    ($type: ident, $modname: ident, $count: expr) => {
        #[derive(Clone)]
        pub struct $type {
            contents: [u64; $count]
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

        impl $type {
            /// 0!
            pub fn zero() -> $type {
                $type { contents: [0; $count] }
            }

            /// The maximum possible value we can hold.
            pub fn max() -> $type {
                $type { contents: [0xFFFFFFFFFFFFFFFF; $count] }
            }

            from_to!($type, $count, u8,  from_u8,  to_u8);
            from_to!($type, $count, u16, from_u16, to_u16);
            from_to!($type, $count, u32, from_u32, to_u32);
            from_to!($type, $count, u64, from_u64, to_u64);
        }

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

        opers2!($type,BitOrAssign,bitor_assign,BitOr,bitor,generic_bitor);
        opers2!($type,BitAndAssign,bitand_assign,BitAnd,bitand,generic_bitand);
        opers2!($type,BitXorAssign,bitxor_assign,BitXor,bitxor,generic_bitxor);

        shifts!($type, usize);
        shifts!($type, u64);
        shifts!($type, i64);
        shifts!($type, u32);
        shifts!($type, i32);
        shifts!($type, u16);
        shifts!($type, i16);
        shifts!($type, u8);
        shifts!($type, i8);

        opers2!($type,AddAssign,add_assign,Add,add,generic_add);
        opers2!($type,SubAssign,sub_assign,Sub,sub,generic_sub);
        opers3!($type,MulAssign,mul_assign,Mul,mul,generic_mul);

        impl DivAssign<$type> for $type {
            fn div_assign(&mut self, rhs: $type) {
                let mut dead = [0; $count];
                let     copy = self.contents.clone();
                generic_div(&copy, &rhs.contents,
                            &mut self.contents, &mut dead);
            }
        }

        impl<'a> DivAssign<&'a $type> for $type {
            fn div_assign(&mut self, rhs: &$type) {
                let mut dead = [0; $count];
                let     copy = self.contents.clone();
                generic_div(&copy, &rhs.contents,
                            &mut self.contents, &mut dead);
            }
        }

        impl Div<$type> for $type {
            type Output = $type;

            fn div(self, rhs: $type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut res.contents, &mut dead);
                res
            }
        }

        impl<'a> Div<$type> for &'a $type {
            type Output = $type;

            fn div(self, rhs: $type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut res.contents, &mut dead);
                res
            }
        }

        impl<'a> Div<&'a $type> for $type {
            type Output = $type;

            fn div(self, rhs: &$type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut res.contents, &mut dead);
                res
            }
        }

        impl<'a,'b> Div<&'a $type> for &'b $type {
            type Output = $type;

            fn div(self, rhs: &$type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut res.contents, &mut dead);
                res
            }
        }

        impl RemAssign<$type> for $type {
            fn rem_assign(&mut self, rhs: $type) {
                let mut dead = [0; $count];
                let     copy = self.contents.clone();
                generic_div(&copy, &rhs.contents,
                            &mut dead, &mut self.contents);
            }
        }

        impl<'a> RemAssign<&'a $type> for $type {
            fn rem_assign(&mut self, rhs: &$type) {
                let mut dead = [0; $count];
                let     copy = self.contents.clone();
                generic_div(&copy, &rhs.contents,
                            &mut dead, &mut self.contents);
            }
        }

        impl Rem<$type> for $type {
            type Output = $type;

            fn rem(self, rhs: $type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut dead, &mut res.contents);
                res
            }
        }

        impl<'a> Rem<$type> for &'a $type {
            type Output = $type;

            fn rem(self, rhs: $type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut dead, &mut res.contents);
                res
            }
        }

        impl<'a> Rem<&'a $type> for $type {
            type Output = $type;

            fn rem(self, rhs: &$type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut dead, &mut res.contents);
                res
            }
        }

        impl<'a,'b> Rem<&'a $type> for &'b $type {
            type Output = $type;

            fn rem(self, rhs: &$type) -> $type {
                let mut res = $type::zero();
                let mut dead = [0; $count];
                generic_div(&self.contents, &rhs.contents,
                            &mut dead, &mut res.contents);
                res
            }
        }

        impl CryptoNum for $type {
            fn divmod(&self, a: &$type, q: &mut $type, r: &mut $type) {
                generic_div(&self.contents, &a.contents,
                            &mut q.contents, &mut r.contents);
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
                assert_eq!($type{ contents: buffer }, $type::from_u8(0));
                buffer[0] = 0x7F;
                assert_eq!($type{ contents: buffer }, $type::from_u8(0x7F));
                buffer[0] = 0x7F7F;
                assert_eq!($type{ contents: buffer }, $type::from_u16(0x7F7F));
                buffer[0] = 0xCA5CADE5;
                assert_eq!($type{ contents: buffer },
                           $type::from_u32(0xCA5CADE5));
                assert_eq!($type{ contents: buffer },
                           $type::from_u64(0xCA5CADE5));
                buffer[0] = 0xFFFFFFFFFFFFFFFF;
                assert_eq!($type{ contents: buffer },
                           $type::from_u64(0xFFFFFFFFFFFFFFFF));
            }

            #[test]
            fn test_max() {
                assert_eq!($type::from_u64(u64::max_value()).to_u64(),
                           u64::max_value());
                assert_eq!($type::max().to_u64(), u64::max_value());
                assert_eq!($type::max() + $type::from_u8(1), $type::zero());
            }

            quickcheck! {
                fn builder_u8_upgrade_u16(x: u8) -> bool {
                    $type::from_u8(x) == $type::from_u16(x as u16)
                }
                fn builder_u16_upgrade_u32(x: u16) -> bool {
                    $type::from_u16(x) == $type::from_u32(x as u32)
                }
                fn builder_u32_upgrade_u64(x: u32) -> bool {
                    $type::from_u32(x) == $type::from_u64(x as u64)
                }
                fn builder_u8_roundtrips(x: u8) -> bool {
                    x == $type::from_u8(x).to_u8()
                }
                fn builder_u16_roundtrips(x: u16) -> bool {
                    x == $type::from_u16(x).to_u16()
                }
                fn builder_u32_roundtrips(x: u32) -> bool {
                    x == $type::from_u32(x).to_u32()
                }
                fn builder_u64_roundtrips(x: u64) -> bool {
                    x == $type::from_u64(x).to_u64()
                }
            }

            quickcheck! {
                fn partial_ord64_works(x: u64, y: u64) -> bool {
                    let xbig = $type::from_u64(x);
                    let ybig = $type::from_u64(y);
                    xbig.partial_cmp(&ybig) == x.partial_cmp(&y)
                }
                fn ord64_works(x: u64, y: u64) -> bool {
                    let xbig = $type::from_u64(x);
                    let ybig = $type::from_u64(y);
                    xbig.cmp(&ybig) == x.cmp(&y)
                }
            }

            quickcheck! {
                fn and_annulment(x: $type) -> bool {
                    (x & $type::zero()) == $type::zero()
                }
                fn or_annulment(x: $type) -> bool {
                    (x | $type::max()) == $type::max()
                }
                fn and_identity(x: $type) -> bool {
                    (&x & $type::max()) == x
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
                    (&x | !&x) == $type::max()
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
                    let x512 = $type::from_u64(x);
                    let y512 = $type::from_u64(y);
                    let z512 = x512 | y512;
                    z512.to_u64() == (x | y)
                }
                fn small_and_check(x: u64, y: u64) -> bool {
                    let x512 = $type::from_u64(x);
                    let y512 = $type::from_u64(y);
                    let z512 = x512 & y512;
                    z512.to_u64() == (x & y)
                }
                fn small_xor_check(x: u64, y: u64) -> bool {
                    let x512 = $type::from_u64(x);
                    let y512 = $type::from_u64(y);
                    let z512 = x512 ^ y512;
                    z512.to_u64() == (x ^ y)
                }
                fn small_neg_check(x: u64) -> bool {
                    let x512 = $type::from_u64(x);
                    let z512 = !x512;
                    z512.to_u64() == !x
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
                           $type::from_u64(0));
                assert_eq!($type::from_u8(2) << 1, $type::from_u8(4));
                let mut buffer = [0; $count];
                buffer[1] = 1;
                assert_eq!($type::from_u8(1) << 64,
                           $type{ contents: buffer.clone() });
                buffer[0] = 0xFFFFFFFFFFFFFFFE;
                assert_eq!($type::from_u64(0xFFFFFFFFFFFFFFFF) << 1,
                           $type{ contents: buffer.clone() });
                buffer[0] = 0;
                buffer[1] = 4;
                assert_eq!($type::from_u8(1) << 66,
                           $type{ contents: buffer.clone() });
                assert_eq!($type::from_u8(1) << 1, $type::from_u8(2));
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
                           $type::from_u8(0));
                assert_eq!($type::from_u8(2) >> 1,
                           $type::from_u8(1));
                let mut oneleft = [0; $count];
                oneleft[1] = 1;
                assert_eq!($type{ contents: oneleft.clone() } >> 1,
                           $type::from_u64(0x8000000000000000));
                assert_eq!($type{ contents: oneleft.clone() } >> 64,
                           $type::from_u64(1));
                oneleft[1] = 4;
                assert_eq!($type{ contents: oneleft.clone() } >> 66,
                           $type::from_u64(1));
            }

            quickcheck! {
                fn shift_mask_equivr(x: $type, in_shift: usize) -> bool {
                    let shift       = in_shift % ($count * 64);
                    let mask        = $type::max() << shift;
                    let masked_x    = &x & mask;
                    let shift_maskr = (x >> shift) << shift;
                    shift_maskr == masked_x
                }
                fn shift_mask_equivl(x: $type, in_shift: usize) -> bool {
                    let shift       = in_shift % ($count * 64);
                    let mask        = $type::max() >> shift;
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
                assert_eq!($type::from_u64(1) + $type::from_u64(0xFFFFFFFFFFFFFFFF),
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
                           $type::from_u64(0));
                let mut buffer = [0; $count];
                buffer[1] = 1;
                assert_eq!($type{ contents: buffer.clone() } - $type::from_u64(1),
                           $type::from_u64(0xFFFFFFFFFFFFFFFF));
                assert_eq!($type::zero() - $type::from_u8(1), $type::max());
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
                assert_eq!($type::from_u8(1) * $type::from_u8(1),
                           $type::from_u8(1));
                assert_eq!($type::from_u8(1) * $type::from_u8(0),
                           $type::from_u8(0));
                assert_eq!($type::from_u8(1) * $type::from_u8(2),
                           $type::from_u8(2));
                let mut temp = $type::zero();
                temp.contents[0] = 1;
                temp.contents[1] = 0xFFFFFFFFFFFFFFFE;
                assert_eq!($type::from_u64(0xFFFFFFFFFFFFFFFF) *
                           $type::from_u64(0xFFFFFFFFFFFFFFFF),
                           temp);
                let effs = $type{ contents: [0xFFFFFFFFFFFFFFFF; $count] };
                assert_eq!($type::from_u8(1) * &effs, effs);
                temp = effs.clone();
                temp.contents[0] = temp.contents[0] - 1;
                assert_eq!($type::from_u8(2) * &effs, temp);
            }

            quickcheck! {
                fn mul_symmetry(a: $type, b: $type) -> bool {
                    (&a * &b) == (&b * &a)
                }
                fn mul_commutivity(a: $type, b: $type, c: $type) -> bool {
                    (&a * (&b * &c)) == ((&a * &b) * &c)
                }
                fn mul_identity(a: $type) -> bool {
                    (&a * $type::from_u64(1)) == a
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
                    (&a << 1) == (&a * $type::from_u64(2))
                }
                fn mul16shift4_equiv(a: $type) -> bool {
                    (&a << 4) == (&a * $type::from_u64(16))
                }
            }

            #[test]
            fn div_tests() {
                assert_eq!($type::from_u8(2) / $type::from_u8(2),
                           $type::from_u8(1));
                assert_eq!($type::from_u8(2) / $type::from_u8(1),
                           $type::from_u8(2));
                assert_eq!($type::from_u8(4) / $type::from_u8(3),
                           $type::from_u8(1));
                assert_eq!($type::from_u8(4) / $type::from_u8(5),
                           $type::from_u8(0));
                assert_eq!($type::from_u8(4) / $type::from_u8(4),
                           $type::from_u8(1));
                let mut temp1 = $type::zero();
                let mut temp2 = $type::zero();
                temp1.contents[$count - 1] = 4;
                temp2.contents[$count - 1] = 4;
                assert_eq!(&temp1 / temp2, $type::from_u8(1));
                assert_eq!(&temp1 / $type::from_u8(1), temp1);
                temp1.contents[$count - 1] = u64::max_value();
                assert_eq!(&temp1 / $type::from_u8(1), temp1);
            }

            #[test]
            #[should_panic]
            fn div0_fails() {
                $type::from_u64(0xabcd) / $type::zero();
            }

            #[test]
            fn mod_tests() {
                assert_eq!($type::from_u8(4) % $type::from_u8(5),
                           $type::from_u8(4));
                assert_eq!($type::from_u8(5) % $type::from_u8(4),
                           $type::from_u8(1));
                let fives = $type{ contents: [5; $count] };
                let fours = $type{ contents: [4; $count] };
                let ones  = $type{ contents: [1; $count] };
                assert_eq!(fives % fours, ones);
            }

            #[test]
            fn divmod_tests() {
                let     a = $type::from_u64(4);
                let     b = $type::from_u64(3);
                let mut q = $type::zero();
                let mut r = $type::zero();
                a.divmod(&b, &mut q, &mut r);
                let mut x = [0; $count];
                x[0] = 1;
                assert_eq!(q, $type{ contents: x });
                assert_eq!(r, $type{ contents: x });
            }

            quickcheck! {
                #[ignore]
                fn div_identity(a: $type) -> bool {
                    &a / $type::from_u64(1) == a
                }
                fn div_self_is_one(a: $type) -> bool {
                    if a == $type::zero() {
                        return true;
                    }
                    &a / &a == $type::from_u64(1)
                }
                fn euclid_is_alive(a: $type, b: $type) -> bool {
                    let mut q = $type::zero();
                    let mut r = $type::zero();
                    a.divmod(&b, &mut q, &mut r);
                    a == ((b * q) + r)
                }
            }

        }
    };
}

macro_rules! from_to {
    ($type: ident, $count: expr, $base: ty, $from: ident, $to: ident) => {
        /// Convert the given base type into this type. This is always safe.
        pub fn $from(x: $base) -> $type {
            let mut res = $type { contents: [0; $count] };
            res.contents[0] = x as u64;
            res
        }

        /// Convert this back into a base type. This is the equivalent of
        /// masking off the relevant number of bits, and should work just
        /// like the `as` keyword with normal word types.
        pub fn $to(&self) -> $base {
            self.contents[0] as $base
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

macro_rules! opers2 {
    ($type:ident,$asncl:ident,$asnfn:ident,$cl:ident,$fn:ident,$impl:ident) => {
        impl $asncl for $type {
            fn $asnfn(&mut self, other: $type) {
                $impl(&mut self.contents, &other.contents);
            }
        }

        impl<'a> $asncl<&'a $type> for $type {
            fn $asnfn(&mut self, other: &$type) {
                $impl(&mut self.contents, &other.contents);
            }
        }

        impl $cl for $type {
            type Output = $type;

            fn $fn(self, rhs: $type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &rhs.contents);
                copy
            }
        }

        impl<'a> $cl<&'a $type> for $type {
            type Output = $type;

            fn $fn(self, rhs: &$type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &rhs.contents);
                copy
            }
        }

        impl<'a> $cl<$type> for &'a $type {
            type Output = $type;

            fn $fn(self, rhs: $type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &rhs.contents);
                copy
            }
        }

        impl<'a,'b> $cl<&'a $type> for &'b $type {
            type Output = $type;

            fn $fn(self, rhs: &$type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &rhs.contents);
                copy
            }
        }
    }
}

macro_rules! opers3 {
    ($type:ident,$asncl:ident,$asnfn:ident,$cl:ident,$fn:ident,$impl:ident) => {
        impl $asncl for $type {
            fn $asnfn(&mut self, other: $type) {
                let copy = self.contents.clone();
                $impl(&mut self.contents, &copy, &other.contents);
            }
        }

        impl<'a> $asncl<&'a $type> for $type {
            fn $asnfn(&mut self, other: &$type) {
                let copy = self.contents.clone();
                $impl(&mut self.contents, &copy, &other.contents);
            }
        }

        impl $cl for $type {
            type Output = $type;

            fn $fn(self, rhs: $type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &self.contents, &rhs.contents);
                copy
            }
        }

        impl<'a> $cl<&'a $type> for $type {
            type Output = $type;

            fn $fn(self, rhs: &$type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &self.contents, &rhs.contents);
                copy
            }
        }

        impl<'a> $cl<$type> for &'a $type {
            type Output = $type;

            fn $fn(self, rhs: $type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &self.contents, &rhs.contents);
                copy
            }
        }

        impl<'a,'b> $cl<&'a $type> for &'b $type {
            type Output = $type;

            fn $fn(self, rhs: &$type) -> $type {
                let mut copy = self.clone();
                $impl(&mut copy.contents, &self.contents, &rhs.contents);
                copy
            }
        }
    }
}
