macro_rules! construct_signed {
    ($type: ident, $base: ident, $modname: ident) => {
        #[derive(Clone,PartialEq,Eq)]
        pub struct $type {
            negative: bool,
            value: $base
        }

        impl Debug for $type {
            fn fmt(&self, f: &mut Formatter) -> Result<(),Error> {
                if self.negative {
                    f.write_str("-")?;
                } else {
                    f.write_str("+")?;
                }
                self.value.fmt(f)
            }
        }

        impl<'a> PartialEq<&'a $type> for $type {
            fn eq(&self, other: &&$type) -> bool {
                (self.negative == other.negative) &&
                (self.value    == other.value)
            }
        }

        impl PartialOrd for $type {
            fn partial_cmp(&self, other: &$type) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $type {
            fn cmp(&self, other: &$type) -> Ordering {
                match (self.negative, other.negative) {
                    (true,  true)  =>
                        self.value.cmp(&other.value).reverse(),
                    (true,  false) => Ordering::Greater,
                    (false, true)  => Ordering::Less,
                    (false, false) =>
                        self.value.cmp(&other.value)
                }
            }
        }

        impl CryptoNumBase for $type {
            fn zero() -> $type {
                $type{ negative: false, value: $base::zero() }
            }
            fn max_value() -> $type {
                $type{ negative: false, value: $base::max_value() }
            }
            fn is_zero(&self) -> bool {
                self.value.is_zero()
            }
            fn is_odd(&self) -> bool {
                self.value.is_odd()
            }
            fn is_even(&self) -> bool {
                self.value.is_even()
            }
        }

        impl CryptoNumFastMod for $type {
            type BarrettMu = <$base as CryptoNumFastMod>::BarrettMu;

            fn barrett_mu(&self) -> Option<Self::BarrettMu> {
                if self.negative {
                    None
                } else {
                    self.value.barrett_mu()
                }
            }

            fn fastmod(&self, mu: &Self::BarrettMu) -> $type {
                let res = self.value.fastmod(mu);
                $type{ negative: self.negative, value: res }
            }
        }

        impl CryptoNumSigned for $type {
            type Unsigned = $base;

            fn new(v: $base) -> $type {
                $type{ negative: false, value: v.clone() }
            }
            fn abs(&self) -> $base {
                self.value.clone()
            }
            fn is_positive(&self) -> bool {
                !self.negative
            }
            fn is_negative(&self) -> bool {
                self.negative
            }
        }

        impl Neg for $type {
            type Output = $type;

            fn neg(self) -> $type {
                (&self).neg()
            }
        }

        impl<'a> Neg for &'a $type {
            type Output = $type;

            fn neg(self) -> $type {
                if self.value.is_zero() {
                    $type{ negative: false, value: self.value.clone() }
                } else {
                    $type{ negative: !self.negative, value: self.value.clone() }
                }
            }
        }

        define_arithmetic!($type,AddAssign,add_assign,Add,add,self,other,{
            let signs_match = self.negative == other.negative;
            let ordering    = self.value.cmp(&other.value);

            match (signs_match, ordering) {
                (true, _) =>
                    // if the signs are the same, we maintain the sign and
                    // just increase the magnitude
                    self.value.add_assign(&other.value),
                (false, Ordering::Equal) => {
                    // if the signs are different and the numbers are equal,
                    // we just set this to zero. However, we actually do the
                    // subtraction to make the timing roughly similar.
                    self.negative = false;
                    self.value.sub_assign(&other.value)
                }
                (false, Ordering::Less) => {
                    // if the signs are different and the first one is less
                    // than the second, then we flip the sign and subtract.
                    self.negative = !self.negative;
                    let mut other_copy = other.value.clone();
                    other_copy.sub_assign(&self.value);
                    self.value = other_copy;
                }
                (false, Ordering::Greater) => {
                    // if the signs are different and the first one is
                    // greater than the second, then we leave the sign and
                    // subtract.
                    self.value.sub_assign(&other.value)
                }
            }
        });

        define_arithmetic!($type,SubAssign,sub_assign,Sub,sub,self,other,{
            // this is a bit inefficient, but a heck of a lot easier.
            let mut other2 = other.clone();
            other2.negative = !other2.negative;
            self.add_assign(&other2)
        });

        define_arithmetic!($type,MulAssign,mul_assign,Mul,mul,self,other,{
            self.negative = self.negative ^ other.negative;
            self.value.mul_assign(&other.value);
        });

        define_arithmetic!($type,DivAssign,div_assign,Div,div,self,other,{
            self.negative = self.negative ^ other.negative;
            self.value.div_assign(&other.value);
        });

        define_arithmetic!($type,RemAssign,rem_assign,Rem,rem,self,other,{
            self.value.rem_assign(&other.value);
        });

        generate_signed_conversions!($type, $base);

        #[cfg(test)]
        mod $modname {
            use quickcheck::{Arbitrary,Gen};
            use super::*;

            impl Arbitrary for $type {
                fn arbitrary<G: Gen>(g: &mut G) -> $type {
                    let value = $base::arbitrary(g);
                    if value.is_zero() {
                        $type{ negative: false, value: value }
                    } else {
                        $type{ negative: g.gen_weighted_bool(2), value: value }
                    }
                }
            }

            quickcheck! {
                fn double_negation(x: $type) -> bool {
                    (- (- &x)) == &x
                }
                fn add_identity(x: $type) -> bool {
                    (&x + $type::zero()) == &x
                }
                fn add_commutivity(x: $type, y: $type) -> bool {
                    (&x + &y) == (&y + &x)
                }
                fn add_associativity(a: $type, b: $type, c: $type) -> bool {
                    // we shift these to get away from rollover
                    let x = $type{ negative: a.negative, value: a.value >> 2 };
                    let y = $type{ negative: b.negative, value: b.value >> 2 };
                    let z = $type{ negative: c.negative, value: c.value >> 2 };
                    (&x + (&y + &z)) == ((&x + &y) + &z)
                }
                fn sub_is_add_negation(x: $type, y: $type) -> bool {
                    (&x - &y) == (&x + (- &y))
                }
                fn sub_destroys(x: $type) -> bool {
                    (&x - &x) == $type::zero()
                }
                fn mul_identity(x: $type) -> bool {
                    (&x * $type::from(1)) == &x
                }
                fn mul_commutivity(x: $type, y: $type) -> bool {
                    (&x * &y) == (&y * &x)
                }
                fn mul_associativity(a: $type, b: $type, c: $type) -> bool {
                    // we shift these to get away from rollover
                    let s = (a.value.bit_size() / 2) - 2;
                    let x = $type{ negative: a.negative, value: a.value >> s };
                    let y = $type{ negative: b.negative, value: b.value >> s };
                    let z = $type{ negative: c.negative, value: c.value >> s };
                    (&x * (&y * &z)) == ((&x * &y) * &z)
                }
                #[ignore]
                fn div_identity(a: $type) -> bool {
                    &a / $type::from(1) == a
                }
                fn div_self_is_one(a: $type) -> bool {
                    (&a / &a) == $type::from(1)
                }
            }
        }
    }
}
