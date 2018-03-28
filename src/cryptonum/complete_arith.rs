macro_rules! derive_arithmetic_operators
{
    ($type: ident, $cl: ident, $fn: ident, $asncl: ident, $asnfn: ident) => {
        impl $asncl for $type {
            fn $asnfn(&mut self, other: $type) {
                self.$asnfn(&other)
            }
        }

        impl $cl for $type {
            type Output = $type;

            fn $fn(self, other: $type) -> $type {
                let mut res = self.clone();
                res.$asnfn(&other);
                res
            }
        }

        impl<'a> $cl<&'a $type> for $type {
            type Output = $type;

            fn $fn(self, other: &$type) -> $type {
                let mut res = self.clone();
                res.$asnfn(other);
                res
            }
        }

        impl<'a> $cl<$type> for &'a $type {
            type Output = $type;

            fn $fn(self, other: $type) -> $type {
                let mut res = self.clone();
                res.$asnfn(&other);
                res
            }
        }

        impl<'a,'b> $cl<&'a $type> for &'b $type {
            type Output = $type;

            fn $fn(self, other: &$type) -> $type {
                let mut res = self.clone();
                res.$asnfn(other);
                res
            }
        }
    }
}

macro_rules! derive_shift_operators
{
    ($type: ident, $asncl: ident, $cl: ident,
                   $asnfn: ident, $fn: ident,
                   $base: ident) =>
    {
        impl $asncl<$base> for $type {
            fn $asnfn(&mut self, rhs: $base) {
                self.$asnfn(rhs as u64);
            }
        }

        derive_shifts_from_shift_assign!($type, $asncl, $cl,
                                                $asnfn, $fn,
                                                $base);
    }
}

macro_rules! derive_shifts_from_shift_assign
{
    ($type: ident, $asncl: ident, $cl: ident,
                   $asnfn: ident, $fn: ident,
                   $base: ident) =>
    {
        impl $cl<$base> for $type {
            type Output = $type;

            fn $fn(self, rhs: $base) -> $type {
                let mut copy = self.clone();
                copy.$asnfn(rhs);
                copy
            }
        }

        impl<'a> $cl<$base> for &'a $type {
            type Output = $type;

            fn $fn(self, rhs: $base) -> $type {
                let mut copy = self.clone();
                copy.$asnfn(rhs);
                copy
            }
        }
    }
}

macro_rules! derive_signed_shift_operators
{
    ($type: ident, $base: ident, $signed_base: ident) => {
        impl ShlAssign<$signed_base> for $type {
            fn shl_assign(&mut self, rhs: $signed_base) {
                if rhs < 0 {
                    self.shr_assign(-rhs);
                } else {
                    self.shl_assign(rhs as $base);
                }
            }
        }

        impl ShrAssign<$signed_base> for $type {
            fn shr_assign(&mut self, rhs: $signed_base) {
                if rhs < 0 {
                    self.shl_assign(-rhs);
                } else {
                    self.shr_assign(rhs);
                }
            }
        }

        derive_shifts_from_shift_assign!($type, ShlAssign, Shl,
                                                shl_assign, shl, $signed_base);
        derive_shifts_from_shift_assign!($type, ShrAssign, Shr,
                                                shr_assign, shr, $signed_base);
    }
}
