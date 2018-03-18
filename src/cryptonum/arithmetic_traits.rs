macro_rules! define_arithmetic {
    ($type: ident, $asncl: ident, $asnfn: ident,
                   $cl: ident, $clfn: ident,
                   $self: ident, $o: ident, $body: block) =>
    {
        build_assign_operator!($type, $asncl, $asnfn, $self, $o, $body);
        derive_arithmetic_operators!($type, $cl, $clfn, $asncl, $asnfn);
    }
}

macro_rules! build_assign_operator {
    ($type: ident, $asncl: ident, $asnfn: ident, $self: ident,
                   $o: ident, $body: block) =>
    {
        impl<'a> $asncl<&'a $type> for $type {
            fn $asnfn(&mut $self, $o: &$type) $body
        }
    }
}

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
