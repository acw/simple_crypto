#[macro_use]
mod conversions;

use num::{BigUint,ToPrimitive,Zero};
use std::cmp::Ordering;

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
}
