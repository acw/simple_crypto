use cryptonum::{U192,   U256,   U384,   U512,   U576,
                U1024,  U2048,  U3072,  U4096,  U8192,
                U15360};
use std::cmp::{Ord,Ordering};

pub fn bignum_cmp(x: &[u64], y: &[u64]) -> Ordering {
    assert_eq!(x.len(), y.len());
    let xiter = x.iter().rev();
    let yiter = y.iter().rev();

    for (x,y) in xiter.zip(yiter) {
        match x.cmp(&y) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less    => return Ordering::Less,
            Ordering::Equal   => continue
        }
    }

    Ordering::Equal
}

pub fn bignum_ge(x: &[u64], y: &[u64]) -> bool {
    match bignum_cmp(x,y) {
        Ordering::Greater => true,
        Ordering::Less    => false,
        Ordering::Equal   => true
    }
}

macro_rules! generate_compares
{
    ($name: ident) => {
        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                bignum_cmp(&self.values, &other.values) == Ordering::Equal
            }
        }

        impl Eq for $name {}

        impl Ord for $name {
            fn cmp(&self, other: &$name) -> Ordering {
                bignum_cmp(&self.values, &other.values)
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<Ordering> {
                Some(bignum_cmp(&self.values, &other.values))
            }
        }
    }
}

generate_compares!(U192);
generate_compares!(U256);
generate_compares!(U384);
generate_compares!(U512);
generate_compares!(U576);
generate_compares!(U1024);
generate_compares!(U2048);
generate_compares!(U3072);
generate_compares!(U4096);
generate_compares!(U8192);
generate_compares!(U15360);
