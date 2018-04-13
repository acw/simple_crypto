#[macro_use]
mod conversions;
#[macro_use]
mod complete_arith;
mod signed;
mod unsigned;
#[cfg(test)]
mod gold_tests;

pub use self::signed::SCN;
pub use self::unsigned::UCN;


