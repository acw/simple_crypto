//! # Simple-Crypto CryptoNum
//!
//! This module is designed to provide large, fixed-width number support for
//! the rest of the Simple-Crypto libraries. Feel free to use it other places,
//! of course, but that's its origin.
mod core;
#[macro_use]
mod builder;
mod extended_math;
// mod primes;
mod signed;
mod traits;
mod unsigned;

pub use self::extended_math::{modexp,modinv,extended_euclidean,egcd};
// pub use self::primes::{probably_prime};
pub use self::signed::{I512,I1024,I2048,I3072,I4096,I7680,I8192,I15360};
pub use self::unsigned::{U512,U1024,U2048,U3072,U4096,U7680,U8192,U15360};
