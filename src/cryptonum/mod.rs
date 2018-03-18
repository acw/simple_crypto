//! # Simple-Crypto CryptoNum
//!
//! This module is designed to provide large, fixed-width number support for
//! the rest of the Simple-Crypto libraries. Feel free to use it other places,
//! of course, but that's its origin.
//!
//! Key generation is supported, using either the native `OsRng` or a random
//! number generator of your choice. Obviously, you should be careful to use
//! a cryptographically-sound random number generator sufficient for the
//! security level you're going for.
//!
//! Signing and verification are via standard PKCS1 padding, but can be
//! adjusted based on the exact hash you want. This library also supports
//! somewhat arbitrary signing mechanisms used by your weirder network
//! protocols. (I'm looking at you, Tor.)
//!
//! Encryption and decryption are via the OAEP mechanism, as described in
//! NIST documents.
//!
#[macro_use]
mod arithmetic_traits;
#[macro_use]
mod barrett;
#[macro_use]
mod conversions;
mod core;
#[macro_use]
mod modops;
#[macro_use]
mod primes;
#[macro_use]
mod signed;
#[macro_use]
mod unsigned;
mod traits;

use cryptonum::core::*;
use num::{BigUint,BigInt};
use rand::Rng;
use std::cmp::Ordering;
use std::fmt::{Debug,Error,Formatter};
use std::ops::*;
pub use self::traits::*;

construct_unsigned!(U512,   BarretMu512,   u512,     8);
construct_unsigned!(U1024,  BarretMu1024,  u1024,   16);
construct_unsigned!(U2048,  BarretMu2048,  u2048,   32);
construct_unsigned!(U3072,  BarretMu3072,  u3072,   48);
construct_unsigned!(U4096,  BarretMu4096,  u4096,   64);
construct_unsigned!(U7680,  BarretMu7680,  u7680,  120);
construct_unsigned!(U8192,  BarretMu8192,  u8192,  128);
construct_unsigned!(U15360, BarretMu15360, u15360, 240);

construct_signed!(I512,   U512,   i512);
construct_signed!(I1024,  U1024,  i1024);
construct_signed!(I2048,  U2048,  i2048);
construct_signed!(I3072,  U3072,  i3072);
construct_signed!(I4096,  U4096,  i4096);
construct_signed!(I7680,  U7680,  i7680);
construct_signed!(I8192,  U8192,  i8192);
construct_signed!(I15360, U15360, i15360);

