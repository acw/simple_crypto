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
mod core;
#[macro_use]
mod builder;
mod signed;
mod traits;
mod unsigned;

pub use self::signed::{I512,I1024,I2048,I3072,I4096,I7680,I8192,I15360};
pub use self::unsigned::{U512,U1024,U2048,U3072,U4096,U7680,U8192,U15360};
pub use self::traits::*;
