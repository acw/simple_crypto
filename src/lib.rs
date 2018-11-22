//! # Simple Crypto: A quaint little crypto library for rust.
//!
//! This is the simple_crypto library. Its goal is to provide straightforward
//! coverage of most of the common cryptographic algorithms used today, along
//! with simplified interfaces for new users. If you see something that's
//! unclear, please point it out! We can always use documentation help.
//!
//! This main library will eventually provide most of the convenience functions
//! that a new user should use, along with documentation regarding how and
//! when they should use it, and examples. For now, it mostly just fowards
//! off to more detailed modules. Help requested!
extern crate byteorder;
extern crate cryptonum;
extern crate digest;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate num;
extern crate rand;
extern crate sha1;
extern crate sha2;
extern crate simple_asn1;

/// The `rsa` module provides bare-bones support for RSA signing, verification,
/// encryption, decryption, and key generation.
pub mod rsa;

#[cfg(test)]
mod testing;
mod utils;
