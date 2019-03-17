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
extern crate chrono;
extern crate cryptonum;
extern crate digest;
extern crate hmac;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate rand;
extern crate sha1;
extern crate sha2;
#[macro_use]
extern crate simple_asn1;

/// The `rsa` module provides bare-bones support for RSA signing, verification,
/// encryption, decryption, and key generation.
pub mod rsa;
/// The `dsa` module provides bare-bones support for DSA signing, verification,
/// and key generation. You shouldn't need to use these if you're building a
/// new system, but might need to use them to interact with legacy systems or
/// protocols.
pub mod dsa;
/// The `ecdsa` module provides bare-bones support for ECDSA signing,
/// verification, and key generation.
pub mod ecdsa;
/// The `ssh` module provides support for parsing OpenSSH-formatted SSH keys,
/// both public and private.
pub mod ssh;
/// The `x509` module supports parsing and generating x.509 certificates, as
/// used by TLS and others.
pub mod x509;

#[cfg(test)]
mod testing;
mod utils;
