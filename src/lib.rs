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

extern crate digest;
extern crate hmac;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate rand;
extern crate sha1;
extern crate sha2;
extern crate simple_asn1;

/// The `cryptonum` module provides support for large numbers for use in various
/// cryptographically-relevant algorithms.
pub mod cryptonum;
/// The `rsa` module provides support for RSA-related core algorithms, including
/// signing / verification and encryption / decryption. You can also generate
/// key material there.
pub mod rsa;
/// The `dsa` module provides support for DSA-related signing and verification
/// algorithms, as well as key generation. That being said: don't use this,
/// unless you've got a legacy application or system that you're trying to
/// interact with. DSA is almost always the wrong choice.
pub mod dsa;

#[cfg(test)]
mod testing;

#[cfg(test)]
mod test {
}
