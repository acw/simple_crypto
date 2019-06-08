//! The SHA family of hash functions, as defined by NIST; specifically, from
//! NIST 180-4 (for SHA1 and SHA2) and NIST 202 (for SHA3).
//! 
//! These hash functions are used through their instantiation of the `Hash`
//! trait, located in the parent `simple_crypto` module and re-exported
//! here for convenience. Thus, you're not going to see a lot of functions
//! or macros, here, just the type declarations.
//! 
//! To use SHA2-384, as an example, you could run the following code:
//! 
//! ```rust
//! use simple_crypto::sha::{Hash,SHA384};
//! 
//! let empty: [u8; 0] = [0; 0];
//! let mut digest_incremental = SHA384::new();
//! digest_incremental.update(&empty);
//! digest_incremental.update(&empty);
//! digest_incremental.update(&empty);
//! let result = digest_incremental.finalize();
//! 
//! assert_eq!(result, vec![0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,
//!                         0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
//!                         0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,
//!                         0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
//!                         0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,
//!                         0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b]);
//! ```
//! 
//! For other hashes, just substitute the appropriate hash structure for
//! `SHA384`. The `Hash` trait also includes a do-it-all-at-once built-in
//! function for those cases when you just have a single blob of data
//! you want to hash, rather than an incremental set of data:
//! 
//! ```rust
//! use simple_crypto::sha::{Hash,SHA3_256};
//! 
//! let empty: [u8; 0] = [0; 0];
//! let result = SHA3_256::hash(&empty);
//! 
//! assert_eq!(result, vec![0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,
//!                         0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
//!                         0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,
//!                         0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a]);
//! ```
//! 
//! In general, you should not use SHA1 for anything but supporting legacy
//! systems. We recommend either SHA2 or SHA3 at their 256-, 384-, or 512-bit
//! sizes. NIST claims (in FIPS 202, page 23-24) that SHA2 and SHA3 are
//! approximately equivalent in terms of security for collision, preimate,
//! and second preimage attacks, but that SHA3 improves upon SHA2 against
//! length-extension and other attacks. On the other hand, SHA2 has been
//! banged on for a little longer, and there's some claims that it's more
//! resistant to quantum attacks. So ... make your own decisions.
#[macro_use]
mod shared;
mod sha1;
mod sha2;
mod sha3;

pub use super::Hash;
pub use self::sha1::SHA1;
pub use self::sha2::{SHA224,SHA256,SHA384,SHA512};
pub use self::sha3::{SHA3_224,SHA3_256,SHA3_384,SHA3_512};