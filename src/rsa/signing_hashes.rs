use digest::Digest;
use sha1::Sha1;
use sha2::{Sha224,Sha256,Sha384,Sha512};
use std::fmt;

/// A hash that can be used to sign a message.
#[derive(Clone)]
pub struct SigningHash {
    /// The name of this hash (only used for display purposes)
    pub name: &'static str,
    /// The approved identity string for the hash.
    pub ident: &'static [u8],
    /// The hash
    pub run: fn(&[u8]) -> Vec<u8>
}

impl fmt::Debug for SigningHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// The "null" signing hash. This signing hash has no identity, and will
/// simply pass the data through unhashed. You really should know what
/// you're doing if you use this, and probably using a somewhat strange
/// signing protocol. There's no good reason to use this in new code
/// for a new protocol or system.
pub static SIGNING_HASH_NULL: SigningHash = SigningHash {
    name: "NULL",
    ident: &[],
    run: nohash
};

fn nohash(i: &[u8]) -> Vec<u8> {
    i.to_vec()
}

/// Sign a hash based on SHA1. You shouldn't use this unless you're using
/// very small keys, and this is the only one available to you. Even then,
/// why are you using such small keys?!
pub static SIGNING_HASH_SHA1: SigningHash = SigningHash {
    name: "SHA1",
    ident: &[0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,
             0x02,0x1a,0x05,0x00,0x04,0x14],
    run: runsha1
};

fn runsha1(i: &[u8]) -> Vec<u8> {
    Sha1::digest(i).as_slice().to_vec()
}

/// Sign a hash based on SHA2-224. This is the first reasonable choice
/// we've come across, and is useful when you have smaller RSA key sizes.
/// I wouldn't recommend it, though.
pub static SIGNING_HASH_SHA224: SigningHash = SigningHash {
    name: "SHA224",
    ident: &[0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,
             0x1c],
    run: runsha224
};

fn runsha224(i: &[u8]) -> Vec<u8> {
    Sha224::digest(i).as_slice().to_vec()
}

/// Sign a hash based on SHA2-256. The first one I'd recommend!
pub static SIGNING_HASH_SHA256: SigningHash = SigningHash {
    name: "SHA256",
    ident: &[0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,
             0x20],
    run: runsha256
};

fn runsha256(i: &[u8]) -> Vec<u8> {
    Sha256::digest(i).as_slice().to_vec()
}

/// Sign a hash based on SHA2-384. Approximately 50% better than
/// SHA-256.
pub static SIGNING_HASH_SHA384: SigningHash = SigningHash {
    name: "SHA384",
    ident: &[0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,
             0x30],
    run: runsha384
};

fn runsha384(i: &[u8]) -> Vec<u8> {
    Sha384::digest(i).as_slice().to_vec()
}

/// Sign a hash based on SHA2-512. At this point, you're getting a bit
/// silly. But if you want to through 8kbit RSA keys with a 512 bit SHA2
/// signing hash, we're totally behind you.
pub static SIGNING_HASH_SHA512: SigningHash = SigningHash {
    name: "SHA512",
    ident: &[0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
             0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,
             0x40],
    run: runsha512
};

fn runsha512(i: &[u8]) -> Vec<u8> {
    Sha512::digest(i).as_slice().to_vec()
}


