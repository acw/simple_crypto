//! This module implements the SHAKE family of variable-length hash functions,
//! which NIST also referes to as Extendable-Output Functions (XOFs). They are
//! based on the same underlying hashing mechanism used in SHA3, but can be
//! tuned to output a variety of different hash lengths. One trick is that the
//! security of the hash is the minimum of the defined bit size (128 for
//! SHAKE128, or 256 for SHAKE256) and the output hash length, so if you use
//! shorter hashes you lose some amount of collision protection.
//! 
//! Because the output is variable length, these don't quite fit into the
//! normal `Hash` trait. Instead, they implement the same basic functions,
//! but with `hash` and `finalize` functions extended with an additional
//! output length function. Usage is thus in the analagous way to normal
//! hashing:
//! 
//! ```rust
//! use simple_crypto::shake::SHAKE128;
//!
//! // Use SHAKE incrementally 
//! let empty = [0; 0];
//! let mut shakef = SHAKE128::new();
//! shakef.update(&empty);
//! let result_inc = shakef.finalize(384);
//! // Use SHAKE directly
//! let result_dir = SHAKE128::hash(&empty, 384);
//! // ... and the answers should be the same.
//! assert_eq!(result_inc, result_dir);
//! ```
use sha::Keccak;

/// The SHAKE128 variable-length hash.
/// 
/// This generates a variable-length hash value, although it's not necessarily as
/// strong as a hash of the same value. My understanding (which is admittedly
/// limited; I've never seen these used) is that this is more for convenience
/// when you want to fit into particularly-sized regions. The 128 is the
/// approximate maximum bit strength of the hash in bits; the true strength is
/// the minimum of the length of the output hash and 128.
/// 
/// `SHAKE128` does not implement `Hash`, because it is finalized differently,
/// but we've kept something of the flavor of the `Hash` interface for
/// familiarity.
/// 
/// Like the SHA3 variants, this can be used incrementally or directly, as per
/// usual:
/// 
/// ```rust
/// use simple_crypto::shake::SHAKE128;
///
/// // Use SHAKE incrementally 
/// let empty = [0; 0];
/// let mut shakef = SHAKE128::new();
/// shakef.update(&empty);
/// let result_inc = shakef.finalize(384);
/// // Use SHAKE directly
/// let result_dir = SHAKE128::hash(&empty, 384);
/// // ... and the answers should be the same.
/// assert_eq!(result_inc, result_dir);
/// ```
pub struct SHAKE128 {
    state: Keccak
}

impl SHAKE128 {
    /// Create a fresh, new SHAKE128 instance for incremental use.
    pub fn new() -> Self
    {
        SHAKE128{
            state: Keccak::new(1600 - 256)
        }
    }

    /// Add more data into the hash function for processing.
    pub fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    /// Generate the final hash. Because this is a variable-length hash,
    /// you will need to provide the output size in bits. Note that this
    /// output size *must* be a multiple of 8, and that the security
    /// strength of the whole hash is approximately the minimum of this
    /// length and 128 bits.
    pub fn finalize(&mut self, outsize: usize) -> Vec<u8>
    {
        assert_eq!(outsize % 8, 0);
        self.state.tag_and_pad(0x1F);
        self.state.squeeze(outsize / 8)
    }

    /// Directly generate the SHAKE128 hash of the given buffer, returning
    /// a hash value of the given size (in bits). Presently, the output
    /// size *must* be a multiple of 8, although this may change in the
    /// future.
    pub fn hash(buffer: &[u8], outsize: usize) -> Vec<u8>
    {
        let mut x = Self::new();
        x.update(&buffer);
        x.finalize(outsize)
    }
}

#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use cryptonum::unsigned::{Decoder,U192};

#[cfg(test)]
#[test]
fn shake128() {
    let fname = "testdata/sha/shake128.test";
    run_test(fname.to_string(), 4, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();
        let (nego, obytes) = case.get("o").unwrap();

        assert!(!negl && !negm && !negd && !nego);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let osize = usize::from(U192::from_bytes(obytes));
        let digest = SHAKE128::hash(&msg, osize);;
        assert_eq!(dbytes, &digest);
    });
}

/// The SHAKE256 variable-length hash.
/// 
/// This generates a variable-length hash value, although it's not necessarily as
/// strong as a hash of the same value. My understanding (which is admittedly
/// limited; I've never seen these used) is that this is more for convenience
/// when you want to fit into particularly-sized regions. The 256 is the
/// approximate maximum bit strength of the hash in bits; the true strength is
/// the minimum of the length of the output hash and 256.
/// 
/// `SHAKE256` does not implement `Hash`, because it is finalized differently,
/// but we've kept something of the flavor of the `Hash` interface for
/// familiarity.
/// 
/// Like the SHA3 variants, this can be used incrementally or directly, as per
/// usual:
/// 
/// ```rust
/// use simple_crypto::shake::SHAKE256;
///
/// // Use SHAKE incrementally 
/// let empty = [0; 0];
/// let mut shakef = SHAKE256::new();
/// shakef.update(&empty);
/// let result_inc = shakef.finalize(384);
/// // Use SHAKE directly
/// let result_dir = SHAKE256::hash(&empty, 384);
/// // ... and the answers should be the same.
/// assert_eq!(result_inc, result_dir);
/// ```
pub struct SHAKE256 {
    state: Keccak
}

impl SHAKE256 {
    /// Create a fresh, new SHAKE256 instance for incremental use.
    pub fn new() -> Self
    {
        SHAKE256{
            state: Keccak::new(1600 - 512)
        }
    }

    /// Add more data into the hash function for processing.
    pub fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    /// Generate the final hash. Because this is a variable-length hash,
    /// you will need to provide the output size in bits. Note that this
    /// output size *must* be a multiple of 8, and that the security
    /// strength of the whole hash is approximately the minimum of this
    /// length and 256 bits.
    pub fn finalize(&mut self, outsize: usize) -> Vec<u8>
    {
        assert_eq!(outsize % 8, 0);
        self.state.tag_and_pad(0x1F);
        self.state.squeeze(outsize / 8)
    }

    /// Directly generate the SHAKE256 hash of the given buffer, returning
    /// a hash value of the given size (in bits). Presently, the output
    /// size *must* be a multiple of 8, although this may change in the
    /// future.
    pub fn hash(buffer: &[u8], outsize: usize) -> Vec<u8>
    {
        let mut x = Self::new();
        x.update(&buffer);
        x.finalize(outsize)
    }
}

#[cfg(test)]
#[test]
fn shake256() {
    let fname = "testdata/sha/shake256.test";
    run_test(fname.to_string(), 4, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();
        let (nego, obytes) = case.get("o").unwrap();

        assert!(!negl && !negm && !negd && !nego);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let osize = usize::from(U192::from_bytes(obytes));
        let digest = SHAKE256::hash(&msg, osize);;
        assert_eq!(dbytes, &digest);
    });
}


