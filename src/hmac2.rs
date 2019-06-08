//! This module implements the Keyed-Hash Message Authentication Code, or HMAC,
//! as defined by NIST 198-1. Now, you might have questions, like:
//!   * *Where did the 'K' go in the acronym?* I don't know. Maybe we should
//!     always be saying Keyed-HMAC? It's a mystery.
//!   * *What is this good for?* I do know the answer to that! HMACs are
//!     useful when you want to extend the ability of a hash to tell you if
//!     a message has been modified with the ability to determine if the
//!     person that sent it had hold of a key. It's thus a version of the
//!     message signing capability used in asymmetric crypto (`DSA`, `RSA`,
//!     `ECDSA`, and `ED25519`, as implemented in this crate), but with a
//!     symmetric key, instead.
//! 
//! Because HMAC can be used with a variety of hash functions, this module
//! implements it as a generic structure that takes the associated hash as
//! a type argument. This should provide a reasonable level of flexibility,
//! while allowing the type system from preventing us from making any number
//! of really annoying mistakes. You can specify which of the hash functions
//! you want to use by using your standard turbofish:
//! 
//! ```rust
//! use simple_crypto::hmac2::HMAC;
//! use simple_crypto::sha::SHA256;
//! 
//! let key = [0,1,2,3,4]; // very secure
//! let msg = [5,6,7,8];
//! let hmac = HMAC::<SHA256>::hmac(&key, &msg);
//! ```
//!
//! Much like with `SHAKE128` and `SHAKE256` the interface for HMAC is
//! similar to, but not quite, the interface for `Hash`. We thus try to
//! copy as much of the standard `Hash` interface as we can, but extend
//! `new` with a key, rename `hash` to `hmac`, and extend `hmac` with a
//! key as well. This provides a similar ability to use HMACs both in an
//! incremental mode as well as just do it all at once, as follows:
//! 
//! ```rust
//! use simple_crypto::hmac2::HMAC;
//! use simple_crypto::sha::SHA256;
//! 
//! let key = [0,1,2,3,4]; // like my suitcase
//! let msg = [5,6,7,8];
//!
//! // Compute the HMAC incrementally 
//! let mut hmacinc = HMAC::<SHA256>::new(&key);
//! hmacinc.update(&[5,6]);
//! hmacinc.update(&[7,8]);
//! let hmac_incremental = hmacinc.finalize();
//! 
//! // Compute the HMAC all at once
//! let hmac_once = HMAC::<SHA256>::hmac(&key, &msg);
//! 
//! // ... which should be the same thing
//! assert_eq!(hmac_incremental, hmac_once);
//! ```

/// The HMAC structure, parameterized by its hash function.
/// 
/// Much like with `SHAKE128` and `SHAKE256` the interface for HMAC is
/// similar to, but not quite, the interface for `Hash`. We thus try to
/// copy as much of the standard `Hash` interface as we can, but extend
/// `new` with a key, rename `hash` to `hmac`, and extend `hmac` with a
/// key as well. This provides a similar ability to use HMACs both in an
/// incremental mode as well as just do it all at once, as follows:
/// 
/// ```rust
/// use simple_crypto::hmac2::HMAC;
/// use simple_crypto::sha::SHA256;
/// 
/// let key = [0,1,2,3,4]; // like my suitcase
/// let msg = [5,6,7,8];
///
/// // Compute the HMAC incrementally 
/// let mut hmacinc = HMAC::<SHA256>::new(&key);
/// hmacinc.update(&[5,6]);
/// hmacinc.update(&[7,8]);
/// let hmac_incremental = hmacinc.finalize();
/// 
/// // Compute the HMAC all at once
/// let hmac_once = HMAC::<SHA256>::hmac(&key, &msg);
/// 
/// // ... which should be the same thing
/// assert_eq!(hmac_incremental, hmac_once);
/// ```
use super::Hash;

pub struct HMAC<H: Hash> {
    ipad_hash: H,
    opad_hash: H,
    result: Option<Vec<u8>>
}

impl<H: Hash> HMAC<H> {
    /// Generate a new HMAC construction for the provide underlying hash
    /// function, and prep it to start taking input via the `update`
    /// method.
    pub fn new(inkey: &[u8]) -> Self {
        let hash_blocklen_bytes = H::block_size() / 8;

        // If the input key is longer than the hash block length, then we
        // immediately hash it down to be the block length. Otherwise, we
        // leave it be.
        let mut key = if inkey.len() > hash_blocklen_bytes { H::hash(inkey) }
                                                      else { inkey.to_vec() };
        // It may now be too small, or have started too small, in which case
        // we pad it out with zeros.
        key.resize(hash_blocklen_bytes, 0);
        // Generate the inner and outer key pad from this key.
        let o_key_pad: Vec<u8> = key.iter().map(|x| *x ^ 0x5c).collect();
        let i_key_pad: Vec<u8> = key.iter().map(|x| *x ^ 0x36).collect();
        // Now we can start the hashes; obviously we'll have to wait
        // until we get the rest of the message to complete them.
        let mut ipad_hash = H::new();
        ipad_hash.update(&i_key_pad);
        let mut opad_hash = H::new();
        opad_hash.update(&o_key_pad);
        let result = None;
        HMAC { ipad_hash, opad_hash, result }
    }

    /// Add more data as part of the HMAC computation. This can be called
    /// zero or more times over the lifetime of the HMAC structure. That
    /// being said, once you call `finalize`, this structure is done, and
    /// it will ignore further calls to `update`.
    pub fn update(&mut self, buffer: &[u8])
    {
        if self.result.is_none() {
            self.ipad_hash.update(&buffer);
        }
    }

    /// Provide the final HMAC value for the bitrstream as read. This shifts
    /// this structure into a final mode, in which it will ignore any more
    /// data provided to it from `update`. You can, however, call `finalize`
    /// more than once; the HMAC structure caches the return value and will
    /// return it as many times as you like.
    pub fn finalize(&mut self) -> Vec<u8>
    {
        if let Some(ref res) = self.result {
            res.clone()
        } else {
            self.opad_hash.update(&self.ipad_hash.finalize());
            let res = self.opad_hash.finalize();
            self.result = Some(res.clone());
            res
        }
    }

    /// A useful method for those situations in which you have only one block
    /// of data to generate an HMAC for. Runs `new`, `update`, and `finalize`
    /// for you, in order.
    pub fn hmac(key: &[u8], val: &[u8]) -> Vec<u8>
    {
        let mut h = Self::new(key);
        h.update(val);
        h.finalize()
    }
}

#[cfg(test)]
use sha::{SHA1,SHA224,SHA256,SHA384,SHA512};
#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use cryptonum::unsigned::{Decoder,U192};

#[cfg(test)]
#[test]
fn nist_vectors() {
    let fname = "testdata/sha/hmac.test";
    run_test(fname.to_string(), 6, |case| {
        let (negh, hbytes) = case.get("h").unwrap();
        let (negr, rbytes) = case.get("r").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negk, kbytes) = case.get("k").unwrap();
        let (negl, lbytes) = case.get("l").unwrap();
        let (negt, tbytes) = case.get("t").unwrap();

        assert!(!negh && !negr && !negm && !negk && !negl && !negt);
        let l = usize::from(U192::from_bytes(lbytes));
        let h = usize::from(U192::from_bytes(hbytes));
        assert_eq!(l, kbytes.len());
        let mut res = match h {
            160 => HMAC::<SHA1>::hmac(&kbytes, &mbytes),
            224 => HMAC::<SHA224>::hmac(&kbytes, &mbytes),
            256 => HMAC::<SHA256>::hmac(&kbytes, &mbytes),
            384 => HMAC::<SHA384>::hmac(&kbytes, &mbytes),
            512 => HMAC::<SHA512>::hmac(&kbytes, &mbytes),
            _   => panic!("Weird hash size in HMAC test file")
        };
        let t = usize::from(U192::from_bytes(tbytes));
        res.resize(t, 0);
        assert_eq!(rbytes, &res);
    });
}

