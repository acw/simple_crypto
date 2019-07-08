#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes"))]
pub mod aesni;
pub mod portable;

#[cfg(all(target_arch="x86", target_feature = "aes"))]
use std::arch::x86::__cpuid;
#[cfg(all(target_arch="x86_64", target_feature = "aes"))]
use std::arch::x86_64::__cpuid;

/// This is the type to use for an AES128 key. The new() routine will select
/// an accelerated routine, at runtime, if one is available. Otherwise, it
/// will use a slower, portable routine.
pub enum AES128 {
    Portable(portable::AES128),
    #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
              target_feature = "aes"))]
    Accelerated(aesni::AES128),
}

#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes"))]
fn test_aesni() -> bool {
    let result = unsafe { __cpuid(1) }; // 1 == processor features
    (result.edx & 0b00000010000000000000000000000000) != 0
}

impl AES128 {
    /// Returns true iff this platform has an acceleration system we support.
    pub fn accelerated() -> bool {
        #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                  target_feature = "aes"))]
        return test_aesni();
        #[allow(unreachable_code)] 
        false
    }

    /// Generate a new AES128 object from the given key. This routine does a
    /// dynamic check of `AES128::accelerated()` to see if it can be
    /// accelerated; this means that you'll get acceleration where you can,
    /// and a safe default where you can't.
    pub fn new(key: [u8; 16]) -> AES128 {
        #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                  target_feature = "aes"))]
        return if AES128::accelerated() {
            AES128::Accelerated(aesni::AES128::new(&key))
        } else {
            AES128::Portable(portable::AES128::new(&key))
        };
        #[allow(unreachable_code)] 
        AES128::Portable(portable::AES128::new(&key))
    }

    /// Encrypt the given block. This *must* be exactly 16 bytes long.
    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        match self {
            AES128::Portable(ref key) => key.encrypt(block),
            #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                      target_feature = "aes"))]
            AES128::Accelerated(ref key) => key.encrypt(block),
        }
    }

    /// Decrypt the given block. This *must* be exactly 16 bytes long.
    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        match self {
            AES128::Portable(ref key) => key.decrypt(block),
            #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                      target_feature = "aes"))]
            AES128::Accelerated(ref key) => key.decrypt(block),
        }
    }
}

/// This is the type to use for an AES128 key. The new() routine will select
/// an accelerated routine, at runtime, if one is available. Otherwise, it
/// will use a slower, portable routine.
pub enum AES256 {
    Portable(portable::AES256),
    #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
              target_feature = "aes"))]
    Accelerated(aesni::AES256),
}

impl AES256 {
    /// Returns true iff this platform has an acceleration system we support.
    pub fn accelerated() -> bool {
        #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                  target_feature = "aes"))]
        return test_aesni(); 
        #[allow(unreachable_code)] 
        false
    }

    /// Generate a new AES256 object from the given key. This routine does a
    /// dynamic check of `AES256::accelerated()` to see if it can be
    /// accelerated; this means that you'll get acceleration where you can,
    /// and a safe default where you can't.
    pub fn new(key: [u8; 32]) -> AES256 {
        #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                  target_feature = "aes"))]
        return if AES256::accelerated() {
            AES256::Accelerated(aesni::AES256::new(&key))
        } else {
            AES256::Portable(portable::AES256::new(&key))
        };
        #[allow(unreachable_code)] 
        AES256::Portable(portable::AES256::new(&key))
    }

    /// Encrypt the given block. This *must* be exactly 16 bytes long.
    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        match self {
            AES256::Portable(ref key) => key.encrypt(block),
            #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                      target_feature = "aes"))]
            AES256::Accelerated(ref key) => key.encrypt(block),
        }
    }

    /// Decrypt the given block. This *must* be exactly 16 bytes long.
    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        match self {
            AES256::Portable(ref key) => key.decrypt(block),
            #[cfg(all(any(target_arch="x86", target_arch="x86_64"),
                      target_feature = "aes"))]
            AES256::Accelerated(ref key) => key.decrypt(block),
        }
    }
}

#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes",
          test))]
mod flexible {
    use super::{AES128,AES256};
    use super::aesni;
    use super::portable;
    use super::portable::aes256::{RandomBlock,RandomKey};
    use testing::run_test;

    quickcheck! {
        fn aes128_implementations_match(key: RandomBlock, block: RandomBlock) -> bool {
            let aesni_key = aesni::AES128::new(&key.block);
            let portable_key = portable::AES128::new(&key.block);
            let aesni_cipher = aesni_key.encrypt(&block.block);
            let portable_cipher = portable_key.encrypt(&block.block);
            aesni_cipher == portable_cipher
        }

        fn aes256_implementations_match(key: RandomKey, block: RandomBlock) -> bool {
            let aesni_key = aesni::AES256::new(&key.key);
            let portable_key = portable::AES256::new(&key.key);
            let aesni_cipher = aesni_key.encrypt(&block.block);
            let portable_cipher = portable_key.encrypt(&block.block);
            aesni_cipher == portable_cipher
        }
    }

    #[test]
    fn aes128_nist_test_vectors() {
        let fname = "testdata/aes/aes128.test";
        run_test(fname.to_string(), 3, |case| {
            let (negk, kbytes) = case.get("k").unwrap();
            let (negp, pbytes) = case.get("p").unwrap();
            let (negc, cbytes) = case.get("c").unwrap();

            assert!(!negk && !negp && !negc);
            let keyval = [kbytes[00], kbytes[01], kbytes[02], kbytes[03],
                          kbytes[04], kbytes[05], kbytes[06], kbytes[07],
                          kbytes[08], kbytes[09], kbytes[10], kbytes[11],
                          kbytes[12], kbytes[13], kbytes[14], kbytes[15]];
            let key = AES128::new(keyval);
            let cipher = key.encrypt(&pbytes);
            let plain = key.decrypt(&cipher);
            assert_eq!(&cipher, cbytes);
            assert_eq!(&plain, pbytes);
        });
    }

    #[test]
    fn aes256_nist_test_vectors() {
        let fname = "testdata/aes/aes256.test";
        run_test(fname.to_string(), 3, |case| {
            let (negk, kbytes) = case.get("k").unwrap();
            let (negp, pbytes) = case.get("p").unwrap();
            let (negc, cbytes) = case.get("c").unwrap();

            assert!(!negk && !negp && !negc);
            let keyval = [kbytes[00], kbytes[01], kbytes[02], kbytes[03],
                          kbytes[04], kbytes[05], kbytes[06], kbytes[07],
                          kbytes[08], kbytes[09], kbytes[10], kbytes[11],
                          kbytes[12], kbytes[13], kbytes[14], kbytes[15],
                          kbytes[16], kbytes[17], kbytes[18], kbytes[19],
                          kbytes[20], kbytes[21], kbytes[22], kbytes[23],
                          kbytes[24], kbytes[25], kbytes[26], kbytes[27],
                          kbytes[28], kbytes[29], kbytes[30], kbytes[31]];
            let key = AES256::new(keyval);
            let cipher = key.encrypt(&pbytes);
            let plain = key.decrypt(&cipher);
            assert_eq!(&cipher, cbytes);
            assert_eq!(&plain, pbytes);
        });
    }
}
