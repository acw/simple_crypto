#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes"))]
pub mod aesni;
pub mod portable;


#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes",
          test))]
mod flexible {
    use super::aesni;
    use super::portable;
    use super::portable::aes256::{RandomBlock,RandomKey};

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
}
