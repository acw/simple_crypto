#[cfg(all(any(target_arch="x86", target_arch="x86_64"),
          target_feature = "aes"))]
pub mod aesni;