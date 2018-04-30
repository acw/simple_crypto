use cryptonum::{BarrettUCN,UCN};
use rsa::core::{ACCEPTABLE_KEY_SIZES,pkcs1_pad,sp1};
use rsa::signing_hashes::SigningHash;
use std::fmt;

#[derive(Clone)]
pub struct RSAPrivate {
    pub(crate) byte_len: usize,
    pub(crate) n: UCN,
    pub(crate) nu: BarrettUCN,
    pub(crate) d: UCN
}

#[cfg(test)]
impl fmt::Debug for RSAPrivate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RSAPrivate")
         .field("byte_len", &self.byte_len)
         .field("n", &self.n)
         .field("nu", &self.nu)
         .field("d", &self.d)
         .finish()
    }
}

#[cfg(test)]
impl PartialEq for RSAPrivate {
    fn eq(&self, rhs: &RSAPrivate) -> bool {
        (self.byte_len == rhs.byte_len) &&
        (self.n        == rhs.n)        &&
        (self.nu       == rhs.nu)       &&
        (self.d        == rhs.d)
    }
}

#[cfg(test)]
impl Eq for RSAPrivate {}

#[cfg(not(test))]
impl fmt::Debug for RSAPrivate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RSAPrivateKey<PRIVATE>")
    }
}

impl RSAPrivate {
    /// Create a new RSA public key from the given components, which you found
    /// via some other mechanism.
    pub fn new(n: UCN, d: UCN) -> RSAPrivate {
        let len = n.bits();

        for &(valid_bits, _) in ACCEPTABLE_KEY_SIZES.iter() {
            if valid_bits >= len {
                return RSAPrivate {
                    byte_len: valid_bits / 8,
                    n: n.clone(),
                    nu: n.barrett_u(),
                    d: d.clone()
                };
            }
        }
        panic!("Invalid RSA key size in new()")
    }

    /// Sign a message using the given hash.
    pub fn sign(&self, sighash: &SigningHash, msg: &[u8]) -> Vec<u8> {
        let hash = (sighash.run)(msg);
        let em   = pkcs1_pad(&sighash.ident, &hash, self.byte_len);
        let m    = UCN::from_bytes(&em);
        let s    = sp1(&self.nu, &self.d, &m);
        let sig  = s.to_bytes(self.byte_len);
        sig
    }
}
