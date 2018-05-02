use cryptonum::{BarrettUCN,UCN};
use rsa::core::{ACCEPTABLE_KEY_SIZES,pkcs1_pad,vp1};
use rsa::signing_hashes::SigningHash;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct RSAPublic {
    pub(crate) byte_len: usize,
    pub(crate) n: UCN,
    pub(crate) nu: BarrettUCN,
    pub(crate) e: UCN
}

impl RSAPublic {
    /// Create a new RSA public key from the given components, which you found
    /// via some other mechanism.
    pub fn new(n: UCN, e: UCN) -> RSAPublic {
        let len = n.bits();

        for &(valid_bits, _) in ACCEPTABLE_KEY_SIZES.iter() {
            if valid_bits >= len {
                return RSAPublic{
                    byte_len: valid_bits / 8,
                    n: n.clone(),
                    nu: n.barrett_u(),
                    e: e.clone()
                };
            }
        }
        panic!("Invalid RSA key size in new()")
    }

    /// Verify the signature for a given message, using the given signing hash,
    /// returning true iff the signature validates.
    pub fn verify(&self, shash: &SigningHash, msg: &[u8], sig: &[u8]) -> bool {
        let hash = (shash.run)(msg);
        let s    = UCN::from_bytes(&sig);
        let m    = vp1(&self.nu, &self.e, &s);
        let em   = m.to_bytes(self.byte_len);
        let em_  = pkcs1_pad(&shash.ident, &hash, self.byte_len);
        (em == em_)
    }
}
