use cryptonum::{BarrettUCN,UCN};
use rsa::core::ACCEPTABLE_KEY_SIZES;

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
            if valid_bits > len {
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
}
