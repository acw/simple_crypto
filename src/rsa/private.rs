use cryptonum::{BarrettUCN,UCN};
use digest::{FixedOutput,Input};
use rsa::core::{ACCEPTABLE_KEY_SIZES,dp,pkcs1_pad,sp1,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
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

    /// Decrypt a message with the given parameters.
    pub fn decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut res = Vec::new();

        for chunk in msg.chunks(self.byte_len) {
            let mut dchunk = self.oaep_decrypt(oaep, chunk)?;
            res.append(&mut dchunk);
        }

        Ok(res)
    }

    fn oaep_decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, c: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        // Step 1b
        if c.len() != self.byte_len {
            return Err(RSAError::DecryptionError);
        }
        // Step 1c
        if self.byte_len < ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::DecryptHashMismatch);
        }
        // Step 2a
        let c_ip = UCN::from_bytes(&c.to_vec());
        // Step 2b
        let m_ip = dp(&self.nu, &self.d, &c_ip);
        // Step 2c
        let em = &m_ip.to_bytes(self.byte_len);
        // Step 3a
        let l_hash = oaep.hash(oaep.label.as_bytes());
        // Step 3b
        let (y, rest) = em.split_at(1);
        let (masked_seed, masked_db) = rest.split_at(oaep.hash_len());
        // Step 3c
        let seed_mask = oaep.mgf1(masked_db, oaep.hash_len());
        // Step 3d
        let seed = xor_vecs(&masked_seed.to_vec(), &seed_mask);
        // Step 3e
        let db_mask = oaep.mgf1(&seed, self.byte_len - oaep.hash_len() - 1);
        // Step 3f
        let db = xor_vecs(&masked_db.to_vec(), &db_mask);
        // Step 3g
        let (l_hash2, ps_o_m) = db.split_at(oaep.hash_len());
        let o_m = drop0s(ps_o_m);
        let (o, m) = o_m.split_at(1);
        // Checks!
        if o != [1] {
            return Err(RSAError::DecryptionError);
        }
        if l_hash != l_hash2 {
            return Err(RSAError::DecryptionError);
        }
        if y != [0] {
            return Err(RSAError::DecryptionError);
        }

        Ok(m.to_vec())
    }
}

fn drop0s(a: &[u8]) -> &[u8] {
    let mut idx = 0;

    while (idx < a.len()) && (a[idx] == 0) {
        idx = idx + 1;
    }

    &a[idx..]
}
