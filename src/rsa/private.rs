use cryptonum::{CryptoNumBase,CryptoNumModOps,CryptoNumSerialization};
use digest::{FixedOutput,Input};
use rsa::core::{dp,sp1,pkcs1_pad,xor_vecs};
use rsa::oaep::{OAEPParams};
use rsa::errors::{RSAError};
use rsa::signing_hashes::SigningHash;

/// A RSA private key. As with public keys, I've left the size as a
/// parameter: 2048-4096 is standard practice, 512-1024 is weak, and
/// >4096 is going to be slow.
#[derive(Clone,Debug,PartialEq)]
pub struct RSAPrivateKey<Size>
 where
  Size: CryptoNumBase + CryptoNumSerialization
{
    pub(crate) n: Size,
    pub(crate) d: Size
}

impl<U> RSAPrivateKey<U>
 where
  U: CryptoNumBase + CryptoNumModOps + CryptoNumSerialization
{
    /// Generate a private key, using the given `n` and `d` parameters
    /// gathered from some other source. The length should be given in
    /// bits.
    pub fn new(n: U, d: U) -> RSAPrivateKey<U> {
        RSAPrivateKey {
            n: n,
            d: d
        }
    }

    /// Sign a message using the given hash.
    pub fn sign(&self, sighash: &SigningHash, msg: &[u8]) -> Vec<u8> {
        let hash = (sighash.run)(msg);
        let em   = pkcs1_pad(&sighash.ident, &hash, self.d.byte_size());
        let m    = U::from_bytes(&em);
        let s    = sp1(&self.n, &self.d, &m);
        let sig  = s.to_bytes();
        sig
    }

    /// Decrypt a message with the given parameters.
    pub fn decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut res = Vec::new();
        let byte_len = self.d.byte_size();

        for chunk in msg.chunks(byte_len) {
            let mut dchunk = self.oaep_decrypt(oaep, chunk)?;
            res.append(&mut dchunk);
        }

        Ok(res)
    }

    fn oaep_decrypt<H: Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, c: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let byte_len = self.d.byte_size();
        // Step 1b
        if c.len() != byte_len {
            return Err(RSAError::DecryptionError);
        }
        // Step 1c
        if byte_len < ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::DecryptHashMismatch);
        }
        // Step 2a
        let c_ip = U::from_bytes(&c);
        // Step 2b
        let m_ip = dp(&self.n, &self.d, &c_ip);
        // Step 2c
        let em = m_ip.to_bytes();
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
        let db_mask = oaep.mgf1(&seed, byte_len - oaep.hash_len() - 1);
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
