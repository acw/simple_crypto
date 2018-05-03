use cryptonum::{BarrettUCN,UCN};
use digest::{FixedOutput,Input};
use rand::{OsRng,Rng};
use rsa::core::{ACCEPTABLE_KEY_SIZES,ep,pkcs1_pad,vp1,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
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

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption.
    ///
    /// OAEP encoding is used for this process, which requires a random number
    /// generator. This version of the function uses `OsRng`. If you want to
    /// use your own RNG, use `encrypt_w_rng`.
    pub fn encrypt<H:Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut g = OsRng::new()?;
        self.encrypt_with_rng(&mut g, oaep, msg)
    }

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption. This
    /// version also allows you to provide your own RNG, if you really feel
    /// like shooting yourself in the foot.
    pub fn encrypt_with_rng<G,H>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
      where G: Rng, H: Clone + Input + FixedOutput
    {
        if self.byte_len <= ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::KeyTooSmallForHash);
        }

        let mut res = Vec::new();

        for chunk in msg.chunks(self.byte_len - (2 * oaep.hash_len()) - 2) {
            let mut newchunk = self.oaep_encrypt(g, oaep, chunk)?;
            res.append(&mut newchunk)
        }

        Ok(res)
    }

    fn oaep_encrypt<G: Rng,H:Clone + Input + FixedOutput>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        // Step 1b
        if msg.len() > (self.byte_len - (2 * oaep.hash_len()) - 2) {
            return Err(RSAError::BadMessageSize)
        }
        // Step 2a
        let mut lhash = oaep.hash(oaep.label.as_bytes());
        // Step 2b
        let num0s = self.byte_len - msg.len() - (2 * oaep.hash_len()) - 2;
        let mut ps = Vec::new();
        ps.resize(num0s, 0);
        // Step 2c
        let mut db = Vec::new();
        db.append(&mut lhash);
        db.append(&mut ps);
        db.push(1);
        db.extend_from_slice(msg);
        // Step 2d
        let seed : Vec<u8> = g.gen_iter().take(oaep.hash_len()).collect();
        // Step 2e
        let db_mask = oaep.mgf1(&seed, self.byte_len - oaep.hash_len() - 1);
        // Step 2f
        let mut masked_db = xor_vecs(&db, &db_mask);
        // Step 2g
        let seed_mask = oaep.mgf1(&masked_db, oaep.hash_len());
        // Step 2h
        let mut masked_seed = xor_vecs(&seed, &seed_mask);
        // Step 2i
        let mut em = Vec::new();
        em.push(0);
        em.append(&mut masked_seed);
        em.append(&mut masked_db);
        // Step 3a
        let m_i = UCN::from_bytes(&em);
        // Step 3b
        let c_i = ep(&self.nu, &self.e, &m_i);
        // Step 3c
        let c = c_i.to_bytes(self.byte_len);
        Ok(c)
    }
}
