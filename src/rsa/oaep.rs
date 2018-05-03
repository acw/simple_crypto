use cryptonum::UCN;
use digest::{FixedOutput,Input};

/// Parameters for OAEP encryption and decryption: a hash function to use as part of the message
/// generation function (MGF1, if you're curious), and any labels you want to include as part of
/// the encryption.
pub struct OAEPParams<H: Clone + Input + FixedOutput> {
    pub hash: H,
    pub label: String
}

impl<H: Clone + Input + FixedOutput> OAEPParams<H> {
    pub fn new(hash: H, label: String)
        -> OAEPParams<H>
    {
        OAEPParams { hash: hash, label: label }
    }

    pub fn hash_len(&self) -> usize {
        self.hash.clone().fixed_result().as_slice().len()
    }

    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut digest = self.hash.clone();
        digest.process(input);
        digest.fixed_result().as_slice().to_vec()
    }

    pub fn mgf1(&self, input: &[u8], len: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(len);
        let mut counter = UCN::from(0u64);
        let one = UCN::from(1u64);

        while res.len() < len {
            let c = counter.to_bytes(4);
            let mut digest = self.hash.clone();
            digest.process(input);
            digest.process(&c);
            let chunk = digest.fixed_result();
            res.extend_from_slice(chunk.as_slice());
            counter = counter + &one;
        }

        res.truncate(len);
        res
    }
}
