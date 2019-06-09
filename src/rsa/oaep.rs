use byteorder::{BigEndian,ByteOrder};
use sha::Hash;
use std::marker::PhantomData;

/// Parameters for OAEP encryption and decryption: a hash function to use as
/// part of the message generation function (MGF1, if you're curious),
/// and any labels you want to include as part of the encryption.
pub struct OAEPParams<H: Hash> {
    pub label: String,
    phantom: PhantomData<H>
}

impl<H: Hash> OAEPParams<H> {
    pub fn new(label: String)
        -> OAEPParams<H>
    {
        OAEPParams { label: label, phantom: PhantomData }
    }

    pub fn hash_len(&self) -> usize {
        H::hash(&[]).len()
    }

    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        H::hash(input)
    }

    pub fn mgf1(&self, input: &[u8], len: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(len);
        let mut counter = 0u32;

        while res.len() < len {
            let mut buffer = [0; 4];
            BigEndian::write_u32(&mut buffer, counter);
            let mut digest = H::new();
            digest.update(input);
            digest.update(&buffer);
            let chunk = digest.finalize();
            res.extend_from_slice(chunk.as_slice());
            counter = counter + 1;
        }

        res.truncate(len);
        res
    }
}
