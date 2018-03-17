use cryptonum::{CryptoNumBase,CryptoNumModOps,CryptoNumSerialization};
use digest::{FixedOutput,Input};
use num::{BigInt,BigUint};
use rand::{OsRng,Rng};
use rsa::core::{ep,vp1,pkcs1_pad,xor_vecs,decode_biguint};
use rsa::oaep::{OAEPParams};
use rsa::errors::{RSAError};
use rsa::signing_hashes::SigningHash;
use simple_asn1::{FromASN1,ToASN1,ASN1DecodeErr,ASN1EncodeErr};
use simple_asn1::{ASN1Block,ASN1Class};

/// An RSA public key with the given modulus size. I've left the size as a
/// parameter, instead of hardcoding particular values. That being said,
/// you almost certainly want one of `U2048`, `U3072`, or `U4096` if you're
/// being pretty standard; `U512` or `U1024` if you're interfacing with
/// legacy code or want to build intentionally weak systems; or `U7680`,
/// `U8192`, or `U15360` if you like things running very slowly.
#[derive(Clone,Debug,PartialEq)]
pub struct RSAPublicKey<Size>
 where
  Size: CryptoNumBase + CryptoNumSerialization
{
    pub(crate) n: Size,
    pub(crate) e: Size
}

impl<U> RSAPublicKey<U>
 where
  U: CryptoNumBase + CryptoNumModOps + CryptoNumSerialization
{
    /// Create a new RSA public key from the given components, which you found
    /// via some other mechanism.
    pub fn new(n: U, e: U) -> RSAPublicKey<U> {
        RSAPublicKey{ n: n, e: e }
    }

    /// Verify the signature for a given message, using the given signing hash,
    /// return true iff the signature validates.
    pub fn verify(&self, sighash: &SigningHash, msg: &[u8], sig: &[u8]) -> bool
    {
        let hash = (sighash.run)(msg);
        let s    = U::from_bytes(sig);
        let m    = vp1(&self.n, &self.e, &s);
        let em   = s.to_bytes();
        let em_  = pkcs1_pad(&sighash.ident, &hash, m.byte_size());
        em == em_
    }

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption.
    ///
    /// OAEP encoding is used for this process, which requires a random number
    /// generator. This version of the function uses `OsRng`. If you want to
    /// use your own RNG, use `encrypt_w_rng`.
    pub fn encrypt<H:Clone + Input + FixedOutput>(&self, oaep: &OAEPParams<H>,
                                                  msg: &[u8])
        -> Result<Vec<u8>,RSAError>
    {
        let mut g = OsRng::new()?;
        self.encrypt_with_rng(&mut g, oaep, msg)
    }

    /// Encrypt the given data with the public key and parameters, returning
    /// the encrypted blob or an error encountered during encryption. This
    /// version also allows you to provide your own RNG, if you really feel
    /// like shooting yourself in the foot.
    pub fn encrypt_with_rng<G,H>(&self, g: &mut G, oaep: &OAEPParams<H>,
                                 msg: &[u8])
        -> Result<Vec<u8>,RSAError>
      where G: Rng, H: Clone + Input + FixedOutput
    {
        let mylen = self.e.byte_size();

        if mylen <= ((2 * oaep.hash_len()) + 2) {
            return Err(RSAError::KeyTooSmallForHash);
        }

        let mut res = Vec::new();

        for chunk in msg.chunks(mylen - (2 * oaep.hash_len()) - 2) {
            let mut newchunk = self.oaep_encrypt(g, oaep, chunk)?;
            res.append(&mut newchunk)
        }

        Ok(res)
    }

    fn oaep_encrypt<G,H>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
     where
       G: Rng, H:Clone + Input + FixedOutput
    {
        let mylen = self.e.byte_size();

        // Step 1b
        if msg.len() > (mylen - (2 * oaep.hash_len()) - 2) {
            return Err(RSAError::BadMessageSize)
        }
        // Step 2a
        let mut lhash = oaep.hash(oaep.label.as_bytes());
        // Step 2b
        let num0s = mylen - msg.len() - (2 * oaep.hash_len()) - 2;
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
        let db_mask = oaep.mgf1(&seed, mylen - oaep.hash_len() - 1);
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
        let m_i = U::from_bytes(&em);
        // Step 3b
        let c_i = ep(&self.n, &self.e, &m_i);
        // Step 3c
        let c = c_i.to_bytes();
        Ok(c)
    }
}

impl<T> FromASN1 for RSAPublicKey<T>
  where
    T: CryptoNumBase + CryptoNumSerialization,
    T: From<BigUint>
{
    type Error = RSAError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(RSAPublicKey<T>,&[ASN1Block]),RSAError>
    {
        match bs.split_first() {
            None =>
                Err(RSAError::ASN1DecodeErr(ASN1DecodeErr::EmptyBuffer)),
            Some((&ASN1Block::Sequence(_, _, ref items), rest))
                if items.len() == 2 =>
            {
                let numn = decode_biguint(&items[0])?;
                let nume = decode_biguint(&items[1])?;
                let nsize = numn.bits();
                let mut rsa_size = 512;

                while rsa_size < nsize {
                    rsa_size = rsa_size + 256;
                }
                rsa_size /= 8;

                if rsa_size != (T::from_u8(0)).bit_size() {
                    return Err(RSAError::KeySizeMismatch);
                }

                let n = T::from(numn);
                let e = T::from(nume);

                let res = RSAPublicKey{ n: n, e: e };

                Ok((res, rest))
            }
            Some(_) =>
                Err(RSAError::InvalidKey)
        }
    }
}

impl<T> ToASN1 for RSAPublicKey<T>
  where
    T: Clone + Into<BigInt>,
    T: CryptoNumBase + CryptoNumSerialization
{
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,Self::Error>
    {
        let enc_n = ASN1Block::Integer(c, 0, self.n.clone().into());
        let enc_e = ASN1Block::Integer(c, 0, self.e.clone().into());
        let seq = ASN1Block::Sequence(c, 0, vec![enc_n, enc_e]);
        Ok(vec![seq])
    }
}


