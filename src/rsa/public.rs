use cryptonum::*;
use digest::{FixedOutput,Input};
use num::{BigInt,BigUint};
use rand::{OsRng,Rng};
use rsa::core::{decode_biguint,pkcs1_pad,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
use rsa::signing_hashes::SigningHash;
use simple_asn1::{ASN1Block,ASN1DecodeErr,ASN1EncodeErr,
                  ASN1Class,FromASN1,ToASN1};

pub trait RSAPublicKey<N> {
    /// Generate a new public key pair for the given modulus and
    /// exponent. You should probably not call this directly unless
    /// you're writing a key generation function or writing your own
    /// public key parser.
    fn new(n: N, e: N) -> Self;

    /// Verify that the provided signature is valid; that the private
    /// key associated with this public key sent exactly this message.
    /// The hash used here must exactly match the hash used to sign
    /// the message, including its ASN.1 metadata.
    fn verify(&self, signhash: &SigningHash, msg: &[u8], sig: &[u8]) -> bool;

    /// Encrypt the message with a hash function, given the appropriate
    /// label. Please note that RSA encryption is not particularly fast,
    /// and decryption is very slow indeed. Thus, most crypto systems that
    /// need asymmetric encryption should generate a symmetric key, encrypt
    /// that key with RSA encryption, and then encrypt the actual message
    /// with that symmetric key.
    ///
    /// In this variant of the function, we use an explicit random number
    /// generator, just in case you have one you really like. It better be
    /// cryptographically strong, though, as some of the padding protections
    /// are relying on it.
    fn encrypt_rng<G,H>(&self, g: &mut G, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
     where
      G: Rng,
      H: Default + Input + FixedOutput;

    /// Encrypt the message with a hash function, given the appropriate
    /// label. Please note that RSA encryption is not particularly fast,
    /// and decryption is very slow indeed. Thus, most crypto systems that
    /// need asymmetric encryption should generate a symmetric key, encrypt
    /// that key with RSA encryption, and then encrypt the actual message
    /// with that symmetric key.
    ///
    /// This variant will just use the system RNG for its randomness.
    fn encrypt<H>(&self,oaep:&OAEPParams<H>,msg:&[u8])
        -> Result<Vec<u8>,RSAError>
     where
      H: Default + Input + FixedOutput
    {
        let mut g = OsRng::new()?;
        self.encrypt_rng(&mut g, oaep, msg)
    }
}

pub enum RSAPublic {
    Key512(RSA512Public),
    Key1024(RSA1024Public),
    Key2048(RSA2048Public),
    Key3072(RSA3072Public),
    Key4096(RSA4096Public),
    Key8192(RSA8192Public),
    Key15360(RSA15360Public)
}

impl FromASN1 for RSAPublic {
    type Error = RSAError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(RSAPublic,&[ASN1Block]),RSAError>
    {
        match bs.split_first() {
            None =>
                Err(RSAError::ASN1DecodeErr(ASN1DecodeErr::EmptyBuffer)),
            Some((&ASN1Block::Sequence(_, _, ref items), rest))
                if items.len() == 2 =>
            {
                let n = decode_biguint(&items[0])?;
                let e = decode_biguint(&items[1])?;
                let nsize = n.bits();
                let mut rsa_size = 512;

                while rsa_size < nsize {
                    rsa_size = rsa_size + 256;
                }
                match rsa_size {
                    512    => {
                        let n2 = U512::from(n);
                        let e2 = U512::from(e);
                        let res = RSA512Public::new(n2, e2);
                        Ok((RSAPublic::Key512(res), rest))
                    }
                    1024    => {
                        let n2 = U1024::from(n);
                        let e2 = U1024::from(e);
                        let res = RSA1024Public::new(n2, e2);
                        Ok((RSAPublic::Key1024(res), rest))
                    }
                    2048    => {
                        let n2 = U2048::from(n);
                        let e2 = U2048::from(e);
                        let res = RSA2048Public::new(n2, e2);
                        Ok((RSAPublic::Key2048(res), rest))
                    }
                    3072    => {
                        let n2 = U3072::from(n);
                        let e2 = U3072::from(e);
                        let res = RSA3072Public::new(n2, e2);
                        Ok((RSAPublic::Key3072(res), rest))
                    }
                    4096    => {
                        let n2 = U4096::from(n);
                        let e2 = U4096::from(e);
                        let res = RSA4096Public::new(n2, e2);
                        Ok((RSAPublic::Key4096(res), rest))
                    }
                    8192    => {
                        let n2 = U8192::from(n);
                        let e2 = U8192::from(e);
                        let res = RSA8192Public::new(n2, e2);
                        Ok((RSAPublic::Key8192(res), rest))
                    }
                    15360    => {
                        let n2 = U15360::from(n);
                        let e2 = U15360::from(e);
                        let res = RSA15360Public::new(n2, e2);
                        Ok((RSAPublic::Key15360(res), rest))
                    }
                    _      =>
                        Err(RSAError::InvalidKey)
                }
            }
            Some(_) =>
                Err(RSAError::InvalidKey)
        }
    }
}

impl ToASN1 for RSAPublic {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,Self::Error>
    {
        match self {
            RSAPublic::Key512(x)   => x.to_asn1_class(c),
            RSAPublic::Key1024(x)  => x.to_asn1_class(c),
            RSAPublic::Key2048(x)  => x.to_asn1_class(c),
            RSAPublic::Key3072(x)  => x.to_asn1_class(c),
            RSAPublic::Key4096(x)  => x.to_asn1_class(c),
            RSAPublic::Key8192(x)  => x.to_asn1_class(c),
            RSAPublic::Key15360(x) => x.to_asn1_class(c)
        }
    }
}

// fn print_vector(name: &'static str, bytes: &[u8])
// {
//     print!("{}: (length {}) ", name, bytes.len());
//     for x in bytes.iter() {
//         print!("{:02X}", *x);
//     }
//     println!("");
// }

macro_rules! generate_rsa_public
{
    ($rsa: ident, $num: ident, $bar: ident, $var: ident, $size: expr) => {
        #[derive(Debug,PartialEq)]
        pub struct $rsa {
            nu: $bar,
            e:  $num
        }

        impl RSAPublicKey<$num> for $rsa {
            fn new(n: $num, e: $num) -> $rsa {
                let nu = $bar::new(&n);
                $rsa { nu: nu, e: e }
            }

            fn verify(&self, signhash: &SigningHash, msg: &[u8], sig: &[u8])
                -> bool
            {
                let hash: Vec<u8> = (signhash.run)(msg);
                let s             = $num::from_bytes(&sig);
                let m             = self.vp1(&s);
                let em            = m.to_bytes();
                let em_           = pkcs1_pad(signhash.ident, &hash, $size/8);
                em == em_
            }

            fn encrypt_rng<G,H>(&self,g: &mut G,oaep: &OAEPParams<H>,msg: &[u8])
                -> Result<Vec<u8>,RSAError>
             where
              G: Rng,
              H: Default + Input + FixedOutput
            {
                let byte_len = $size / 8;
                let mut res = Vec::new();

                if byte_len <= ((2 * oaep.hash_len()) + 2) {
                    return Err(RSAError::KeyTooSmallForHash);
                }
                for chunk in msg.chunks(byte_len - (2 * oaep.hash_len()) - 2) {
                    let mut newchunk = self.oaep_encrypt(g, oaep, chunk)?;
                    res.append(&mut newchunk);
                }

                Ok(res)
            }
        }

        impl $rsa {
            fn vp1(&self, s: &$num) -> $num {
                s.modexp(&self.e, &self.nu)
            }

            fn ep(&self, m: &$num) -> $num {
                m.modexp(&self.e, &self.nu)
            }

            fn oaep_encrypt<G,H>(&self,g: &mut G,oaep: &OAEPParams<H>,m: &[u8])
                -> Result<Vec<u8>,RSAError>
             where
              G: Rng,
              H: Default + Input + FixedOutput
            {
                let byte_len = $size / 8;
                // Step 1b
                if m.len() > (byte_len - (2 * oaep.hash_len()) - 2) {
                    return Err(RSAError::BadMessageSize)
                }
                // Step 2a
                let mut lhash = oaep.hash(oaep.label.as_bytes());
                // Step 2b
                let num0s = byte_len - m.len() - (2 * oaep.hash_len()) - 2;
                let mut ps = Vec::new();
                ps.resize(num0s, 0);
                // Step 2c
                let mut db = Vec::new();
                db.append(&mut lhash);
                db.append(&mut ps);
                db.push(1);
                db.extend_from_slice(m);
                // Step 2d
                let seed : Vec<u8> = g.gen_iter().take(oaep.hash_len()).collect();
                // Step 2e
                let db_mask = oaep.mgf1(&seed, byte_len - oaep.hash_len() - 1);
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
                let m_i = $num::from_bytes(&em);
                // Step 3b
                let c_i = self.ep(&m_i);
                // Step 3c
                let c = c_i.to_bytes();
                Ok(c)
            }
        }

        impl FromASN1 for $rsa {
            type Error = RSAError;

            fn from_asn1(bs: &[ASN1Block])
                -> Result<($rsa,&[ASN1Block]),RSAError>
            {
                let (core, rest) = RSAPublic::from_asn1(bs)?;

                match core {
                    RSAPublic::$var(x) => Ok((x, rest)),
                    _                  => Err(RSAError::InvalidKey)
                }
            }
        }

        impl ToASN1 for $rsa {
            type Error = ASN1EncodeErr;

            fn to_asn1_class(&self, c: ASN1Class)
                -> Result<Vec<ASN1Block>,Self::Error>
            {
                let n = BigInt::from(BigUint::from(self.nu.m.clone()));
                let e = BigInt::from(BigUint::from(self.e.clone()));
                let enc_n = ASN1Block::Integer(c, 0, n);
                let enc_e = ASN1Block::Integer(c, 0, e);
                let seq = ASN1Block::Sequence(c, 0, vec![enc_n, enc_e]);
                Ok(vec![seq])
            }
        }
    }
}

generate_rsa_public!(RSA512Public,   U512,   BarrettU512,   Key512,   512);
generate_rsa_public!(RSA1024Public,  U1024,  BarrettU1024,  Key1024,  1024);
generate_rsa_public!(RSA2048Public,  U2048,  BarrettU2048,  Key2048,  2048);
generate_rsa_public!(RSA3072Public,  U3072,  BarrettU3072,  Key3072,  3072);
generate_rsa_public!(RSA4096Public,  U4096,  BarrettU4096,  Key4096,  4096);
generate_rsa_public!(RSA8192Public,  U8192,  BarrettU8192,  Key8192,  8192);
generate_rsa_public!(RSA15360Public, U15360, BarrettU15360, Key15360, 15360);

macro_rules! generate_tests {
    ( $( ($mod: ident, $rsa: ident, $num: ident, $size: expr) ),* ) => {
        $(
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::Decoder;
            use super::*;
            use testing::run_test;
            use rsa::signing_hashes::*;

            #[test]
            fn encode() {
                let fname = format!("tests/rsa/rsa{}.test", $size);
                run_test(fname.to_string(), 6, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();

                    assert!(!neg0);
                    let n = $num::from_bytes(nbytes);
                    let e = $num::from(65537u64);
                    let pubkey = $rsa::new(n, e);
                    let asn1 = pubkey.to_asn1().unwrap();
                    let (pubkey2, _) = $rsa::from_asn1(&asn1).unwrap();
                    assert_eq!(pubkey, pubkey2);
                });
            }

            #[test]
            fn verify() {
                let fname = format!("tests/rsa/rsa{}.test", $size);
                run_test(fname.to_string(), 6, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, hbytes) = case.get("h").unwrap();
                    let (neg2, mbytes) = case.get("m").unwrap();
                    let (neg3, sbytes) = case.get("s").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3);
                    let n = $num::from_bytes(nbytes);
                    let e = $num::from(65537u64);
                    let pubkey = $rsa::new(n, e);
                    let hashnum = ((hbytes[0] as u16)<<8) + (hbytes[1] as u16);
                    let sighash = match hashnum {
                                    0x160 => &SIGNING_HASH_SHA1,
                                    0x224 => &SIGNING_HASH_SHA224,
                                    0x256 => &SIGNING_HASH_SHA256,
                                    0x384 => &SIGNING_HASH_SHA384,
                                    0x512 => &SIGNING_HASH_SHA512,
                                    _     => panic!("Bad signing hash: {}", hashnum)
                                  };
                    assert!(pubkey.verify(sighash, &mbytes, &sbytes));
                });
            }

            #[test]
            fn encrypt() {
                let fname = format!("tests/rsa/rsa{}.test", $size);
                run_test(fname.to_string(), 6, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, hbytes) = case.get("h").unwrap();
                    let (neg2, mbytes) = case.get("m").unwrap();
                    let (neg3, sbytes) = case.get("s").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3);
                    let n = $num::from_bytes(nbytes);
                    let e = $num::from(65537u64);
                    let pubkey = $rsa::new(n, e);
                    let hashnum = ((hbytes[0] as u16)<<8) + (hbytes[1] as u16);
                    let sighash = match hashnum {
                                    0x160 => &SIGNING_HASH_SHA1,
                                    0x224 => &SIGNING_HASH_SHA224,
                                    0x256 => &SIGNING_HASH_SHA256,
                                    0x384 => &SIGNING_HASH_SHA384,
                                    0x512 => &SIGNING_HASH_SHA512,
                                    _     => panic!("Bad signing hash: {}", hashnum)
                                  };
                    assert!(pubkey.verify(sighash, &mbytes, &sbytes));
                });
             }
        }
        )*
    }
}

generate_tests!( (RSA512,   RSA512Public,   U512,   512),
                 (RSA1024,  RSA1024Public,  U1024,  1024),
                 (RSA2048,  RSA2048Public,  U2048,  2048),
                 (RSA3072,  RSA3072Public,  U3072,  3072),
                 (RSA4096,  RSA4096Public,  U4096,  4096),
                 (RSA8192,  RSA8192Public,  U8192,  8192),
                 (RSA15360, RSA15360Public, U15360, 15360)
               );
