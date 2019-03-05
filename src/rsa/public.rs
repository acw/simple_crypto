use cryptonum::unsigned::*;
use digest::{Digest,FixedOutput};
use rand::Rng;
use rand::rngs::OsRng;
use rsa::core::{decode_biguint,pkcs1_pad,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
use rsa::signing_hashes::SigningHash;
use simple_asn1::{ASN1Block,ASN1DecodeErr,ASN1EncodeErr,
                  ASN1Class,FromASN1,ToASN1};
#[cfg(test)]
use std::fmt;
use utils::TranslateNums;

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
      H: Default + Digest + FixedOutput;

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
      H: Default + Digest + FixedOutput
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

impl RSAPublic {
    pub fn verify(&self, signhash: &SigningHash, msg: &[u8], sig: &[u8]) -> bool
    {
        match self {
            RSAPublic::Key512(x)   => x.verify(signhash, msg, sig),
            RSAPublic::Key1024(x)  => x.verify(signhash, msg, sig),
            RSAPublic::Key2048(x)  => x.verify(signhash, msg, sig),
            RSAPublic::Key3072(x)  => x.verify(signhash, msg, sig),
            RSAPublic::Key4096(x)  => x.verify(signhash, msg, sig),
            RSAPublic::Key8192(x)  => x.verify(signhash, msg, sig),
            RSAPublic::Key15360(x) => x.verify(signhash, msg, sig)
        }
    }
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

                println!("n': {:X}", n);
                println!("nsize: {}", nsize);
                while rsa_size < nsize {
                    rsa_size = rsa_size + 256;
                }
                match rsa_size {
                    512    => {
                        let n2 = U512::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U512::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA512Public::new(n2, e2);
                        Ok((RSAPublic::Key512(res), rest))
                    }
                    1024    => {
                        let n2 = U1024::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U1024::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA1024Public::new(n2, e2);
                        Ok((RSAPublic::Key1024(res), rest))
                    }
                    2048    => {
                        let n2 = U2048::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U2048::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA2048Public::new(n2, e2);
                        Ok((RSAPublic::Key2048(res), rest))
                    }
                    3072    => {
                        let n2 = U3072::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U3072::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA3072Public::new(n2, e2);
                        Ok((RSAPublic::Key3072(res), rest))
                    }
                    4096    => {
                        let n2 = U4096::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U4096::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA4096Public::new(n2, e2);
                        Ok((RSAPublic::Key4096(res), rest))
                    }
                    8192    => {
                        let n2 = U8192::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U8192::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSA8192Public::new(n2, e2);
                        Ok((RSAPublic::Key8192(res), rest))
                    }
                    15360    => {
                        let n2 = U15360::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U15360::from_num(&e).ok_or(RSAError::InvalidKey)?;
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
        #[derive(PartialEq)]
        pub struct $rsa {
            pub(crate) n:  $num,
            pub(crate) nu: $bar,
            pub(crate) e:  $num
        }

        impl RSAPublicKey<$num> for $rsa {
            fn new(n: $num, e: $num) -> $rsa {
                let nu = $bar::new(n.clone());
                $rsa { n: n, nu: nu, e: e }
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
              H: Default + Digest + FixedOutput
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
              H: Default + Digest + FixedOutput
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
                let mut seed: Vec<u8> = Vec::with_capacity(oaep.hash_len());
                seed.resize(oaep.hash_len(), 0);
                g.fill(seed.as_mut_slice());
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
                let n = self.n.to_num();
                let e = self.e.to_num();
                let enc_n = ASN1Block::Integer(c, 0, n);
                let enc_e = ASN1Block::Integer(c, 0, e);
                let seq = ASN1Block::Sequence(c, 0, vec![enc_n, enc_e]);
                Ok(vec![seq])
            }
        }

        #[cfg(test)]
        impl fmt::Debug for $rsa {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_struct(stringify!($rsa))
                   .field("n", &self.n)
                   .field("nu", &self.nu)
                   .field("e", &self.e)
                   .finish()
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
    ( $( ($mod: ident, $rsa: ident, $priv: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) ),* ) => {
        $(
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::unsigned::Decoder;
            use super::*;
            use testing::run_test;
            use rsa::private::*;
            use rsa::signing_hashes::*;
            use sha2::{Sha224,Sha256,Sha384,Sha512};

            #[test]
            fn new() {
                let fname = format!("testdata/rsa/sign{}.test", $size);
                run_test(fname.to_string(), 7, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, ubytes) = case.get("u").unwrap();
                    let (neg2, kbytes) = case.get("k").unwrap();

                    assert!(!neg0&&!neg1&&!neg2);
                    let n = $num::from_bytes(nbytes);
                    let n64 = $num64::from(&n);
                    let nu = $num64::from_bytes(ubytes);
                    let bigk = $num::from_bytes(kbytes);
                    let k = usize::from(bigk);
                    let e = $num::from(65537u64);
                    let pubkey2 = $rsa::new(n.clone(), e.clone());
                    let pubkey1 = $rsa{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
                    assert_eq!(pubkey1, pubkey2);
                });
            }

            #[test]
            fn encode() {
                let fname = format!("testdata/rsa/sign{}.test", $size);
                run_test(fname.to_string(), 7, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, ubytes) = case.get("u").unwrap();
                    let (neg2, kbytes) = case.get("k").unwrap();

                    assert!(!neg0&&!neg1&&!neg2);
                    let n = $num::from_bytes(nbytes);
                    let n64 = $num64::from(&n);
                    let nu = $num64::from_bytes(ubytes);
                    let bigk = $num::from_bytes(kbytes);
                    let k = usize::from(bigk);
                    let e = $num::from(65537u64);
                    let pubkey = $rsa{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
                    let asn1 = pubkey.to_asn1().unwrap();
                    let (pubkey2, _) = $rsa::from_asn1(&asn1).unwrap();
                    assert_eq!(pubkey, pubkey2);
                });
            }

            #[test]
            fn verify() {
                let fname = format!("testdata/rsa/sign{}.test", $size);
                run_test(fname.to_string(), 7, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, hbytes) = case.get("h").unwrap();
                    let (neg2, mbytes) = case.get("m").unwrap();
                    let (neg3, sbytes) = case.get("s").unwrap();
                    let (neg4, ubytes) = case.get("u").unwrap();
                    let (neg5, kbytes) = case.get("k").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 && !neg5);
                    let n = $num::from_bytes(nbytes);
                    let n64 = $num64::from(&n);
                    let nu = $num64::from_bytes(ubytes);
                    let bigk = $num::from_bytes(kbytes);
                    let k = usize::from(bigk);
                    let e = $num::from(65537u64);
                    let pubkey = $rsa{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
                    let hashnum = u64::from($num::from_bytes(hbytes));
                    let sighash = match hashnum {
                                    160 => &SIGNING_HASH_SHA1,
                                    224 => &SIGNING_HASH_SHA224,
                                    256 => &SIGNING_HASH_SHA256,
                                    384 => &SIGNING_HASH_SHA384,
                                    512 => &SIGNING_HASH_SHA512,
                                    _   => panic!("Bad signing hash: {}", hashnum)
                                  };
                    assert!(pubkey.verify(sighash, &mbytes, &sbytes));
                });
            }

            #[test]
            fn encrypt() {
                let fname = format!("testdata/rsa/encrypt{}.test", $size);
                run_test(fname.to_string(), 9, |case| {
                    let (neg0, nbytes) = case.get("n").unwrap();
                    let (neg1, hbytes) = case.get("h").unwrap();
                    let (neg2, mbytes) = case.get("m").unwrap();
                    let (neg3, _bytes) = case.get("e").unwrap();
                    let (neg4, ubytes) = case.get("u").unwrap();
                    let (neg5, kbytes) = case.get("k").unwrap();
                    let (neg6, dbytes) = case.get("d").unwrap();
                    let (neg7, lbytes) = case.get("l").unwrap();

                    assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 && !neg5 && !neg6 && !neg7);
                    let n = $num::from_bytes(nbytes);
                    let n64 = $num64::from(&n);
                    let nu = $num64::from_bytes(ubytes);
                    let bigk = $num::from_bytes(kbytes);
                    let k = usize::from(bigk);
                    let e = $num::from(65537u64);
                    let d = $num::from_bytes(dbytes);
                    let nu = $bar::from_components(k, n64, nu);
                    let pubkey = $rsa{ n: n.clone(), nu: nu.clone(), e: e };
                    let privkey = $priv{ nu: nu, d: d };
                    let lstr = String::from_utf8(lbytes.clone()).unwrap();
                    let cipher = match usize::from($num::from_bytes(hbytes)) {
                        224 => pubkey.encrypt(&OAEPParams::<Sha224>::new(lstr.clone()), mbytes),
                        256 => pubkey.encrypt(&OAEPParams::<Sha256>::new(lstr.clone()), mbytes),
                        384 => pubkey.encrypt(&OAEPParams::<Sha384>::new(lstr.clone()), mbytes),
                        512 => pubkey.encrypt(&OAEPParams::<Sha512>::new(lstr.clone()), mbytes),
                        x   => panic!("Unknown hash number: {}", x)
                    };
                    assert!(cipher.is_ok());
                    let message = match usize::from($num::from_bytes(hbytes)) {
                        224 => privkey.decrypt(&OAEPParams::<Sha224>::new(lstr), &cipher.unwrap()),
                        256 => privkey.decrypt(&OAEPParams::<Sha256>::new(lstr), &cipher.unwrap()),
                        384 => privkey.decrypt(&OAEPParams::<Sha384>::new(lstr), &cipher.unwrap()),
                        512 => privkey.decrypt(&OAEPParams::<Sha512>::new(lstr), &cipher.unwrap()),
                        x   => panic!("Unknown hash number: {}", x)
                                  };
                    assert!(message.is_ok());
                    assert_eq!(mbytes, &message.unwrap());
                });
             }
        }
        )*
    }
}

generate_tests!( (RSA512,   RSA512Public,   RSA512Private,   U512,   BarrettU512,   U576,   512),
                 (RSA1024,  RSA1024Public,  RSA1024Private,  U1024,  BarrettU1024,  U1088,  1024),
                 (RSA2048,  RSA2048Public,  RSA2048Private,  U2048,  BarrettU2048,  U2112,  2048),
                 (RSA3072,  RSA3072Public,  RSA3072Private,  U3072,  BarrettU3072,  U3136,  3072),
                 (RSA4096,  RSA4096Public,  RSA4096Private,  U4096,  BarrettU4096,  U4160,  4096),
                 (RSA8192,  RSA8192Public,  RSA8192Private,  U8192,  BarrettU8192,  U8256,  8192),
                 (RSA15360, RSA15360Public, RSA15360Private, U15360, BarrettU15360, U15424, 15360)
               );