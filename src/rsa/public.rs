use cryptonum::unsigned::*;
use digest::{Digest,FixedOutput};
use rand::Rng;
use rand::rngs::OsRng;
use rsa::core::{RSAMode,decode_biguint,pkcs1_pad,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
use rsa::signing_hashes::SigningHash;
use simple_asn1::{ASN1Block,ASN1DecodeErr,ASN1EncodeErr,
                  ASN1Class,FromASN1,ToASN1};
#[cfg(test)]
use std::fmt;
use utils::TranslateNums;

/// An RSA public key. Useful for verifying signatures or encrypting data to
/// send to the private key holder.
#[derive(Clone,PartialEq)]
pub struct RSAPublicKey<R: RSAMode> {
    pub(crate) n:  R,
    pub(crate) nu: R::Barrett,
    pub(crate) e:  R 
}

/// A generic private key that is agnostic to the key size.
#[derive(Clone,PartialEq)]
pub enum RSAPublic {
    Key512(  RSAPublicKey<U512>),
    Key1024( RSAPublicKey<U1024>),
    Key2048( RSAPublicKey<U2048>),
    Key3072( RSAPublicKey<U3072>),
    Key4096( RSAPublicKey<U4096>),
    Key8192( RSAPublicKey<U8192>),
    Key15360(RSAPublicKey<U15360>)
}

impl RSAPublic {
    /// Verify that the given signature is for the given message, passing
    /// in the same signing arguments used to sign the message in the
    /// first place.
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

                while rsa_size < nsize {
                    rsa_size = rsa_size + 256;
                }
                match rsa_size {
                    512    => {
                        let n2 = U512::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U512::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U512>::new(n2, e2);
                        Ok((RSAPublic::Key512(res), rest))
                    }
                    1024    => {
                        let n2 = U1024::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U1024::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U1024>::new(n2, e2);
                        Ok((RSAPublic::Key1024(res), rest))
                    }
                    2048    => {
                        let n2 = U2048::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U2048::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U2048>::new(n2, e2);
                        Ok((RSAPublic::Key2048(res), rest))
                    }
                    3072    => {
                        let n2 = U3072::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U3072::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U3072>::new(n2, e2);
                        Ok((RSAPublic::Key3072(res), rest))
                    }
                    4096    => {
                        let n2 = U4096::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U4096::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U4096>::new(n2, e2);
                        Ok((RSAPublic::Key4096(res), rest))
                    }
                    8192    => {
                        let n2 = U8192::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U8192::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U8192>::new(n2, e2);
                        Ok((RSAPublic::Key8192(res), rest))
                    }
                    15360    => {
                        let n2 = U15360::from_num(&n).ok_or(RSAError::InvalidKey)?;
                        let e2 = U15360::from_num(&e).ok_or(RSAError::InvalidKey)?;
                        let res = RSAPublicKey::<U15360>::new(n2, e2);
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

#[cfg(test)]
impl fmt::Debug for RSAPublic {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RSAPublic::Key512(x)   => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key1024(x)  => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key2048(x)  => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key3072(x)  => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key4096(x)  => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key8192(x)  => write!(fmt, "RSA:{:?}", x),
            RSAPublic::Key15360(x) => write!(fmt, "RSA:{:?}", x)
        }
    }
}
 
macro_rules! generate_rsa_public
{
    ($num: ident, $bar: ident, $var: ident, $size: expr) => {
        impl RSAPublicKey<$num> {
            /// Generate a new public key pair for the given modulus and
            /// exponent. You should probably not call this directly unless
            /// you're writing a key generation function or writing your own
            /// public key parser.
            pub fn new(n: $num, e: $num) -> RSAPublicKey<$num> {
                let nu = $bar::new(n.clone());
                RSAPublicKey{ n: n, nu: nu, e: e }
            }

            /// Verify that the provided signature is valid; that the private
            /// key associated with this public key sent exactly this message.
            /// The hash used here must exactly match the hash used to sign
            /// the message, including its ASN.1 metadata.
            pub fn verify(&self, signhash: &SigningHash, msg: &[u8], sig: &[u8])
                -> bool
            {
                let hash: Vec<u8> = (signhash.run)(msg);
                let s             = $num::from_bytes(&sig);
                let m             = self.vp1(&s);
                let em            = m.to_bytes();
                let em_           = pkcs1_pad(signhash.ident, &hash, $size/8);
                em == em_
            }

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
            pub fn encrypt_rng<G,H>(&self,g: &mut G,oaep: &OAEPParams<H>,msg: &[u8])
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

            /// Encrypt the message with a hash function, given the appropriate
            /// label. Please note that RSA encryption is not particularly fast,
            /// and decryption is very slow indeed. Thus, most crypto systems that
            /// need asymmetric encryption should generate a symmetric key, encrypt
            /// that key with RSA encryption, and then encrypt the actual message
            /// with that symmetric key.
            ///
            /// This variant will just use the system RNG for its randomness.
            pub fn encrypt<H>(&self,oaep:&OAEPParams<H>,msg:&[u8])
                -> Result<Vec<u8>,RSAError>
             where
              H: Default + Digest + FixedOutput
            {
                let mut g = OsRng::new()?;
                self.encrypt_rng(&mut g, oaep, msg)
            }

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

        impl FromASN1 for RSAPublicKey<$num> {
            type Error = RSAError;

            fn from_asn1(bs: &[ASN1Block])
                -> Result<(RSAPublicKey<$num>,&[ASN1Block]),RSAError>
            {
                let (core, rest) = RSAPublic::from_asn1(bs)?;

                match core {
                    RSAPublic::$var(x) => Ok((x, rest)),
                    _                  => Err(RSAError::InvalidKey)
                }
            }
        }

        impl ToASN1 for RSAPublicKey<$num> {
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
        impl fmt::Debug for RSAPublicKey<$num> {
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

generate_rsa_public!(U512,   BarrettU512,   Key512,   512);
generate_rsa_public!(U1024,  BarrettU1024,  Key1024,  1024);
generate_rsa_public!(U2048,  BarrettU2048,  Key2048,  2048);
generate_rsa_public!(U3072,  BarrettU3072,  Key3072,  3072);
generate_rsa_public!(U4096,  BarrettU4096,  Key4096,  4096);
generate_rsa_public!(U8192,  BarrettU8192,  Key8192,  8192);
generate_rsa_public!(U15360, BarrettU15360, Key15360, 15360);

#[cfg(test)]
macro_rules! new_test_body {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
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
            let pubkey2 = RSAPublicKey::<$num>::new(n.clone(), e.clone());
            let pubkey1 = RSAPublicKey{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
            assert_eq!(pubkey1, pubkey2);
        });
    };
}

#[cfg(test)]
macro_rules! encode_test_body {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
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
            let pubkey = RSAPublicKey{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
            let asn1 = pubkey.to_asn1().unwrap();
            let (pubkey2, _) = RSAPublicKey::from_asn1(&asn1).unwrap();
            assert_eq!(pubkey, pubkey2);
        });
    };
}

#[cfg(test)]
macro_rules! verify_test_body {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
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
            let pubkey = RSAPublicKey{ n: n, nu: $bar::from_components(k, n64, nu), e: e };
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
    };
}

#[cfg(test)]
macro_rules! encrypt_test_body {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
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
            let pubkey = RSAPublicKey{ n: n.clone(), nu: nu.clone(), e: e };
            let privkey = RSAPrivateKey{ nu: nu, d: d };
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
    };
}

macro_rules! generate_tests {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
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
            fn new() { new_test_body!($mod, $num, $bar, $num64, $size); }
            #[test]
            fn encode() { encode_test_body!($mod, $num, $bar, $num64, $size); }
            #[test]
            fn verify() { verify_test_body!($mod, $num, $bar, $num64, $size); }
            #[test]
            fn encrypt() { encrypt_test_body!($mod, $num, $bar, $num64, $size); }
        }
    };
    (ignore $mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::unsigned::Decoder;
            use super::*;
            use testing::run_test;
            use rsa::private::*;
            use rsa::signing_hashes::*;
            use sha2::{Sha224,Sha256,Sha384,Sha512};

            #[ignore]
            #[test]
            fn new() { new_test_body!($mod, $num, $bar, $num64, $size); }
            #[ignore]
            #[test]
            fn encode() { encode_test_body!($mod, $num, $bar, $num64, $size); }
            #[ignore]
            #[test]
            fn verify() { verify_test_body!($mod, $num, $bar, $num64, $size); }
            #[ignore]
            #[test]
            fn encrypt() { encrypt_test_body!($mod, $num, $bar, $num64, $size); }
        }
    };
}

generate_tests!(       RSA512,   U512,   BarrettU512,   U576,   512);
generate_tests!(       RSA1024,  U1024,  BarrettU1024,  U1088,  1024);
generate_tests!(       RSA2048,  U2048,  BarrettU2048,  U2112,  2048);
generate_tests!(       RSA3072,  U3072,  BarrettU3072,  U3136,  3072);
generate_tests!(       RSA4096,  U4096,  BarrettU4096,  U4160,  4096);
generate_tests!(ignore RSA8192,  U8192,  BarrettU8192,  U8256,  8192);
generate_tests!(ignore RSA15360, U15360, BarrettU15360, U15424, 15360);