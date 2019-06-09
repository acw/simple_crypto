use cryptonum::unsigned::*;
use rsa::core::{RSAMode,drop0s,pkcs1_pad,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
use rsa::signing_hashes::SigningHash;
use sha::Hash;

/// An RSA private key. Useful for signing messages and decrypting encrypted
/// content.
#[derive(Clone,PartialEq)]
pub struct RSAPrivateKey<R: RSAMode>
{
    pub(crate) nu: R::Barrett,
    pub(crate) d:  R
}

/// A generic RSA private key which is agnostic to its key size.
#[derive(Clone,PartialEq)]
pub enum RSAPrivate {
    Key512(RSAPrivateKey<U512>),
    Key1024(RSAPrivateKey<U1024>),
    Key2048(RSAPrivateKey<U2048>),
    Key3072(RSAPrivateKey<U3072>),
    Key4096(RSAPrivateKey<U4096>),
    Key8192(RSAPrivateKey<U8192>),
    Key15360(RSAPrivateKey<U15360>)
}

macro_rules! generate_rsa_private
{
    ($num: ident, $bar: ident, $size: expr) => {
        impl RSAPrivateKey<$num> {
            /// Generate a new private key with the given modulus and private
            /// number (`d`). This operation actually does a bit of computation
            /// under the hood, in order to speed up future ones, so you might
            /// want to strongly consider sharing rather than multiple
            /// instantiation. But you do you.
            pub fn new(n: $num, d: $num) -> RSAPrivateKey<$num> {
                let nu = $bar::new(n.clone());
                RSAPrivateKey{ nu: nu, d: d }
            }

            /// Sign the given message with the given SigningHash, returning
            /// the signature. This uses a deterministic PKCS1 method for
            /// signing messages, so no RNG required.
            pub fn sign(&self, signhash: &SigningHash, msg: &[u8])
                -> Vec<u8>
            {
                let hash = (signhash.run)(msg);
                let em   = pkcs1_pad(&signhash.ident, &hash, $size/8);
                let m    = $num::from_bytes(&em);
                let s    = self.sp1(&m);
                let sig  = s.to_bytes();
                sig
            }

            /// Decrypted the provided encrypted blob using the given
            /// parameters. This does standard RSA OAEP decryption, which is
            /// rather slow. If you have a choice, you should probably do
            /// something clever, like only use this encryption/decryption
            /// method to encrypt/decrypt a shared symmetric key, like an
            /// AES key. That way, you only do this operation (which is
            /// SO SLOW) for a relatively small amount of data.
            pub fn decrypt<H: Hash>(&self, oaep: &OAEPParams<H>, msg: &[u8])
                -> Result<Vec<u8>,RSAError>
            {
                let mut res = Vec::new();

                for chunk in msg.chunks($size/8) {
                    let mut dchunk = self.oaep_decrypt(oaep, chunk)?;
                    res.append(&mut dchunk);
                }

                Ok(res)
            }

            fn sp1(&self, m: &$num) -> $num {
                m.modexp(&self.d, &self.nu)
            }

            fn dp(&self, c: &$num) -> $num {
                c.modexp(&self.d, &self.nu)
            }

            fn oaep_decrypt<H: Hash>(&self, oaep: &OAEPParams<H>, c: &[u8])
                -> Result<Vec<u8>,RSAError>
            {
                let byte_len = $size / 8;
                // Step 1b
                if c.len() != byte_len {
                    return Err(RSAError::DecryptionError);
                }
                // Step 1c
                if byte_len < ((2 * oaep.hash_len()) + 2) {
                    return Err(RSAError::DecryptHashMismatch);
                }
                // Step 2a
                let c_ip = $num::from_bytes(&c);
                // Step 2b
                let m_ip = self.dp(&c_ip);
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
    }
}

generate_rsa_private!(U512,   BarrettU512,   512);
generate_rsa_private!(U1024,  BarrettU1024,  1024);
generate_rsa_private!(U2048,  BarrettU2048,  2048);
generate_rsa_private!(U3072,  BarrettU3072,  3072);
generate_rsa_private!(U4096,  BarrettU4096,  4096);
generate_rsa_private!(U8192,  BarrettU8192,  8192);
generate_rsa_private!(U15360, BarrettU15360, 15360);

#[cfg(test)]
macro_rules! sign_test_body {
    ($mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
        let fname = format!("testdata/rsa/sign{}.test", $size);
        run_test(fname.to_string(), 7, |case| {
            let (neg0, dbytes) = case.get("d").unwrap();
            let (neg1, nbytes) = case.get("n").unwrap();
            let (neg2, hbytes) = case.get("h").unwrap();
            let (neg3, mbytes) = case.get("m").unwrap();
            let (neg4, sbytes) = case.get("s").unwrap();
            let (neg5, ubytes) = case.get("u").unwrap();
            let (neg6, kbytes) = case.get("k").unwrap();

            assert!(!neg0&&!neg1&&!neg2&&!neg3&&!neg4&&!neg5&&!neg6);
            let n = $num64::from_bytes(nbytes);
            let nu = $num64::from_bytes(ubytes);
            let bigk = $num::from_bytes(kbytes);
            let k = usize::from(bigk);
            let d = $num::from_bytes(dbytes);
            let sighash = match usize::from($num::from_bytes(hbytes)) {
                            224 => &SIGNING_HASH_SHA224,
                            256 => &SIGNING_HASH_SHA256,
                            384 => &SIGNING_HASH_SHA384,
                            512 => &SIGNING_HASH_SHA512,
                            x     => panic!("Bad signing hash: {}", x)
                          };
            let privkey = RSAPrivateKey{ nu: $bar::from_components(k, n.clone(), nu), d: d };
            let sig = privkey.sign(sighash, &mbytes);
            assert_eq!(*sbytes, sig);
        });
    };
}

#[cfg(test)]
macro_rules! decrypt_test_body {
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
            let (neg8, cbytes) = case.get("c").unwrap();

            assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 && !neg5 && !neg6 && !neg7 && !neg8);
            let n = $num::from_bytes(nbytes);
            let n64 = $num64::from(&n);
            let nu = $num64::from_bytes(ubytes);
            let bigk = $num::from_bytes(kbytes);
            let k = usize::from(bigk);
            let d = $num::from_bytes(dbytes);
            let nu = $bar::from_components(k, n64, nu);
            let privkey = RSAPrivateKey{ nu: nu, d: d };
            let lstr = String::from_utf8(lbytes.clone()).unwrap();
            let message = match usize::from($num::from_bytes(hbytes)) {
                224 => privkey.decrypt(&OAEPParams::<SHA224>::new(lstr), &cbytes),
                256 => privkey.decrypt(&OAEPParams::<SHA256>::new(lstr), &cbytes),
                384 => privkey.decrypt(&OAEPParams::<SHA384>::new(lstr), &cbytes),
                512 => privkey.decrypt(&OAEPParams::<SHA512>::new(lstr), &cbytes),
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
            use rsa::signing_hashes::*;
            use sha::{SHA224,SHA256,SHA384,SHA512};

            #[test]
            fn sign() {
                sign_test_body!($mod, $num, $bar, $num64, $size);
            }

            #[test]
            fn decrypt() {
                decrypt_test_body!($mod, $num, $bar, $num64, $size);
            }
        }
    };
    (ignore $mod: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) => {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::unsigned::Decoder;
            use super::*;
            use testing::run_test;
            use rsa::signing_hashes::*;
            use sha::{SHA224,SHA256,SHA384,SHA512};

            #[ignore]
            #[test]
            fn sign() {
                sign_test_body!($mod, $num, $bar, $num64, $size);
            }

            #[ignore]
            #[test]
            fn decrypt() {
                decrypt_test_body!($mod, $num, $bar, $num64, $size);
            }
        }
    }
}

generate_tests!(       RSA512,   U512,   BarrettU512,   U576,   512);
generate_tests!(       RSA1024,  U1024,  BarrettU1024,  U1088,  1024);
generate_tests!(       RSA2048,  U2048,  BarrettU2048,  U2112,  2048);
generate_tests!(       RSA3072,  U3072,  BarrettU3072,  U3136,  3072);
generate_tests!(       RSA4096,  U4096,  BarrettU4096,  U4160,  4096);
generate_tests!(ignore RSA8192,  U8192,  BarrettU8192,  U8256,  8192);
generate_tests!(ignore RSA15360, U15360, BarrettU15360, U15424, 15360);