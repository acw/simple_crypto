use cryptonum::unsigned::*;
use digest::{FixedOutput,Input};
use rsa::core::{drop0s,pkcs1_pad,xor_vecs};
use rsa::errors::RSAError;
use rsa::oaep::OAEPParams;
use rsa::signing_hashes::SigningHash;

pub trait RSAPrivateKey<N> {
    /// Generate a new private key using the given modulus and private
    /// exponent. You probably don't want to use this function directly
    /// unless you're writing your own key generation routine or key
    /// parsing library.
    fn new(n: N, d: N) -> Self;

    /// Sign the given message with the given private key.
    fn sign(&self, signhash: &SigningHash, msg: &[u8]) -> Vec<u8>;

    /// Decrypt the provided message using the given OAEP parameters. As
    /// mentioned in the comment for encryption, RSA decryption is really,
    /// really slow. So if your plaintext is larger than about half the
    /// bit size of the key, it's almost certainly a better idea to generate
    /// a fresh symmetric encryption key, encrypt only the key with RSA, and
    /// then encrypt the message with that key.
    fn decrypt<H>(&self, oaep: &OAEPParams<H>, msg: &[u8])
        -> Result<Vec<u8>,RSAError>
     where H: Default + Input + FixedOutput;
}

pub enum RSAPrivate {
    Key512(RSA512Private),
    Key1024(RSA1024Private),
    Key2048(RSA2048Private),
    Key3072(RSA3072Private),
    Key4096(RSA4096Private),
    Key8192(RSA8192Private),
    Key15360(RSA15360Private)
}

// fn print_vector(name: &'static str, bytes: &[u8])
// {
//     print!("{}: (length {}) ", name, bytes.len());
//     for x in bytes.iter() {
//         print!("{:02X}", *x);
//     }
//     println!("");
// }

macro_rules! generate_rsa_private
{
    ($rsa: ident, $num: ident, $bar: ident, $size: expr) => {
        pub struct $rsa {
            nu: $bar,
            d:  $num
        }

        impl RSAPrivateKey<$num> for $rsa {
            fn new(n: $num, d: $num) -> $rsa {
                let nu = $bar::new(n.clone());
                $rsa { nu: nu, d: d }
            }

            fn sign(&self, signhash: &SigningHash, msg: &[u8])
                -> Vec<u8>
            {
                let hash = (signhash.run)(msg);
                let em   = pkcs1_pad(&signhash.ident, &hash, $size/8);
                let m    = $num::from_bytes(&em);
                let s    = self.sp1(&m);
                let sig  = s.to_bytes();
                sig
            }

            fn decrypt<H>(&self, oaep: &OAEPParams<H>, msg: &[u8])
                -> Result<Vec<u8>,RSAError>
             where H: Default + Input + FixedOutput
            {
                let mut res = Vec::new();

                for chunk in msg.chunks($size/8) {
                    let mut dchunk = self.oaep_decrypt(oaep, chunk)?;
                    res.append(&mut dchunk);
                }

                Ok(res)
            }
        }

        impl $rsa {
            fn sp1(&self, m: &$num) -> $num {
                m.modexp(&self.d, &self.nu)
            }

            fn dp(&self, c: &$num) -> $num {
                c.modexp(&self.d, &self.nu)
            }

            fn oaep_decrypt<H>(&self, oaep: &OAEPParams<H>, c: &[u8])
                -> Result<Vec<u8>,RSAError>
             where
              H: Default + Input + FixedOutput
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

generate_rsa_private!(RSA512Private,   U512,   BarrettU512,   512);
generate_rsa_private!(RSA1024Private,  U1024,  BarrettU1024,  1024);
generate_rsa_private!(RSA2048Private,  U2048,  BarrettU2048,  2048);
generate_rsa_private!(RSA3072Private,  U3072,  BarrettU3072,  3072);
generate_rsa_private!(RSA4096Private,  U4096,  BarrettU4096,  4096);
generate_rsa_private!(RSA8192Private,  U8192,  BarrettU8192,  8192);
generate_rsa_private!(RSA15360Private, U15360, BarrettU15360, 15360);

macro_rules! generate_tests {
    ( $( ($mod: ident, $rsa: ident, $num: ident, $bar: ident, $num64: ident, $size: expr) ),* ) => {
        $(
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $mod {
            use cryptonum::unsigned::Decoder;
            use super::*;
            use testing::run_test;
            use rsa::signing_hashes::*;
            use sha1::Sha1;
            use sha2::{Sha224,Sha256,Sha384,Sha512};

            #[test]
            fn sign() {
                let fname = format!("tests/rsa/rsa{}.test", $size);
                run_test(fname.to_string(), 8, |case| {
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
                    let privkey = $rsa{ nu: $bar::from_components(k, n, nu), d: d };
                    let hashnum = ((hbytes[0] as u16)<<8) + (hbytes[1] as u16);
                    let sighash = match hashnum {
                                    0x160 => &SIGNING_HASH_SHA1,
                                    0x224 => &SIGNING_HASH_SHA224,
                                    0x256 => &SIGNING_HASH_SHA256,
                                    0x384 => &SIGNING_HASH_SHA384,
                                    0x512 => &SIGNING_HASH_SHA512,
                                    _     => panic!("Bad signing hash: {}", hashnum)
                                  };
                    let sig = privkey.sign(sighash, &mbytes);
                    assert_eq!(sig, *sbytes);
                });
            }

            #[test]
            fn decrypt() {
                let fname = format!("tests/rsa/rsa{}.test", $size);
                run_test(fname.to_string(), 8, |case| {
                    let (neg0, dbytes) = case.get("d").unwrap();
                    let (neg1, nbytes) = case.get("n").unwrap();
                    let (neg2, hbytes) = case.get("h").unwrap();
                    let (neg3, mbytes) = case.get("m").unwrap();
                    let (neg4, cbytes) = case.get("c").unwrap();
                    let (neg5, ubytes) = case.get("u").unwrap();
                    let (neg6, kbytes) = case.get("k").unwrap();

                    assert!(!neg0&&!neg1&&!neg2&&!neg3&&!neg4&&!neg5&&!neg6);
                    let n = $num64::from_bytes(nbytes);
                    let nu = $num64::from_bytes(ubytes);
                    let bigk = $num::from_bytes(kbytes);
                    let k = usize::from(bigk);
                    let d = $num::from_bytes(dbytes);
                    let privkey = $rsa{ nu: $bar::from_components(k, n, nu), d: d };
                    let hashnum = ((hbytes[0] as u16)<<8) + (hbytes[1] as u16);
                    let empty = "".to_string();
                    match hashnum {
                        0x160 => {
                            let oaep = OAEPParams::<Sha1>::new(empty);
                            let plain = privkey.decrypt(&oaep, &cbytes);
                            assert!(plain.is_ok());
                            assert_eq!(*mbytes, plain.unwrap());
                        }
                        0x224 =>{
                            let oaep = OAEPParams::<Sha224>::new(empty);
                            let plain = privkey.decrypt(&oaep, &cbytes);
                            assert!(plain.is_ok());
                            assert_eq!(*mbytes, plain.unwrap());
                        }
                        0x256 => {
                            let oaep = OAEPParams::<Sha256>::new(empty);
                            let plain = privkey.decrypt(&oaep, &cbytes);
                            assert!(plain.is_ok());
                            assert_eq!(*mbytes, plain.unwrap());
                        }
                        0x384 => {
                            let oaep = OAEPParams::<Sha384>::new(empty);
                            let plain = privkey.decrypt(&oaep, &cbytes);
                            assert!(plain.is_ok());
                            assert_eq!(*mbytes, plain.unwrap());
                        }
                        0x512 => {
                            let oaep = OAEPParams::<Sha512>::new(empty);
                            let plain = privkey.decrypt(&oaep, &cbytes);
                            assert!(plain.is_ok());
                            assert_eq!(*mbytes, plain.unwrap());
                        }
                        _     => panic!("Bad signing hash: {}", hashnum)
                    };
                });
            }
        }
        )*
    }
}

generate_tests!( (RSA512,   RSA512Private,   U512,   BarrettU512,   U576,   512),
                 (RSA1024,  RSA1024Private,  U1024,  BarrettU1024,  U1088,  1024),
                 (RSA2048,  RSA2048Private,  U2048,  BarrettU2048,  U2112,  2048),
                 (RSA3072,  RSA3072Private,  U3072,  BarrettU3072,  U3136,  3072),
                 (RSA4096,  RSA4096Private,  U4096,  BarrettU4096,  U4160,  4096),
                 (RSA8192,  RSA8192Private,  U8192,  BarrettU8192,  U8256,  8192),
                 (RSA15360, RSA15360Private, U15360, BarrettU15360, U15424, 15360)
               );