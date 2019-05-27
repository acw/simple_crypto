mod constants;
mod fe;
mod loads;
mod point;
mod scalars;

use digest::Digest;
use rand::Rng;
use sha2::Sha512;
use self::scalars::{curve25519_scalar_mask,x25519_sc_muladd,x25519_sc_reduce};
use self::point::{Point,Point2};
#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use std::collections::HashMap;
use super::KeyPair;

/// An ED25519 key pair
pub struct ED25519KeyPair
{
    pub public: ED25519Public,
    pub private: ED25519Private
}

impl KeyPair for ED25519KeyPair
{
    type Public = ED25519Public;
    type Private = ED25519Private;

    fn new(pbl: ED25519Public, prv: ED25519Private) -> ED25519KeyPair
    {
        ED25519KeyPair {
            public: pbl,
            private: prv
        }
    }
}

impl ED25519KeyPair
{
    /// Generate a random ED25519 key pair, using the given random number
    /// generator. You really need to use a good, cryptographically-strong
    /// RNG if you want good keys.
    pub fn generate<G: Rng>(rng: &mut G) -> ED25519KeyPair
    {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let private = ED25519Private::from_seed(&seed);
        let public = ED25519Public::from(&private);
        ED25519KeyPair::new(public, private)
    }

    /// Generate the ED25519 key pair defined by the given seed value.
    /// This should be a block of 32 bytes.
    pub fn from_seed(seed: &[u8]) -> ED25519KeyPair
    {
        let private = ED25519Private::from_seed(seed);
        let public = ED25519Public::from(&private);
        ED25519KeyPair{ public, private }
    }
}

/// An ED25519 private key.
#[derive(Debug,PartialEq)]
pub struct ED25519Private
{
    seed:    [u8; 32],
    private: [u8; 32],
    prefix:  [u8; 32],
    public:  [u8; 32]
}

impl ED25519Private {
    /// Generate the ED25519 private key defined by the given 32 byte seed
    /// value.
    pub fn from_seed(seed: &[u8]) -> ED25519Private {
        let mut result = ED25519Private {
            seed: [0; 32],
            private: [0; 32],
            prefix: [0; 32],
            public: [0; 32]
        };
        result.seed.copy_from_slice(seed);
        let mut expanded = Sha512::digest(seed);
        let (private, prefix) = expanded.split_at_mut(32);
        result.private.copy_from_slice(private);
        result.prefix.copy_from_slice(prefix);
        curve25519_scalar_mask(&mut result.private);
        let a = Point::scalarmult_base(&result.private);
        result.public.copy_from_slice(&a.encode());
        result
    }

    /// Sign the given message, returning the signature. Unlike most other
    /// public/private schemes, you don't get a choice on the hash used to
    /// compute this signature. (On the bright side, it's SHA2-512.)
    pub fn sign(&self, msg: &[u8]) -> Vec<u8>
    {
        let mut signature_s = [0u8; 32];

        let mut ctx = Sha512::new();
        ctx.input(&self.prefix);
        ctx.input(&msg);
        let nonce = digest_scalar(ctx.result().as_slice());
        let r = Point::scalarmult_base(&nonce);
        let signature_r = r.encode();
        let hram_digest = eddsa_digest(&signature_r, &self.public, &msg);
        let hram = digest_scalar(&hram_digest);
        x25519_sc_muladd(&mut signature_s, &hram, &self.private, &nonce);
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&signature_r);
        result.extend_from_slice(&signature_s);
        result
    }

    /// Covert the given private key into its byte representation. This is
    /// guaranteed to be exactly 32 bytes.
    pub fn to_bytes(&self) -> Vec<u8>
    {
        self.seed.to_vec()
    }
}

/// An ED25519 Public key
#[derive(Debug,PartialEq)]
pub struct ED25519Public
{
    bytes: [u8; 32],
    point: Point
}

impl<'a> From<&'a ED25519Private> for ED25519Public
{
    fn from(x: &ED25519Private) -> ED25519Public
    {
        ED25519Public::new(&x.public).expect("Broke converting private ED25519 to public. (?!)")
    }
}

/// The kinds of errors you can get when you try to generate a public key from,
/// for example, an unknown block of bytes.
#[derive(Debug)]
pub enum ED25519PublicImportError
{
    WrongNumberOfBytes(usize),
    InvalidPublicPoint
}

impl ED25519Public {
    /// Generate an ED25519 public key given the provided (32 byte) bytes. This
    /// can return errors if the value isn't a reasonable representation of an
    /// ED25519 point.
    pub fn new(bytes: &[u8]) -> Result<ED25519Public,ED25519PublicImportError>
    {
        if bytes.len() != 32 {
            return Err(ED25519PublicImportError::WrongNumberOfBytes(bytes.len()));
        }
        match Point::from_bytes(&bytes) {
            None =>
                Err(ED25519PublicImportError::InvalidPublicPoint),
            Some(a) => {
                let mut res = ED25519Public{ bytes: [0; 32], point: a };
                res.bytes.copy_from_slice(&bytes);
                Ok(res)
            }
        }
    }

    /// Verify that the given signature matches the given message.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool
    {
        assert_eq!(sig.len(), 64);

        let signature_r = &sig[..32];
        let signature_s = &sig[32..];

        if signature_s[31] & 0b11100000 != 0 {
            return false;
        }

        let ainv = self.point.invert();
        let h_digest = eddsa_digest(signature_r, &self.bytes, msg);
        let h = digest_scalar(&h_digest);
        let r = Point2::double_scalarmult_vartime(&h, &ainv, &signature_s);
        let r_check = r.encode();
        signature_r.to_vec() == r_check
    }

    /// Turn the ED25519 into its byte representation. This will always be a
    /// 32 byte block.
    pub fn to_bytes(&self) -> Vec<u8>
    {
        self.bytes.to_vec()
    }
}

fn eddsa_digest(signature_r: &[u8], public_key: &[u8], msg: &[u8]) -> Vec<u8>
{
    let mut ctx = Sha512::new();
    ctx.input(signature_r);
    ctx.input(public_key);
    ctx.input(msg);
    ctx.result().as_slice().to_vec()
}

fn digest_scalar(digest: &[u8]) -> Vec<u8> {
    assert_eq!(digest.len(), 512/8);
    let mut copy = [0; 512/8];
    copy.copy_from_slice(digest);
    x25519_sc_reduce(&mut copy);
    copy[..32].to_vec()
}

#[cfg(test)]
fn run_signing_testcase(case: HashMap<String,(bool,Vec<u8>)>)
{
    let (negr, rbytes) = case.get("r").unwrap();
    let (negu, ubytes) = case.get("u").unwrap();
    let (negm, mbytes) = case.get("m").unwrap();
    let (negs, sbytes) = case.get("s").unwrap();

    assert!(!negr && !negu && !negm && !negs);
    let keypair = ED25519KeyPair::from_seed(rbytes);
    assert_eq!(ubytes, &keypair.public.bytes.to_vec());
    let mut privpub = Vec::new();
    privpub.append(&mut rbytes.clone());
    privpub.append(&mut ubytes.clone());
    let sig = keypair.private.sign(&mbytes);
    assert_eq!(sig.len(), sbytes.len());
    assert!(sig.iter().eq(sbytes.iter()));
    assert!(keypair.public.verify(&mbytes, &sig));
}

#[cfg(test)]
#[test]
fn rfc8072() {
    let fname = "testdata/ed25519/rfc8032.test";
    run_test(fname.to_string(), 4, run_signing_testcase);
}

#[cfg(test)]
#[test]
fn signing() {
    let fname = "testdata/ed25519/sign.test";
    run_test(fname.to_string(), 4, run_signing_testcase);
}
