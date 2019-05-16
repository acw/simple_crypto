mod constants;
mod fe;
mod point;

use digest::Digest;
use rand::Rng;
use sha2::Sha512;
use self::fe::*;
use self::point::*;
#[cfg(test)]
use testing::run_test;
#[cfg(test)]
use std::collections::HashMap;
use super::KeyPair;

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
    pub fn generate<G: Rng>(rng: &mut G) -> ED25519KeyPair
    {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let private = ED25519Private::from_seed(&seed);
        let public = ED25519Public::from(&private);
        ED25519KeyPair::new(public, private)
    }

    pub fn from_seed(seed: &[u8]) -> ED25519KeyPair
    {
        let private = ED25519Private::from_seed(seed);
        let public = ED25519Public::from(&private);
        ED25519KeyPair{ public, private }
    }
}

pub struct ED25519Private
{
    seed:    [u8; 32],
    private: [u8; 32],
    prefix:  [u8; 32],
    public:  [u8; 32]
}

impl ED25519Private {
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
        let mut a = Point::new();
        x25519_ge_scalarmult_base(&mut a, &result.private);
        into_encoded_point(&mut result.public, &a.x, &a.y, &a.z);
        result
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8>
    {
        let mut signature_r = [0u8; 32];
        let mut signature_s = [0u8; 32];

        let mut ctx = Sha512::new();
        ctx.input(&self.prefix);
        ctx.input(&msg);
        let nonce = digest_scalar(ctx.result().as_slice());
        println!("ME:nonce: {:?}", nonce);
        let mut r = Point::new();
        x25519_ge_scalarmult_base(&mut r, &nonce);
        println!("ME:r.x: {:?}", r.x);
        println!("ME:r.y: {:?}", r.y);
        println!("ME:r.z: {:?}", r.z);
        println!("ME:r.t: {:?}", r.t);
        into_encoded_point(&mut signature_r, &r.x, &r.y, &r.z);
        println!("ME:signature_r: {:?}", signature_r);
        let hram_digest = eddsa_digest(&signature_r, &self.public, &msg);
        let hram = digest_scalar(&hram_digest);
        println!("ME:hram: {:?}", hram);
        x25519_sc_muladd(&mut signature_s, &hram, &self.private, &nonce);
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&signature_r);
        result.extend_from_slice(&signature_s);
        result
    }
}

pub struct ED25519Public
{
    public:  [u8; 32]
}

impl<'a> From<&'a ED25519Private> for ED25519Public
{
    fn from(x: &ED25519Private) -> ED25519Public
    {
        ED25519Public{ public: x.public.clone() }
    }
}

impl ED25519Public {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool
    {
        assert_eq!(sig.len(), 64);

        let signature_r = &sig[..32];
        let signature_s = &sig[32..];

        if signature_s[31] & 0b11100000 != 0 {
            return false;
        }

        let mut a = from_encoded_point(&self.public);
        invert_vartime(&mut a);
        let h_digest = eddsa_digest(signature_r, &self.public, msg);
        let h = digest_scalar(&h_digest);
        let mut r = Point2::new();
        ge_double_scalarmult_vartime(&mut r, &h, &a, &signature_s);
        let mut r_check = [0; 32];
        into_encoded_point(&mut r_check, &r.x, &r.y, &r.z);
        signature_r == r_check
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

fn into_encoded_point(bytes: &mut [u8], x: &Element, y: &Element, z: &Element)
{
    let mut x_over_z = [0; NUM_ELEMENT_LIMBS];
    let mut y_over_z = [0; NUM_ELEMENT_LIMBS];
    assert_eq!(bytes.len(), 32);

    let recip = fe_invert(z);
    fe_mul(&mut x_over_z, x, &recip);
    fe_mul(&mut y_over_z, y, &recip);
    fe_tobytes(bytes, &y_over_z);
    let sign_bit = if fe_isnegative(&x_over_z) { 1 } else { 0 };

    // The preceding computations must execute in constant time, but this
    // doesn't need to.
    bytes[31] ^= sign_bit << 7;
}

fn from_encoded_point(encoded: &[u8]) -> Point
{
    let mut point = Point::new();
    x25519_ge_frombytes_vartime(&mut point, encoded);
    point
}

fn invert_vartime(v: &mut Point)
{
    for i in 0..NUM_ELEMENT_LIMBS {
        v.x[i] = -v.x[i];
        v.t[i] = -v.t[i];
    }
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
    assert_eq!(ubytes, &keypair.public.public.to_vec());
    let mut privpub = Vec::new();
    privpub.append(&mut rbytes.clone());
    privpub.append(&mut ubytes.clone());
    let sig = keypair.private.sign(&mbytes);
    assert_eq!(sig.len(), sbytes.len());
    println!("sig:  {:?}", sbytes);
    println!("sig': {:?}", sig);
    assert!(sig.iter().eq(sbytes.iter()));
    assert!(keypair.public.verify(&mbytes, &sig));
    println!("DONE");
}

#[cfg(test)]
#[test]
fn rfc8072() {
    let fname = "testdata/ed25519/rfc8032.test";
    run_test(fname.to_string(), 4, run_signing_testcase);
}

//#[cfg(test)]
//#[test]
//fn signing() {
//    let fname = "testdata/ed25519/sign.test";
//    run_test(fname.to_string(), 4, run_signing_testcase);
//}