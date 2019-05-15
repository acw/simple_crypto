mod constants;
mod fe;
mod point;

use digest::Digest;
use rand::Rng;
use sha2::Sha512;
use self::fe::*;
use self::point::*;

pub struct ED25519KeyPair {
    private: [u8; 32],
    prefix:  [u8; 32],
    public:  [u8; 32]
}

impl ED25519KeyPair {
    fn blank() -> ED25519KeyPair
    {
        ED25519KeyPair {
            private: [0; 32],
            prefix:  [0; 32],
            public:  [0; 32]
        }
    }

    pub fn generate<G: Rng>(rng: &mut G) -> ED25519KeyPair
    {
        let mut result = ED25519KeyPair::blank();

        let mut seed: [u8; 32] = [0; 32];
        rng.fill(&mut seed);
        let mut hashed = Sha512::digest(&seed);
        let (private, prefix) = hashed.split_at_mut(32);
        assert_eq!(private.len(), 32);
        assert_eq!(prefix.len(), 32);
        result.prefix.copy_from_slice(&prefix);
        curve25519_scalar_mask(private);
        result.private.copy_from_slice(&private);
        x25519_public_from_private(&mut result.public, &private);
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
        let mut r = Point::new();
        x25519_ge_scalarmult_base(&mut r, &nonce);
        into_encoded_point(&mut signature_r, &r.x, &r.y, &r.z);
        let hram_digest = eddsa_digest(&signature_r, &self.public, &msg);
        let hram = digest_scalar(&hram_digest);
        x25519_sc_muladd(&mut signature_s, &hram, &self.private, &nonce);
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&signature_r);
        result.extend_from_slice(&signature_s);
        result
    }

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

// use cryptonum::signed::{I256};
// use cryptonum::unsigned::{BarrettU256,CryptoNum,Decoder,ModExp,U256,U512};
// use digest::Digest;
// use rand::Rng;
// use rand::distributions::Standard;
// use sha2::Sha512;
// use super::KeyPair;
// 
// struct Field {
//     x: U256,
//     p: U256,
//     pu: BarrettU256
// }
// 
// impl Field {
//     fn unsafe_new(&self, v: U256) -> Field
//     {
//         Field{ x: v, p: self.p.clone(), pu: self.pu.clone() }
//     }
// 
//     fn new(&self, v: U256) -> Field
//     {
//         let v2 = self.pu.reduce(&U512::from(v));
//         Field{ x: v2, p: self.p.clone(), pu: self.pu.clone() }
//     }
// 
//     fn init(x: U256, p: U256) -> Field
//     {
//         let pu = BarrettU256::new(p.clone());
//         Field{ x, p, pu }
//     }
// 
//     fn add(&self, y: &Field) -> Field
//     {
//         assert_eq!(self.p, y.p);
//         assert_eq!(self.pu, y.pu);
//         let v = U512::from(&self.x + &y.x);
//         Field { x: self.pu.reduce(&v), p: self.p.clone(), pu: self.pu.clone() }
//     }
// 
//     fn sub(&self, y: &Field) -> Field
//     {
//         assert_eq!(self.p, y.p);
//         assert_eq!(self.pu, y.pu);
//         let mut ix = I256::from(&self.x);
//         let iy = I256::from(&y.x);
//         ix -= iy;
//         if ix.is_negative() {
//             let mut rx = I256::from(&self.p);
//             rx += ix;
//             self.new(U256::from(rx))
//         } else {
//             self.new(U256::from(ix))
//         }
//     }
// 
//     fn neg(&self) -> Field
//     {
//         let mut rx = self.p.clone();
//         rx -= &self.x;
//         self.new(rx)
//     }
// 
//     fn mul(&self, y: &Field) -> Field
//     {
//         let v = &self.x * &y.x;
//         self.unsafe_new(self.pu.reduce(&v))
//     }
// 
//     fn inv(&self) -> Field
//     {
//         let mut pm2 = self.p.clone();
//         pm2 -= U256::from(2u8);
//         let res = self.x.modexp(&pm2, &self.pu);
//         self.unsafe_new(res)
//     }
// 
//     fn div(&self, y: &Field) -> Field
//     {
//         self.mul(&y.inv())
//     }
// 
//     fn sqrt(&self) -> Field
//     {
//         panic!("field sqrt")
//     }
// 
//     fn is_zero(&self) -> bool
//     {
//         self.x.is_zero()
//     }
// 
//     fn eq(&self, y: &Field) -> bool
//     {
//         self.x == y.x
//     }
// 
//     fn neq(&self, y: &Field) -> bool
//     {
//         self.x != y.x
//     }
// 
//     fn sign(&self) -> Field
//     {
//         let mut vx = I256::from(&self.x);
//         vx %= I256::from(2u64);
//         self.unsafe_new(U256::from(vx))
//     }
// }
// 
// pub struct ED25519Public {
// }
// 
// pub struct ED25519Private {
//     key: U256
// }
// 
// pub struct ED25519Pair {
//     public: ED25519Public,
//     private: ED25519Private
// }
// 
// impl KeyPair for ED25519Pair {
//     type Public = ED25519Public;
//     type Private = ED25519Private;
// 
//     fn new(pu: ED25519Public, pr: ED25519Private) -> ED25519Pair
//     {
//         ED25519Pair{ public: pu, private: pr }
//     }
// }
// 
// impl ED25519Pair {
//     pub fn generate<G: Rng>(g: &mut G) -> ED25519Pair
//     {
//         let bytes: Vec<u8> = g.sample_iter(&Standard).take(256 / 8).collect();
//         let key = U256::from_bytes(&bytes);
//         let private = ED25519Private{ key };
//         let mut hash = Sha512::digest(&bytes);
//         assert_eq!(hash.len(), 64);
//         let (scalar, prefix) = hash.split_at_mut(32);
//         assert_eq!(scalar.len(), 32);
//         assert_eq!(prefix.len(), 32);
//         //
//         scalar[0]  &= 0b11111000u8;
//         scalar[31] &= 0b01111111u8;
//         scalar[31] |= 0b01000000u8;
//         //
//         
//         let public = ED25519Public{};
//         ED25519Pair{ public, private }
//     }
// }