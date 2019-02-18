use cryptonum::unsigned::{CryptoNum,Decoder,Encoder};
use digest::{BlockInput,Digest,FixedOutput,Input,Reset};
use digest::generic_array::ArrayLength;
use hmac::{Hmac,Mac};
use num::BigInt;
use simple_asn1::{ASN1Block,ASN1Class,ASN1DecodeErr,ASN1EncodeErr};
use simple_asn1::{FromASN1,ToASN1};
use utils::TranslateNums;
use std::ops::{Shr,Sub};

#[derive(Debug,PartialEq)]
pub struct DSASignature<N>
{
    pub r: N,
    pub s: N
}

impl<N> DSASignature<N>
{
    pub fn new(r: N, s: N) -> DSASignature<N>
    {
        DSASignature{ r, s }
    }
}

#[allow(non_snake_case)]
pub struct KIterator<H,N>
 where
  H: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
  N: Clone + Decoder + Encoder + PartialOrd + Shr<usize,Output=N>,
  Hmac<H>: Mac
{
    hmac_k: Hmac<H>,
    V: Vec<u8>,
    q: N,
    qlen: usize
}

impl<H,N> KIterator<H,N>
 where
  H: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
  N: Clone + Decoder + Encoder + PartialOrd + Shr<usize,Output=N> + Sub<Output=N>,
  Hmac<H>: Mac
{
    pub fn new(h1: &[u8], qlen: usize, q: &N, x: &N) -> KIterator<H,N>
    {
        // Given the input message m, the following process is applied:
        //
        // a.  Process m through the hash function H, yielding:
        //
        //           h1 = H(m)
        //
        //     (h1 is a sequence of hlen bits).
        //
        let hlen = h1.len();
        // b.  Set:
        //
        //           V = 0x01 0x01 0x01 ... 0x01
        //
        //     such that the length of V, in bits, is equal to 8*ceil(hlen/8).
        //     For instance, on an octet-based system, if H is SHA-256, then
        //     V is set to a sequence of 32 octets of value 1.  Note that in
        //     this step and all subsequent steps, we use the same H function
        //     as the one used in step 'a' to process the input message; this
        //     choice will be discussed in more detail in Section 3.6.
        //
        #[allow(non_snake_case)]
        let mut V = Vec::new();
        V.resize(hlen, 0x01);
        // c.  Set:
        //
        //           K = 0x00 0x00 0x00 ... 0x00
        //
        //     such that the length of K, in bits, is equal to 8*ceil(hlen/8).
        #[allow(non_snake_case)]
        let mut K = Vec::new();
        K.resize(hlen, 0x00);
        // d.  Set:
        //
        //           K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        //
        //     where '||' denotes concatenation.  In other words, we compute
        //     HMAC with key K, over the concatenation of the following, in
        //     order: the current value of V, a sequence of eight bits of value
        //     0, the encoding of the (EC)DSA private key x, and the hashed
        //     message (possibly truncated and extended as specified by the
        //     bits2octets transform).  The HMAC result is the new value of K.
        //     Note that the private key x is in the [1, q-1] range, hence a
        //     proper input for int2octets, yielding rlen bits of output, i.e.,
        //     an integral number of octets (rlen is a multiple of 8).
        let xbytes = int2octets(x, qlen);
        let h1bytes = bits2octets(h1, q, qlen);
        let mut input = Vec::new();
        input.extend_from_slice(&V);
        input.push(0x00);
        input.extend_from_slice(&xbytes);
        input.extend_from_slice(&h1bytes);
        K = hmac(&K, &input);
        // e.  Set:
        //
        //           V = HMAC_K(V)
        V = hmac(&K, &V);
        // f. Set:
        //
        //           K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
        //
        //                  Note that the "internal octet" is 0x01 this time.
        input = Vec::new();
        input.extend_from_slice(&V);
        input.push(0x01);
        input.extend_from_slice(&xbytes);
        input.extend_from_slice(&h1bytes);
        K = hmac(&K, &input);
        // g. Set:
        //
        //          V = HMAC_K(V)
        V = hmac(&K, &V);
        // h is for later ...
        KIterator {
            hmac_k: Hmac::<H>::new_varkey(&K).unwrap(),
            V: V,
            q: q.clone(),
            qlen: qlen
        }
    }
}

impl<H,N> Iterator for KIterator<H,N>
 where
  H: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
  N: Clone + CryptoNum + Decoder + Encoder + PartialOrd + Shr<usize,Output=N>,
  Hmac<H>: Mac
{
    type Item = N;

    fn next(&mut self) -> Option<N>
    {
        loop {
           // h.  Apply the following algorithm until a proper value is found
           //     for k:
           //
           //     1.  Set T to the empty sequence.  The length of T (in bits) is
           //         denoted tlen; thus, at that point, tlen = 0.
           let mut t = Vec::new();
           //
           //     2.  While tlen < qlen, do the following:
           //
           //               V = HMAC_K(V)
           //               T = T || V
           let target = (self.qlen + 7) / 8;
           while t.len() < target {
               self.V = runhmac(&self.hmac_k, &self.V);
               t.extend_from_slice(&self.V);
           }
           //
           //      3.  Compute:
           //
           //               k = bits2int(T)
           let resk: N = bits2int(&t, self.qlen);
           //
           //          If that value of k is within the [1,q-1] range, and is
           //          suitable for DSA or ECDSA (i.e., it results in an r value
           //          that is not 0; see Section 3.4), then the generation of k
           //          is finished.  The obtained value of k is used in DSA or
           //          ECDSA.  Otherwise, compute:
           //
           //               K = HMAC_K(V || 0x00)
           let mut input = self.V.clone();
           input.push(0x00);
           #[allow(non_snake_case)]
           let K = runhmac(&self.hmac_k, &input);
           //               V = HMAC_K(V)
           self.hmac_k = Hmac::<H>::new_varkey(&K).unwrap();
           self.V = runhmac(&self.hmac_k, &self.V);
           //
           //          and loop (try to generate a new T, and so on).
           //
           if !resk.is_zero() && (resk < self.q) {
               return Some(resk);
           }
        }
    }
}

pub fn bits2int<X>(x: &[u8], qlen: usize) -> X
 where
  X: Decoder + Shr<usize,Output=X>
{

    if qlen < (x.len() * 8) {
        let mut fixed_x = Vec::from(x);
        let qlen_bytes = (qlen + 7) / 8;
        let rounded_qlen = qlen_bytes * 8;
        fixed_x.resize(qlen_bytes, 0);
        X::from_bytes(&fixed_x) >> (rounded_qlen - qlen)
    } else {
        X::from_bytes(x)
    }
}

fn bits2octets<X>(x: &[u8], q: &X, qlen: usize) -> Vec<u8>
 where
  X: Clone + Decoder + Encoder + PartialOrd + Sub<Output=X> + Shr<usize,Output=X>
{
    let z1: X = bits2int(x, qlen);
    let res = if &z1 > q { z1 - q.clone() } else { z1 };
    int2octets(&res, qlen)
}

fn int2octets<X>(x: &X, qlen_bits: usize) -> Vec<u8>
 where X: Encoder
{
    let qlen_bytes = (qlen_bits + 7) / 8;
    let mut base = x.to_bytes();

    while base.len() < qlen_bytes {
        base.insert(0,0);
    }

    while base.len() > qlen_bytes {
        base.remove(0);
    }

    base
}

fn runhmac<H>(base: &Hmac<H>, m: &[u8]) -> Vec<u8>
  where
    H: Clone + BlockInput + Default + Input + FixedOutput + Reset,
    Hmac<H>: Clone + Mac,
    H::BlockSize : ArrayLength<u8>
{
    let mut runner = base.clone();
    runner.input(&m);
    runner.result().code().as_slice().to_vec()
}

fn hmac<H>(k: &[u8], m: &[u8]) -> Vec<u8>
  where
    H: BlockInput + Clone + Default + Input + FixedOutput + Reset,
    Hmac<H>: Clone + Mac,
    H::BlockSize : ArrayLength<u8>
{
    let mut runner = Hmac::<H>::new_varkey(&k).unwrap();
    runner.input(&m);
    runner.result().code().as_slice().to_vec()
}

#[derive(Clone,Debug,PartialEq)]
pub enum DSADecodeError {
    ASN1Error(ASN1DecodeErr),
    NoSignatureFound,
    InvalidRValue,
    InvalidSValue
}

impl From<ASN1DecodeErr> for DSADecodeError {
    fn from(a: ASN1DecodeErr) -> DSADecodeError {
        DSADecodeError::ASN1Error(a)
    }
}

impl<N> FromASN1 for DSASignature<N>
 where N: TranslateNums<BigInt>
{
    type Error = DSADecodeError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(DSASignature<N>,&[ASN1Block]),DSADecodeError>
    {
        match v.split_first() {
            Some((&ASN1Block::Sequence(_,_,ref info), rest))
                if info.len() == 2 =>
            {
                match (&info[0], &info[1]) {
                    (&ASN1Block::Integer(_,_,ref rint),
                     &ASN1Block::Integer(_,_,ref sint)) => {
                         let r = N::from_num(rint).ok_or(DSADecodeError::InvalidRValue)?;
                         let s = N::from_num(sint).ok_or(DSADecodeError::InvalidSValue)?;
                         Ok((DSASignature{ r, s }, rest))
                    }
                    _ => Err(DSADecodeError::NoSignatureFound)
                }
            }
            _ => Err(DSADecodeError::NoSignatureFound)
        }
    }
}

impl<N> ToASN1 for DSASignature<N>
 where N: TranslateNums<BigInt>
{
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let rb = ASN1Block::Integer(c, 0, self.r.to_num());
        let sb = ASN1Block::Integer(c, 0, self.s.to_num());
        Ok(vec![ASN1Block::Sequence(c, 0, vec![rb,sb])])
    }
}

#[cfg(test)]
mod tests {
    use cryptonum::unsigned::U192;
    use sha2::{Sha224,Sha256,Sha384,Sha512};
    use super::*;
    use testing::*;

    const QBYTES: [u8; 21] = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x02, 0x01, 0x08, 0xA2, 0xE0, 0xCC,
                              0x0D, 0x99, 0xF8, 0xA5, 0xEF];
    const XBYTES: [u8; 21] = [0x00, 0x9A, 0x4D, 0x67, 0x92, 0x29, 0x5A, 0x7F,
                              0x73, 0x0F, 0xC3, 0xF2, 0xB4, 0x9C, 0xBC, 0x0F,
                              0x62, 0xE8, 0x62, 0x27, 0x2F];
    const H1: [u8; 32]     = [0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
                              0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
                              0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
                              0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF];

    #[test]
    fn int2octets_example() {
        let x = U192::from_bytes(&XBYTES);
        let octets = int2octets(&x, 163);
        let target = vec![0x00, 0x9A, 0x4D, 0x67, 0x92, 0x29, 0x5A, 0x7F,
                          0x73, 0x0F, 0xC3, 0xF2, 0xB4, 0x9C, 0xBC, 0x0F,
                          0x62, 0xE8, 0x62, 0x27, 0x2F];
        assert_eq!(octets, target);
    }

    #[test]
    fn bits2octets_example() {
        let q = U192::from_bytes(&QBYTES);
        let octets = bits2octets(&H1, &q, 163);
        let target = vec![0x01, 0x79, 0x5E, 0xDF, 0x0D, 0x54, 0xDB, 0x76,
                          0x0F, 0x15, 0x6D, 0x0D, 0xAC, 0x04, 0xC0, 0x32,
                          0x2B, 0x3A, 0x20, 0x42, 0x24];
        assert_eq!(octets, target);
    }

    #[test]
    fn k_gen_example() {
        let q = U192::from_bytes(&QBYTES);
        let x = U192::from_bytes(&XBYTES);
        let mut iter = KIterator::<Sha256,U192>::new(&H1, 163, &q, &x);
        match iter.next() {
            None =>
                assert!(false),
            Some(x) => {
                let target = vec![0x02, 0x3A, 0xF4, 0x07, 0x4C, 0x90, 0xA0,
                                  0x2B, 0x3F, 0xE6, 0x1D, 0x28, 0x6D, 0x5C,
                                  0x87, 0xF4, 0x25, 0xE6, 0xBD, 0xD8, 0x1B];
                let x2 = U192::from_bytes(&target);
                assert_eq!(x, x2);
            }
        }
    }

    use cryptonum::unsigned::*;

    macro_rules! k_generator_tests {
        ($testname: ident, $hash: ident, $fname: expr) => {
            #[test]
            fn $testname() {
                let fname = build_test_path("rfc6979", $fname);
                run_test(fname.to_string(), 7, |case| {
                    let (negq, qbytes) = case.get("q").unwrap();
                    let (negl, lbytes) = case.get("l").unwrap();
                    let (negx, xbytes) = case.get("x").unwrap();
                    let (negh, h1)     = case.get("h").unwrap();
                    let (negk, kbytes) = case.get("k").unwrap();
                    let (negy, ybytes) = case.get("y").unwrap();
                    let (negz, zbytes) = case.get("z").unwrap();

                    assert!(!negq && !negl && !negx && !negh &&
                            !negk && !negy && !negz);
                    let qlen = usize::from(U192::from_bytes(lbytes));
                    assert!(qlen >= 160); assert!(qlen <= 521);

                    if qlen < 192 {
                        let q = U192::from_bytes(qbytes);
                        let x = U192::from_bytes(xbytes);
                        let k = U192::from_bytes(kbytes);
                        let y = U192::from_bytes(ybytes);
                        let z = U192::from_bytes(zbytes);

                        let mut kiter = KIterator::<$hash,U192>::new(h1,qlen,&q,&x);
                        assert_eq!(Some(k), kiter.next(), "first value test");
                        assert_eq!(Some(y), kiter.next(), "second value test");
                        assert_eq!(Some(z), kiter.next(), "third value test");
                    } else if qlen < 256 {
                        let q = U256::from_bytes(qbytes);
                        let x = U256::from_bytes(xbytes);
                        let k = U256::from_bytes(kbytes);
                        let y = U256::from_bytes(ybytes);
                        let z = U256::from_bytes(zbytes);

                        let mut kiter = KIterator::<$hash,U256>::new(h1,qlen,&q,&x);
                        assert_eq!(Some(k), kiter.next(), "first value test");
                        assert_eq!(Some(y), kiter.next(), "second value test");
                        assert_eq!(Some(z), kiter.next(), "third value test");
                    } else if qlen < 512 {
                        let q = U512::from_bytes(qbytes);
                        let x = U512::from_bytes(xbytes);
                        let k = U512::from_bytes(kbytes);
                        let y = U512::from_bytes(ybytes);
                        let z = U512::from_bytes(zbytes);

                        let mut kiter = KIterator::<$hash,U512>::new(h1,qlen,&q,&x);
                        assert_eq!(Some(k), kiter.next(), "first value test");
                        assert_eq!(Some(y), kiter.next(), "second value test");
                        assert_eq!(Some(z), kiter.next(), "third value test");
                    } else {
                        let q = U576::from_bytes(qbytes);
                        let x = U576::from_bytes(xbytes);
                        let k = U576::from_bytes(kbytes);
                        let y = U576::from_bytes(ybytes);
                        let z = U576::from_bytes(zbytes);

                        let mut kiter = KIterator::<$hash,U576>::new(h1,qlen,&q,&x);
                        assert_eq!(Some(k), kiter.next(), "first value test");
                        assert_eq!(Some(y), kiter.next(), "second value test");
                        assert_eq!(Some(z), kiter.next(), "third value test");
                    }
                });
            } 
        };
    }

    k_generator_tests!(kgen_sha224, Sha224, "SHA224");
    k_generator_tests!(kgen_sha256, Sha256, "SHA256");
    k_generator_tests!(kgen_sha384, Sha384, "SHA384");
    k_generator_tests!(kgen_sha512, Sha512, "SHA512");

}