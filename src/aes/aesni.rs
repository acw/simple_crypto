#[cfg(target_arch="x86")]
use std::arch::x86::*;
#[cfg(target_arch="x86_64")]
use std::arch::x86_64::*;
#[cfg(test)]
use std::mem::transmute;
use std::mem::uninitialized;

////////////////////////////////////////////////////////////////////////////////////////////////////
//
// 128-Bit Support
//
////////////////////////////////////////////////////////////////////////////////////////////////////

struct AES128 {
    expanded_enc: [__m128i; 11],
    expanded_dec: [__m128i; 11],
}

macro_rules! expand128 {
    ($v: expr, $r: expr) => {{
        let gen0 = _mm_aeskeygenassist_si128($v, $r);
        let gen1 = _mm_shuffle_epi32(gen0, 0xff);
        let key0 = $v;
        let key1 = _mm_xor_si128(key0, _mm_slli_si128(key0, 4));
        let key2 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        let key3 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        _mm_xor_si128(gen1, key3)
    }};
}

impl AES128 {
    pub fn new(base_key: &[u8]) -> AES128 {
        assert_eq!(base_key.len(), 16);
        unsafe {
            let mut expanded_enc: [__m128i; 11] = uninitialized();
            let mut expanded_dec: [__m128i; 11] = uninitialized();

            let initial_m128 = _mm_loadu_si128(base_key.as_ptr() as *const __m128i);
            _mm_store_si128(expanded_enc.as_mut_ptr(), initial_m128);

            expanded_enc[1]  = expand128!(expanded_enc[0], 0x01);
            expanded_enc[2]  = expand128!(expanded_enc[1], 0x02);
            expanded_enc[3]  = expand128!(expanded_enc[2], 0x04);
            expanded_enc[4]  = expand128!(expanded_enc[3], 0x08);
            expanded_enc[5]  = expand128!(expanded_enc[4], 0x10);
            expanded_enc[6]  = expand128!(expanded_enc[5], 0x20);
            expanded_enc[7]  = expand128!(expanded_enc[6], 0x40);
            expanded_enc[8]  = expand128!(expanded_enc[7], 0x80);
            expanded_enc[9]  = expand128!(expanded_enc[8], 0x1B);
            expanded_enc[10] = expand128!(expanded_enc[9], 0x36);

            expanded_dec[0]  = expanded_enc[10];
            expanded_dec[1]  = _mm_aesimc_si128(expanded_enc[9]);
            expanded_dec[2]  = _mm_aesimc_si128(expanded_enc[8]);
            expanded_dec[3]  = _mm_aesimc_si128(expanded_enc[7]);
            expanded_dec[4]  = _mm_aesimc_si128(expanded_enc[6]);
            expanded_dec[5]  = _mm_aesimc_si128(expanded_enc[5]);
            expanded_dec[6]  = _mm_aesimc_si128(expanded_enc[4]);
            expanded_dec[7]  = _mm_aesimc_si128(expanded_enc[3]);
            expanded_dec[8]  = _mm_aesimc_si128(expanded_enc[2]);
            expanded_dec[9]  = _mm_aesimc_si128(expanded_enc[1]);
            expanded_dec[10] = expanded_enc[0];

            AES128 { expanded_enc, expanded_dec }
        }
    }

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16);
        let mut result = Vec::with_capacity(16);
        result.resize(16, 0);
        unsafe {
            let mut val = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            val = _mm_xor_si128(val, self.expanded_enc[0]);
            val = _mm_aesenc_si128(val, self.expanded_enc[1]);
            val = _mm_aesenc_si128(val, self.expanded_enc[2]);
            val = _mm_aesenc_si128(val, self.expanded_enc[3]);
            val = _mm_aesenc_si128(val, self.expanded_enc[4]);
            val = _mm_aesenc_si128(val, self.expanded_enc[5]);
            val = _mm_aesenc_si128(val, self.expanded_enc[6]);
            val = _mm_aesenc_si128(val, self.expanded_enc[7]);
            val = _mm_aesenc_si128(val, self.expanded_enc[8]);
            val = _mm_aesenc_si128(val, self.expanded_enc[9]);
            val = _mm_aesenclast_si128(val, self.expanded_enc[10]);
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, val);
        }
        result
    }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16);
        let mut result = Vec::with_capacity(16);
        result.resize(16, 0);
        unsafe {
            let mut val = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            val = _mm_xor_si128(val, self.expanded_dec[0]);
            val = _mm_aesdec_si128(val, self.expanded_dec[1]);
            val = _mm_aesdec_si128(val, self.expanded_dec[2]);
            val = _mm_aesdec_si128(val, self.expanded_dec[3]);
            val = _mm_aesdec_si128(val, self.expanded_dec[4]);
            val = _mm_aesdec_si128(val, self.expanded_dec[5]);
            val = _mm_aesdec_si128(val, self.expanded_dec[6]);
            val = _mm_aesdec_si128(val, self.expanded_dec[7]);
            val = _mm_aesdec_si128(val, self.expanded_dec[8]);
            val = _mm_aesdec_si128(val, self.expanded_dec[9]);
            val = _mm_aesdeclast_si128(val, self.expanded_dec[10]);
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, val);
        }
        result
    }
}

#[cfg(test)]
fn unpack_m128(b: __m128i) -> (u64, u64)
{
    unsafe {
        let data: [u64; 2] = transmute(b);
        (data[0].to_be(), data[1].to_be())
    }
}

#[cfg(test)]
mod aes128 {
    use super::*;
    use testing::run_test;

    #[test]
    fn expansion() {
        let zero_key = AES128::new(&[0x00; 16]);
        assert_eq!(unpack_m128(zero_key.expanded_enc[0]),  (0x0000000000000000, 0x0000000000000000));
        assert_eq!(unpack_m128(zero_key.expanded_enc[1]),  (0x6263636362636363, 0x6263636362636363));
        assert_eq!(unpack_m128(zero_key.expanded_enc[2]),  (0x9b9898c9f9fbfbaa, 0x9b9898c9f9fbfbaa));
        assert_eq!(unpack_m128(zero_key.expanded_enc[3]),  (0x90973450696ccffa, 0xf2f457330b0fac99));
        assert_eq!(unpack_m128(zero_key.expanded_enc[4]),  (0xee06da7b876a1581, 0x759e42b27e91ee2b));
        assert_eq!(unpack_m128(zero_key.expanded_enc[5]),  (0x7f2e2b88f8443e09, 0x8dda7cbbf34b9290));
        assert_eq!(unpack_m128(zero_key.expanded_enc[6]),  (0xec614b851425758c, 0x99ff09376ab49ba7));
        assert_eq!(unpack_m128(zero_key.expanded_enc[7]),  (0x217517873550620b, 0xacaf6b3cc61bf09b));
        assert_eq!(unpack_m128(zero_key.expanded_enc[8]),  (0x0ef903333ba96138, 0x97060a04511dfa9f));
        assert_eq!(unpack_m128(zero_key.expanded_enc[9]),  (0xb1d4d8e28a7db9da, 0x1d7bb3de4c664941));
        assert_eq!(unpack_m128(zero_key.expanded_enc[10]), (0xb4ef5bcb3e92e211, 0x23e951cf6f8f188e));
        let ff_key = AES128::new(&[0xff; 16]);
        assert_eq!(unpack_m128(ff_key.expanded_enc[0]),  (0xffffffffffffffff, 0xffffffffffffffff));
        assert_eq!(unpack_m128(ff_key.expanded_enc[1]),  (0xe8e9e9e917161616, 0xe8e9e9e917161616));
        assert_eq!(unpack_m128(ff_key.expanded_enc[2]),  (0xadaeae19bab8b80f, 0x525151e6454747f0));
        assert_eq!(unpack_m128(ff_key.expanded_enc[3]),  (0x090e2277b3b69a78, 0xe1e7cb9ea4a08c6e));
        assert_eq!(unpack_m128(ff_key.expanded_enc[4]),  (0xe16abd3e52dc2746, 0xb33becd8179b60b6));
        assert_eq!(unpack_m128(ff_key.expanded_enc[5]),  (0xe5baf3ceb766d488, 0x045d385013c658e6));
        assert_eq!(unpack_m128(ff_key.expanded_enc[6]),  (0x71d07db3c6b6a93b, 0xc2eb916bd12dc98d));
        assert_eq!(unpack_m128(ff_key.expanded_enc[7]),  (0xe90d208d2fbb89b6, 0xed5018dd3c7dd150));
        assert_eq!(unpack_m128(ff_key.expanded_enc[8]),  (0x96337366b988fad0, 0x54d8e20d68a5335d));
        assert_eq!(unpack_m128(ff_key.expanded_enc[9]),  (0x8bf03f233278c5f3, 0x66a027fe0e0514a3));
        assert_eq!(unpack_m128(ff_key.expanded_enc[10]), (0xd60a3588e472f07b, 0x82d2d7858cd7c326));
        let nist_key = AES128::new(&[0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]);
        assert_eq!(unpack_m128(nist_key.expanded_enc[0]),  (0x2b7e151628aed2a6, 0xabf7158809cf4f3c));
        assert_eq!(unpack_m128(nist_key.expanded_enc[1]),  (0xa0fafe1788542cb1, 0x23a339392a6c7605));
        assert_eq!(unpack_m128(nist_key.expanded_enc[2]),  (0xf2c295f27a96b943, 0x5935807a7359f67f));
        assert_eq!(unpack_m128(nist_key.expanded_enc[3]),  (0x3d80477d4716fe3e, 0x1e237e446d7a883b));
        assert_eq!(unpack_m128(nist_key.expanded_enc[4]),  (0xef44a541a8525b7f, 0xb671253bdb0bad00));
        assert_eq!(unpack_m128(nist_key.expanded_enc[5]),  (0xd4d1c6f87c839d87, 0xcaf2b8bc11f915bc));
        assert_eq!(unpack_m128(nist_key.expanded_enc[6]),  (0x6d88a37a110b3efd, 0xdbf98641ca0093fd));
        assert_eq!(unpack_m128(nist_key.expanded_enc[7]),  (0x4e54f70e5f5fc9f3, 0x84a64fb24ea6dc4f));
        assert_eq!(unpack_m128(nist_key.expanded_enc[8]),  (0xead27321b58dbad2, 0x312bf5607f8d292f));
        assert_eq!(unpack_m128(nist_key.expanded_enc[9]),  (0xac7766f319fadc21, 0x28d12941575c006e));
        assert_eq!(unpack_m128(nist_key.expanded_enc[10]), (0xd014f9a8c9ee2589, 0xe13f0cc8b6630ca6));
    }

    #[test]
    fn fips197_examples() {
        let input1  = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
        let key1    = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let aeskey1 = AES128::new(&key1);
        let cipher1 = aeskey1.encrypt(&input1);
        assert_eq!(cipher1, vec![0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                                 0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32]);
        assert_eq!(input1.to_vec(), aeskey1.decrypt(&cipher1));
        let input2  = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
        let key2    = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f];
        let aeskey2 = AES128::new(&key2);
        let cipher2 = aeskey2.encrypt(&input2);
        assert_eq!(cipher2, vec![0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                 0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a]);
        assert_eq!(input2.to_vec(), aeskey2.decrypt(&cipher2));
    }

    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/aes/aes128.test";
        run_test(fname.to_string(), 3, |case| {
            let (negk, kbytes) = case.get("k").unwrap();
            let (negp, pbytes) = case.get("p").unwrap();
            let (negc, cbytes) = case.get("c").unwrap();

            assert!(!negk && !negp && !negc);
            let key = AES128::new(&kbytes);
            let cipher = key.encrypt(&pbytes);
            let plain = key.decrypt(&cipher);
            assert_eq!(&cipher, cbytes);
            assert_eq!(&plain, pbytes);
        });
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
// 256-Bit Support
//
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AES256 {
    expanded_enc: [__m128i; 15],
    expanded_dec: [__m128i; 15],
}

macro_rules! expand256 {
    ($prevprev: expr, $prev: expr, $shuffle: expr, $round: expr) => {{
        let gen0 = _mm_aeskeygenassist_si128($prev, $round);
        let gen1 = _mm_shuffle_epi32(gen0, $shuffle);
        let key0 = $prevprev;
        let key1 = _mm_xor_si128(key0, _mm_slli_si128(key0, 4));
        let key2 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
        let key3 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
        _mm_xor_si128(gen1, key3) 
    }};
}

impl AES256 {
    pub fn new(base_key: &[u8]) -> AES256 {
        assert_eq!(base_key.len(), 32);
        unsafe {
            let mut expanded_enc: [__m128i; 15] = uninitialized();
            let mut expanded_dec: [__m128i; 15] = uninitialized();

            let keyptr = base_key.as_ptr() as *const __m128i;
            expanded_enc[00] = _mm_loadu_si128(keyptr.offset(0));
            expanded_enc[01] = _mm_loadu_si128(keyptr.offset(1));
            expanded_enc[02] = expand256!(expanded_enc[00], expanded_enc[01], 0xff, 0x01);
            expanded_enc[03] = expand256!(expanded_enc[01], expanded_enc[02], 0xaa, 0x00);
            expanded_enc[04] = expand256!(expanded_enc[02], expanded_enc[03], 0xff, 0x02);
            expanded_enc[05] = expand256!(expanded_enc[03], expanded_enc[04], 0xaa, 0x00);
            expanded_enc[06] = expand256!(expanded_enc[04], expanded_enc[05], 0xff, 0x04);
            expanded_enc[07] = expand256!(expanded_enc[05], expanded_enc[06], 0xaa, 0x00);
            expanded_enc[08] = expand256!(expanded_enc[06], expanded_enc[07], 0xff, 0x08);
            expanded_enc[09] = expand256!(expanded_enc[07], expanded_enc[08], 0xaa, 0x00);
            expanded_enc[10] = expand256!(expanded_enc[08], expanded_enc[09], 0xff, 0x10);
            expanded_enc[11] = expand256!(expanded_enc[09], expanded_enc[10], 0xaa, 0x00);
            expanded_enc[12] = expand256!(expanded_enc[10], expanded_enc[11], 0xff, 0x20);
            expanded_enc[13] = expand256!(expanded_enc[11], expanded_enc[12], 0xaa, 0x00);
            expanded_enc[14] = expand256!(expanded_enc[12], expanded_enc[13], 0xff, 0x40);

            expanded_dec[00] = expanded_enc[14];
            expanded_dec[01] = _mm_aesimc_si128(expanded_enc[13]);
            expanded_dec[02] = _mm_aesimc_si128(expanded_enc[12]);
            expanded_dec[03] = _mm_aesimc_si128(expanded_enc[11]);
            expanded_dec[04] = _mm_aesimc_si128(expanded_enc[10]);
            expanded_dec[05] = _mm_aesimc_si128(expanded_enc[09]);
            expanded_dec[06] = _mm_aesimc_si128(expanded_enc[08]);
            expanded_dec[07] = _mm_aesimc_si128(expanded_enc[07]);
            expanded_dec[08] = _mm_aesimc_si128(expanded_enc[06]);
            expanded_dec[09] = _mm_aesimc_si128(expanded_enc[05]);
            expanded_dec[10] = _mm_aesimc_si128(expanded_enc[04]);
            expanded_dec[11] = _mm_aesimc_si128(expanded_enc[03]);
            expanded_dec[12] = _mm_aesimc_si128(expanded_enc[02]);
            expanded_dec[13] = _mm_aesimc_si128(expanded_enc[01]);
            expanded_dec[14] = expanded_enc[0];

            AES256{ expanded_enc, expanded_dec }
        }
    }

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16);
        let mut result = Vec::with_capacity(16);
        result.resize(16, 0);
        unsafe {
            let mut val = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            val = _mm_xor_si128(val, self.expanded_enc[0]);
            val = _mm_aesenc_si128(val, self.expanded_enc[01]);
            val = _mm_aesenc_si128(val, self.expanded_enc[02]);
            val = _mm_aesenc_si128(val, self.expanded_enc[03]);
            val = _mm_aesenc_si128(val, self.expanded_enc[04]);
            val = _mm_aesenc_si128(val, self.expanded_enc[05]);
            val = _mm_aesenc_si128(val, self.expanded_enc[06]);
            val = _mm_aesenc_si128(val, self.expanded_enc[07]);
            val = _mm_aesenc_si128(val, self.expanded_enc[08]);
            val = _mm_aesenc_si128(val, self.expanded_enc[09]);
            val = _mm_aesenc_si128(val, self.expanded_enc[10]);
            val = _mm_aesenc_si128(val, self.expanded_enc[11]);
            val = _mm_aesenc_si128(val, self.expanded_enc[12]);
            val = _mm_aesenc_si128(val, self.expanded_enc[13]);
            val = _mm_aesenclast_si128(val, self.expanded_enc[14]);
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, val);
        }
        result
    }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16);
        let mut result = Vec::with_capacity(16);
        result.resize(16, 0);
        unsafe {
            let mut val = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            val = _mm_xor_si128(val, self.expanded_dec[00]);
            val = _mm_aesdec_si128(val, self.expanded_dec[01]);
            val = _mm_aesdec_si128(val, self.expanded_dec[02]);
            val = _mm_aesdec_si128(val, self.expanded_dec[03]);
            val = _mm_aesdec_si128(val, self.expanded_dec[04]);
            val = _mm_aesdec_si128(val, self.expanded_dec[05]);
            val = _mm_aesdec_si128(val, self.expanded_dec[06]);
            val = _mm_aesdec_si128(val, self.expanded_dec[07]);
            val = _mm_aesdec_si128(val, self.expanded_dec[08]);
            val = _mm_aesdec_si128(val, self.expanded_dec[09]);
            val = _mm_aesdec_si128(val, self.expanded_dec[10]);
            val = _mm_aesdec_si128(val, self.expanded_dec[11]);
            val = _mm_aesdec_si128(val, self.expanded_dec[12]);
            val = _mm_aesdec_si128(val, self.expanded_dec[13]);
            val = _mm_aesdeclast_si128(val, self.expanded_dec[14]);
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, val);
        }
        result
    }
}

#[cfg(test)]
mod aes256 {
    use super::*;
    use testing::run_test;

    #[test]
    fn expansion() {
        let zero_key = AES256::new(&[0x00; 32]);
        assert_eq!(unpack_m128(zero_key.expanded_enc[00]), (0x0000000000000000, 0x0000000000000000));
        assert_eq!(unpack_m128(zero_key.expanded_enc[01]), (0x0000000000000000, 0x0000000000000000));
        assert_eq!(unpack_m128(zero_key.expanded_enc[02]), (0x6263636362636363, 0x6263636362636363));
        assert_eq!(unpack_m128(zero_key.expanded_enc[03]), (0xaafbfbfbaafbfbfb, 0xaafbfbfbaafbfbfb));
        assert_eq!(unpack_m128(zero_key.expanded_enc[04]), (0x6f6c6ccf0d0f0fac, 0x6f6c6ccf0d0f0fac));
        assert_eq!(unpack_m128(zero_key.expanded_enc[05]), (0x7d8d8d6ad7767691, 0x7d8d8d6ad7767691));
        assert_eq!(unpack_m128(zero_key.expanded_enc[06]), (0x5354edc15e5be26d, 0x31378ea23c38810e));
        assert_eq!(unpack_m128(zero_key.expanded_enc[07]), (0x968a81c141fcf750, 0x3c717a3aeb070cab));
        assert_eq!(unpack_m128(zero_key.expanded_enc[08]), (0x9eaa8f28c0f16d45, 0xf1c6e3e7cdfe62e9));
        assert_eq!(unpack_m128(zero_key.expanded_enc[09]), (0x2b312bdf6acddc8f, 0x56bca6b5bdbbaa1e));
        assert_eq!(unpack_m128(zero_key.expanded_enc[10]), (0x6406fd52a4f79017, 0x553173f098cf1119));
        assert_eq!(unpack_m128(zero_key.expanded_enc[11]), (0x6dbba90b07767584, 0x51cad331ec71792f));
        assert_eq!(unpack_m128(zero_key.expanded_enc[12]), (0xe7b0e89c4347788b, 0x16760b7b8eb91a62));
        assert_eq!(unpack_m128(zero_key.expanded_enc[13]), (0x74ed0ba1739b7e25, 0x2251ad14ce20d43b));
        assert_eq!(unpack_m128(zero_key.expanded_enc[14]), (0x10f80a1753bf729c, 0x45c979e7cb706385));
        let ff_key = AES256::new(&[0xff; 32]);
        assert_eq!(unpack_m128(ff_key.expanded_enc[00]), (0xffffffffffffffff, 0xffffffffffffffff));
        assert_eq!(unpack_m128(ff_key.expanded_enc[01]), (0xffffffffffffffff, 0xffffffffffffffff));
        assert_eq!(unpack_m128(ff_key.expanded_enc[02]), (0xe8e9e9e917161616, 0xe8e9e9e917161616));
        assert_eq!(unpack_m128(ff_key.expanded_enc[03]), (0x0fb8b8b8f0474747, 0x0fb8b8b8f0474747));
        assert_eq!(unpack_m128(ff_key.expanded_enc[04]), (0x4a4949655d5f5f73, 0xb5b6b69aa2a0a08c));
        assert_eq!(unpack_m128(ff_key.expanded_enc[05]), (0x355858dcc51f1f9b, 0xcaa7a7233ae0e064));
        assert_eq!(unpack_m128(ff_key.expanded_enc[06]), (0xafa80ae5f2f75596, 0x4741e30ce5e14380));
        assert_eq!(unpack_m128(ff_key.expanded_enc[07]), (0xeca0421129bf5d8a, 0xe318faa9d9f81acd));
        assert_eq!(unpack_m128(ff_key.expanded_enc[08]), (0xe60ab7d014fde246, 0x53bc014ab65d42ca));
        assert_eq!(unpack_m128(ff_key.expanded_enc[09]), (0xa2ec6e658b5333ef, 0x684bc946b1b3d38b));
        assert_eq!(unpack_m128(ff_key.expanded_enc[10]), (0x9b6c8a188f91685e, 0xdc2d69146a702bde));
        assert_eq!(unpack_m128(ff_key.expanded_enc[11]), (0xa0bd9f782beeac97, 0x43a565d1f216b65a));
        assert_eq!(unpack_m128(ff_key.expanded_enc[12]), (0xfc22349173b35ccf, 0xaf9e35dbc5ee1e05));
        assert_eq!(unpack_m128(ff_key.expanded_enc[13]), (0x0695ed132d7b4184, 0x6ede24559cc8920f));
        assert_eq!(unpack_m128(ff_key.expanded_enc[14]), (0x546d424f27de1e80, 0x88402b5b4dae355e));
        let nist_key = AES256::new(&[0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                                     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                                     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]);
        assert_eq!(unpack_m128(nist_key.expanded_enc[00]), (0x603deb1015ca71be, 0x2b73aef0857d7781));
        assert_eq!(unpack_m128(nist_key.expanded_enc[01]), (0x1f352c073b6108d7, 0x2d9810a30914dff4));
        assert_eq!(unpack_m128(nist_key.expanded_enc[02]), (0x9ba354118e6925af, 0xa51a8b5f2067fcde));
        assert_eq!(unpack_m128(nist_key.expanded_enc[03]), (0xa8b09c1a93d194cd, 0xbe49846eb75d5b9a));
        assert_eq!(unpack_m128(nist_key.expanded_enc[04]), (0xd59aecb85bf3c917, 0xfee94248de8ebe96));
        assert_eq!(unpack_m128(nist_key.expanded_enc[05]), (0xb5a9328a2678a647, 0x983122292f6c79b3));
        assert_eq!(unpack_m128(nist_key.expanded_enc[06]), (0x812c81addadf48ba, 0x24360af2fab8b464));
        assert_eq!(unpack_m128(nist_key.expanded_enc[07]), (0x98c5bfc9bebd198e, 0x268c3ba709e04214));
        assert_eq!(unpack_m128(nist_key.expanded_enc[08]), (0x68007bacb2df3316, 0x96e939e46c518d80));
        assert_eq!(unpack_m128(nist_key.expanded_enc[09]), (0xc814e20476a9fb8a, 0x5025c02d59c58239));
        assert_eq!(unpack_m128(nist_key.expanded_enc[10]), (0xde1369676ccc5a71, 0xfa2563959674ee15));
        assert_eq!(unpack_m128(nist_key.expanded_enc[11]), (0x5886ca5d2e2f31d7, 0x7e0af1fa27cf73c3));
        assert_eq!(unpack_m128(nist_key.expanded_enc[12]), (0x749c47ab18501dda, 0xe2757e4f7401905a));
        assert_eq!(unpack_m128(nist_key.expanded_enc[13]), (0xcafaaae3e4d59b34, 0x9adf6acebd10190d));
        assert_eq!(unpack_m128(nist_key.expanded_enc[14]), (0xfe4890d1e6188d0b, 0x046df344706c631e));
    }

    #[test]
    fn fips197_example() {
        let input  = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
        let key    = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                      0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let aeskey = AES256::new(&key);
        let cipher = aeskey.encrypt(&input);
        assert_eq!(cipher, vec![0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                                0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89]);
        assert_eq!(input.to_vec(), aeskey.decrypt(&cipher));
    }

    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/aes/aes256.test";
        run_test(fname.to_string(), 3, |case| {
            let (negk, kbytes) = case.get("k").unwrap();
            let (negp, pbytes) = case.get("p").unwrap();
            let (negc, cbytes) = case.get("c").unwrap();

            assert!(!negk && !negp && !negc);
            let key = AES256::new(&kbytes);
            let cipher = key.encrypt(&pbytes);
            let plain = key.decrypt(&cipher);
            assert_eq!(&cipher, cbytes);
            assert_eq!(&plain, pbytes);
        });
    }
}