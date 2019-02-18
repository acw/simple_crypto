use cryptonum::unsigned::*;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha224,Sha256,Sha384,Sha512};
use simple_asn1::{der_decode,der_encode};
use dsa::params::{DSAParameters,L1024N160,L2048N256};
use dsa::private::{DSAPrivateKey,DSAPrivKey};
use dsa::public::{DSAPublicKey,DSAPubKey};
use dsa::rfc6979::KIterator;

macro_rules! run_rfc6979_test {
    ($hash: ty, $ntype: ident, $val: ident, $params: ident, $public: ident, $private: ident,
     k $k: expr,
     r $r: expr,
     s $s: expr) => ({
        let h1 = <$hash>::digest(&$val);
        let rbytes = $r;
        let sbytes = $s;
        let r = $ntype::from_bytes(&rbytes);
        let s = $ntype::from_bytes(&sbytes);
        let mut iter = KIterator::<$hash,$ntype>::new(&h1, $params.n_bits(), &$params.q, &$private.x);
        let mut k1 = iter.next().unwrap().to_bytes().to_vec();
        while k1.len() > $k.len() {
            assert_eq!(k1[0], 0);
            k1.remove(0);
        }
        assert_eq!($k, k1);
        let sig = $private.sign::<$hash>(&$val);
        assert_eq!(sig.r, r);
        assert_eq!(sig.s, s);
        assert!($public.verify::<$hash>(&$val, &sig));
        let blocks = der_encode(&sig).unwrap();
        let sig2 = der_decode(&blocks).unwrap();
        assert_eq!(sig, sig2);
    })
}

// these appendix_* tests are out of RFC6979
#[test]
fn appendix_a21() {
    let pbytes = vec![0x86, 0xF5, 0xCA, 0x03, 0xDC, 0xFE, 0xB2, 0x25,
                      0x06, 0x3F, 0xF8, 0x30, 0xA0, 0xC7, 0x69, 0xB9,
                      0xDD, 0x9D, 0x61, 0x53, 0xAD, 0x91, 0xD7, 0xCE,
                      0x27, 0xF7, 0x87, 0xC4, 0x32, 0x78, 0xB4, 0x47,
                      0xE6, 0x53, 0x3B, 0x86, 0xB1, 0x8B, 0xED, 0x6E,
                      0x8A, 0x48, 0xB7, 0x84, 0xA1, 0x4C, 0x25, 0x2C,
                      0x5B, 0xE0, 0xDB, 0xF6, 0x0B, 0x86, 0xD6, 0x38,
                      0x5B, 0xD2, 0xF1, 0x2F, 0xB7, 0x63, 0xED, 0x88,
                      0x73, 0xAB, 0xFD, 0x3F, 0x5B, 0xA2, 0xE0, 0xA8,
                      0xC0, 0xA5, 0x90, 0x82, 0xEA, 0xC0, 0x56, 0x93,
                      0x5E, 0x52, 0x9D, 0xAF, 0x7C, 0x61, 0x04, 0x67,
                      0x89, 0x9C, 0x77, 0xAD, 0xED, 0xFC, 0x84, 0x6C,
                      0x88, 0x18, 0x70, 0xB7, 0xB1, 0x9B, 0x2B, 0x58,
                      0xF9, 0xBE, 0x05, 0x21, 0xA1, 0x70, 0x02, 0xE3,
                      0xBD, 0xD6, 0xB8, 0x66, 0x85, 0xEE, 0x90, 0xB3,
                      0xD9, 0xA1, 0xB0, 0x2B, 0x78, 0x2B, 0x17, 0x79];
    let qbytes = vec![0x99, 0x6F, 0x96, 0x7F, 0x6C, 0x8E, 0x38, 0x8D,
                      0x9E, 0x28, 0xD0, 0x1E, 0x20, 0x5F, 0xBA, 0x95,
                      0x7A, 0x56, 0x98, 0xB1];
    let gbytes = vec![0x07, 0xB0, 0xF9, 0x25, 0x46, 0x15, 0x0B, 0x62,
                      0x51, 0x4B, 0xB7, 0x71, 0xE2, 0xA0, 0xC0, 0xCE,
                      0x38, 0x7F, 0x03, 0xBD, 0xA6, 0xC5, 0x6B, 0x50,
                      0x52, 0x09, 0xFF, 0x25, 0xFD, 0x3C, 0x13, 0x3D,
                      0x89, 0xBB, 0xCD, 0x97, 0xE9, 0x04, 0xE0, 0x91,
                      0x14, 0xD9, 0xA7, 0xDE, 0xFD, 0xEA, 0xDF, 0xC9,
                      0x07, 0x8E, 0xA5, 0x44, 0xD2, 0xE4, 0x01, 0xAE,
                      0xEC, 0xC4, 0x0B, 0xB9, 0xFB, 0xBF, 0x78, 0xFD,
                      0x87, 0x99, 0x5A, 0x10, 0xA1, 0xC2, 0x7C, 0xB7,
                      0x78, 0x9B, 0x59, 0x4B, 0xA7, 0xEF, 0xB5, 0xC4,
                      0x32, 0x6A, 0x9F, 0xE5, 0x9A, 0x07, 0x0E, 0x13,
                      0x6D, 0xB7, 0x71, 0x75, 0x46, 0x4A, 0xDC, 0xA4,
                      0x17, 0xBE, 0x5D, 0xCE, 0x2F, 0x40, 0xD1, 0x0A,
                      0x46, 0xA3, 0xA3, 0x94, 0x3F, 0x26, 0xAB, 0x7F,
                      0xD9, 0xC0, 0x39, 0x8F, 0xF8, 0xC7, 0x6E, 0xE0,
                      0xA5, 0x68, 0x26, 0xA8, 0xA8, 0x8F, 0x1D, 0xBD];
    let xbytes = vec![0x41, 0x16, 0x02, 0xCB, 0x19, 0xA6, 0xCC, 0xC3,
                      0x44, 0x94, 0xD7, 0x9D, 0x98, 0xEF, 0x1E, 0x7E,
                      0xD5, 0xAF, 0x25, 0xF7];
    let ybytes = vec![0x5D, 0xF5, 0xE0, 0x1D, 0xED, 0x31, 0xD0, 0x29,
                      0x7E, 0x27, 0x4E, 0x16, 0x91, 0xC1, 0x92, 0xFE,
                      0x58, 0x68, 0xFE, 0xF9, 0xE1, 0x9A, 0x84, 0x77,
                      0x64, 0x54, 0xB1, 0x00, 0xCF, 0x16, 0xF6, 0x53,
                      0x92, 0x19, 0x5A, 0x38, 0xB9, 0x05, 0x23, 0xE2,
                      0x54, 0x2E, 0xE6, 0x18, 0x71, 0xC0, 0x44, 0x0C,
                      0xB8, 0x7C, 0x32, 0x2F, 0xC4, 0xB4, 0xD2, 0xEC,
                      0x5E, 0x1E, 0x7E, 0xC7, 0x66, 0xE1, 0xBE, 0x8D,
                      0x4C, 0xE9, 0x35, 0x43, 0x7D, 0xC1, 0x1C, 0x3C,
                      0x8F, 0xD4, 0x26, 0x33, 0x89, 0x33, 0xEB, 0xFE,
                      0x73, 0x9C, 0xB3, 0x46, 0x5F, 0x4D, 0x36, 0x68,
                      0xC5, 0xE4, 0x73, 0x50, 0x82, 0x53, 0xB1, 0xE6,
                      0x82, 0xF6, 0x5C, 0xBD, 0xC4, 0xFA, 0xE9, 0x3C,
                      0x2E, 0xA2, 0x12, 0x39, 0x0E, 0x54, 0x90, 0x5A,
                      0x86, 0xE2, 0x22, 0x31, 0x70, 0xB4, 0x4E, 0xAA,
                      0x7D, 0xA5, 0xDD, 0x9F, 0xFC, 0xFB, 0x7F, 0x3B];
    //
    let p = U1024::from_bytes(&pbytes);
    let q = U192::from_bytes(&qbytes);
    let g = U1024::from_bytes(&gbytes);
    let params = L1024N160::new(p, g, q);
    let x = U192::from_bytes(&xbytes);
    let y = U1024::from_bytes(&ybytes);
    let private = DSAPrivKey::new(params.clone(), x);
    let public = DSAPubKey::<L1024N160,U1024>::new(params.clone(), y);
    //
    let sample: [u8; 6] = [115, 97, 109, 112, 108, 101]; // "sample", ASCII
    let test:   [u8; 4] = [116, 101, 115, 116]; // "test", ASCII
    // With SHA-1, message = "sample":
    //    k = 7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B
    //    r = 2E1A0C2562B2912CAAF89186FB0F42001585DA55
    //    s = 29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5
    run_rfc6979_test!(Sha1, U192, sample, params, public, private,
      k vec![0x7B, 0xDB, 0x6B, 0x0F, 0xF7, 0x56, 0xE1, 0xBB,
             0x5D, 0x53, 0x58, 0x3E, 0xF9, 0x79, 0x08, 0x2F,
             0x9A, 0xD5, 0xBD, 0x5B],
      r vec![0x2E, 0x1A, 0x0C, 0x25, 0x62, 0xB2, 0x91, 0x2C,
             0xAA, 0xF8, 0x91, 0x86, 0xFB, 0x0F, 0x42, 0x00,
             0x15, 0x85, 0xDA, 0x55],
      s vec![0x29, 0xEF, 0xB6, 0xB0, 0xAF, 0xF2, 0xD7, 0xA6,
             0x8E, 0xB7, 0x0C, 0xA3, 0x13, 0x02, 0x22, 0x53,
             0xB9, 0xA8, 0x8D, 0xF5]);
    //  With SHA-224, message = "sample":
    //     k = 562097C06782D60C3037BA7BE104774344687649
    //     r = 4BC3B686AEA70145856814A6F1BB53346F02101E
    //     s = 410697B92295D994D21EDD2F4ADA85566F6F94C1
    run_rfc6979_test!(Sha224, U192, sample, params, public, private,
       k vec![0x56, 0x20, 0x97, 0xC0, 0x67, 0x82, 0xD6, 0x0C,
              0x30, 0x37, 0xBA, 0x7B, 0xE1, 0x04, 0x77, 0x43,
              0x44, 0x68, 0x76, 0x49],
       r vec![0x4B, 0xC3, 0xB6, 0x86, 0xAE, 0xA7, 0x01, 0x45,
              0x85, 0x68, 0x14, 0xA6, 0xF1, 0xBB, 0x53, 0x34,
              0x6F, 0x02, 0x10, 0x1E],
       s vec![0x41, 0x06, 0x97, 0xB9, 0x22, 0x95, 0xD9, 0x94,
              0xD2, 0x1E, 0xDD, 0x2F, 0x4A, 0xDA, 0x85, 0x56,
              0x6F, 0x6F, 0x94, 0xC1]);
    // With SHA-256, message = "sample":
    //    k = 519BA0546D0C39202A7D34D7DFA5E760B318BCFB
    //    r = 81F2F5850BE5BC123C43F71A3033E9384611C545
    //    s = 4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89
    run_rfc6979_test!(Sha256, U192, sample, params, public, private,
        k vec![0x51, 0x9B, 0xA0, 0x54, 0x6D, 0x0C, 0x39, 0x20,
               0x2A, 0x7D, 0x34, 0xD7, 0xDF, 0xA5, 0xE7, 0x60,
               0xB3, 0x18, 0xBC, 0xFB],
        r vec![0x81, 0xF2, 0xF5, 0x85, 0x0B, 0xE5, 0xBC, 0x12,
               0x3C, 0x43, 0xF7, 0x1A, 0x30, 0x33, 0xE9, 0x38,
               0x46, 0x11, 0xC5, 0x45],
        s vec![0x4C, 0xDD, 0x91, 0x4B, 0x65, 0xEB, 0x6C, 0x66,
               0xA8, 0xAA, 0xAD, 0x27, 0x29, 0x9B, 0xEE, 0x6B,
               0x03, 0x5F, 0x5E, 0x89]);
    // With SHA-384, message = "sample":
    //    k = 95897CD7BBB944AA932DBC579C1C09EB6FCFC595
    //    r = 07F2108557EE0E3921BC1774F1CA9B410B4CE65A
    //    s = 54DF70456C86FAC10FAB47C1949AB83F2C6F7595
    run_rfc6979_test!(Sha384, U192, sample, params, public, private,
        k vec![0x95, 0x89, 0x7C, 0xD7, 0xBB, 0xB9, 0x44, 0xAA,
               0x93, 0x2D, 0xBC, 0x57, 0x9C, 0x1C, 0x09, 0xEB,
               0x6F, 0xCF, 0xC5, 0x95],
        r vec![0x07, 0xF2, 0x10, 0x85, 0x57, 0xEE, 0x0E, 0x39,
               0x21, 0xBC, 0x17, 0x74, 0xF1, 0xCA, 0x9B, 0x41,
               0x0B, 0x4C, 0xE6, 0x5A],
        s vec![0x54, 0xDF, 0x70, 0x45, 0x6C, 0x86, 0xFA, 0xC1,
               0x0F, 0xAB, 0x47, 0xC1, 0x94, 0x9A, 0xB8, 0x3F,
               0x2C, 0x6F, 0x75, 0x95]);
    // With SHA-512, message = "sample":
    //    k = 09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B
    //    r = 16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B
    //    s = 02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C
    run_rfc6979_test!(Sha512, U192, sample, params, public, private,
        k vec![0x09, 0xEC, 0xE7, 0xCA, 0x27, 0xD0, 0xF5, 0xA4,
               0xDD, 0x4E, 0x55, 0x6C, 0x9D, 0xF1, 0xD2, 0x1D,
               0x28, 0x10, 0x4F, 0x8B],
        r vec![0x16, 0xC3, 0x49, 0x1F, 0x9B, 0x8C, 0x3F, 0xBB,
               0xDD, 0x5E, 0x7A, 0x7B, 0x66, 0x70, 0x57, 0xF0,
               0xD8, 0xEE, 0x8E, 0x1B],
        s vec![0x02, 0xC3, 0x6A, 0x12, 0x7A, 0x7B, 0x89, 0xED,
               0xBB, 0x72, 0xE4, 0xFF, 0xBC, 0x71, 0xDA, 0xBC,
               0x7D, 0x4F, 0xC6, 0x9C]);
    // With SHA-1, message = "test":
    //    k = 5C842DF4F9E344EE09F056838B42C7A17F4A6433
    //    r = 42AB2052FD43E123F0607F115052A67DCD9C5C77
    //    s = 183916B0230D45B9931491D4C6B0BD2FB4AAF088
    run_rfc6979_test!(Sha1, U192, test, params, public, private,
        k vec![0x5C, 0x84, 0x2D, 0xF4, 0xF9, 0xE3, 0x44, 0xEE,
               0x09, 0xF0, 0x56, 0x83, 0x8B, 0x42, 0xC7, 0xA1,
               0x7F, 0x4A, 0x64, 0x33],
        r vec![0x42, 0xAB, 0x20, 0x52, 0xFD, 0x43, 0xE1, 0x23,
               0xF0, 0x60, 0x7F, 0x11, 0x50, 0x52, 0xA6, 0x7D,
               0xCD, 0x9C, 0x5C, 0x77],
        s vec![0x18, 0x39, 0x16, 0xB0, 0x23, 0x0D, 0x45, 0xB9,
               0x93, 0x14, 0x91, 0xD4, 0xC6, 0xB0, 0xBD, 0x2F,
               0xB4, 0xAA, 0xF0, 0x88]);
    // With SHA-224, message = "test":
    //    k = 4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297
    //    r = 6868E9964E36C1689F6037F91F28D5F2C30610F2
    //    s = 49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F
    run_rfc6979_test!(Sha224, U192, test, params, public, private,
        k vec![0x45, 0x98, 0xB8, 0xEF, 0xC1, 0xA5, 0x3B, 0xC8,
               0xAE, 0xCD, 0x58, 0xD1, 0xAB, 0xBB, 0x0C, 0x0C,
               0x71, 0xE6, 0x72, 0x97],
        r vec![0x68, 0x68, 0xE9, 0x96, 0x4E, 0x36, 0xC1, 0x68,
               0x9F, 0x60, 0x37, 0xF9, 0x1F, 0x28, 0xD5, 0xF2,
               0xC3, 0x06, 0x10, 0xF2],
        s vec![0x49, 0xCE, 0xC3, 0xAC, 0xDC, 0x83, 0x01, 0x8C,
               0x5B, 0xD2, 0x67, 0x4E, 0xCA, 0xAD, 0x35, 0xB8,
               0xCD, 0x22, 0x94, 0x0F]);
    // With SHA-256, message = "test":
    //    k = 5A67592E8128E03A417B0484410FB72C0B630E1A
    //    r = 22518C127299B0F6FDC9872B282B9E70D0790812
    //    s = 6837EC18F150D55DE95B5E29BE7AF5D01E4FE160
    run_rfc6979_test!(Sha256, U192, test, params, public, private,
        k vec![0x5A, 0x67, 0x59, 0x2E, 0x81, 0x28, 0xE0, 0x3A,
               0x41, 0x7B, 0x04, 0x84, 0x41, 0x0F, 0xB7, 0x2C,
               0x0B, 0x63, 0x0E, 0x1A],
        r vec![0x22, 0x51, 0x8C, 0x12, 0x72, 0x99, 0xB0, 0xF6,
               0xFD, 0xC9, 0x87, 0x2B, 0x28, 0x2B, 0x9E, 0x70,
               0xD0, 0x79, 0x08, 0x12],
        s vec![0x68, 0x37, 0xEC, 0x18, 0xF1, 0x50, 0xD5, 0x5D,
               0xE9, 0x5B, 0x5E, 0x29, 0xBE, 0x7A, 0xF5, 0xD0,
               0x1E, 0x4F, 0xE1, 0x60]);
    // With SHA-384, message = "test":
    //    k = 220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89
    //    r = 854CF929B58D73C3CBFDC421E8D5430CD6DB5E66
    //    s = 91D0E0F53E22F898D158380676A871A157CDA622
    run_rfc6979_test!(Sha384, U192, test, params, public, private,
        k vec![0x22, 0x01, 0x56, 0xB7, 0x61, 0xF6, 0xCA, 0x5E,
               0x6C, 0x9F, 0x1B, 0x9C, 0xF9, 0xC2, 0x4B, 0xE2,
               0x5F, 0x98, 0xCD, 0x89],
        r vec![0x85, 0x4C, 0xF9, 0x29, 0xB5, 0x8D, 0x73, 0xC3,
               0xCB, 0xFD, 0xC4, 0x21, 0xE8, 0xD5, 0x43, 0x0C,
               0xD6, 0xDB, 0x5E, 0x66],
        s vec![0x91, 0xD0, 0xE0, 0xF5, 0x3E, 0x22, 0xF8, 0x98,
               0xD1, 0x58, 0x38, 0x06, 0x76, 0xA8, 0x71, 0xA1,
               0x57, 0xCD, 0xA6, 0x22]);
    // With SHA-512, message = "test":
    //    k = 65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C
    //    r = 8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0
    //    s = 7C670C7AD72B6C050C109E1790008097125433E8
    run_rfc6979_test!(Sha512, U192, test, params, public, private,
        k vec![0x65, 0xD2, 0xC2, 0xEE, 0xB1, 0x75, 0xE3, 0x70,
               0xF2, 0x8C, 0x75, 0xBF, 0xCD, 0xC0, 0x28, 0xD2,
               0x2C, 0x7D, 0xBE, 0x9C],
        r vec![0x8E, 0xA4, 0x7E, 0x47, 0x5B, 0xA8, 0xAC, 0x6F,
               0x2D, 0x82, 0x1D, 0xA3, 0xBD, 0x21, 0x2D, 0x11,
               0xA3, 0xDE, 0xB9, 0xA0],
        s vec![0x7C, 0x67, 0x0C, 0x7A, 0xD7, 0x2B, 0x6C, 0x05,
               0x0C, 0x10, 0x9E, 0x17, 0x90, 0x00, 0x80, 0x97,
               0x12, 0x54, 0x33, 0xE8]);
}

#[test]
fn appendix_a22() {
    let pbytes = vec![0x9D,0xB6,0xFB,0x59,0x51,0xB6,0x6B,0xB6,
                      0xFE,0x1E,0x14,0x0F,0x1D,0x2C,0xE5,0x50,
                      0x23,0x74,0x16,0x1F,0xD6,0x53,0x8D,0xF1,
                      0x64,0x82,0x18,0x64,0x2F,0x0B,0x5C,0x48,
                      0xC8,0xF7,0xA4,0x1A,0xAD,0xFA,0x18,0x73,
                      0x24,0xB8,0x76,0x74,0xFA,0x18,0x22,0xB0,
                      0x0F,0x1E,0xCF,0x81,0x36,0x94,0x3D,0x7C,
                      0x55,0x75,0x72,0x64,0xE5,0xA1,0xA4,0x4F,
                      0xFE,0x01,0x2E,0x99,0x36,0xE0,0x0C,0x1D,
                      0x3E,0x93,0x10,0xB0,0x1C,0x7D,0x17,0x98,
                      0x05,0xD3,0x05,0x8B,0x2A,0x9F,0x4B,0xB6,
                      0xF9,0x71,0x6B,0xFE,0x61,0x17,0xC6,0xB5,
                      0xB3,0xCC,0x4D,0x9B,0xE3,0x41,0x10,0x4A,
                      0xD4,0xA8,0x0A,0xD6,0xC9,0x4E,0x00,0x5F,
                      0x4B,0x99,0x3E,0x14,0xF0,0x91,0xEB,0x51,
                      0x74,0x3B,0xF3,0x30,0x50,0xC3,0x8D,0xE2,
                      0x35,0x56,0x7E,0x1B,0x34,0xC3,0xD6,0xA5,
                      0xC0,0xCE,0xAA,0x1A,0x0F,0x36,0x82,0x13,
                      0xC3,0xD1,0x98,0x43,0xD0,0xB4,0xB0,0x9D,
                      0xCB,0x9F,0xC7,0x2D,0x39,0xC8,0xDE,0x41,
                      0xF1,0xBF,0x14,0xD4,0xBB,0x45,0x63,0xCA,
                      0x28,0x37,0x16,0x21,0xCA,0xD3,0x32,0x4B,
                      0x6A,0x2D,0x39,0x21,0x45,0xBE,0xBF,0xAC,
                      0x74,0x88,0x05,0x23,0x6F,0x5C,0xA2,0xFE,
                      0x92,0xB8,0x71,0xCD,0x8F,0x9C,0x36,0xD3,
                      0x29,0x2B,0x55,0x09,0xCA,0x8C,0xAA,0x77,
                      0xA2,0xAD,0xFC,0x7B,0xFD,0x77,0xDD,0xA6,
                      0xF7,0x11,0x25,0xA7,0x45,0x6F,0xEA,0x15,
                      0x3E,0x43,0x32,0x56,0xA2,0x26,0x1C,0x6A,
                      0x06,0xED,0x36,0x93,0x79,0x7E,0x79,0x95,
                      0xFA,0xD5,0xAA,0xBB,0xCF,0xBE,0x3E,0xDA,
                      0x27,0x41,0xE3,0x75,0x40,0x4A,0xE2,0x5B];
    let qbytes = vec![0xF2,0xC3,0x11,0x93,0x74,0xCE,0x76,0xC9,
                      0x35,0x69,0x90,0xB4,0x65,0x37,0x4A,0x17,
                      0xF2,0x3F,0x9E,0xD3,0x50,0x89,0xBD,0x96,
                      0x9F,0x61,0xC6,0xDD,0xE9,0x99,0x8C,0x1F];
    let gbytes = vec![0x5C,0x7F,0xF6,0xB0,0x6F,0x8F,0x14,0x3F,
                      0xE8,0x28,0x84,0x33,0x49,0x3E,0x47,0x69,
                      0xC4,0xD9,0x88,0xAC,0xE5,0xBE,0x25,0xA0,
                      0xE2,0x48,0x09,0x67,0x07,0x16,0xC6,0x13,
                      0xD7,0xB0,0xCE,0xE6,0x93,0x2F,0x8F,0xAA,
                      0x7C,0x44,0xD2,0xCB,0x24,0x52,0x3D,0xA5,
                      0x3F,0xBE,0x4F,0x6E,0xC3,0x59,0x58,0x92,
                      0xD1,0xAA,0x58,0xC4,0x32,0x8A,0x06,0xC4,
                      0x6A,0x15,0x66,0x2E,0x7E,0xAA,0x70,0x3A,
                      0x1D,0xEC,0xF8,0xBB,0xB2,0xD0,0x5D,0xBE,
                      0x2E,0xB9,0x56,0xC1,0x42,0xA3,0x38,0x66,
                      0x1D,0x10,0x46,0x1C,0x0D,0x13,0x54,0x72,
                      0x08,0x50,0x57,0xF3,0x49,0x43,0x09,0xFF,
                      0xA7,0x3C,0x61,0x1F,0x78,0xB3,0x2A,0xDB,
                      0xB5,0x74,0x0C,0x36,0x1C,0x9F,0x35,0xBE,
                      0x90,0x99,0x7D,0xB2,0x01,0x4E,0x2E,0xF5,
                      0xAA,0x61,0x78,0x2F,0x52,0xAB,0xEB,0x8B,
                      0xD6,0x43,0x2C,0x4D,0xD0,0x97,0xBC,0x54,
                      0x23,0xB2,0x85,0xDA,0xFB,0x60,0xDC,0x36,
                      0x4E,0x81,0x61,0xF4,0xA2,0xA3,0x5A,0xCA,
                      0x3A,0x10,0xB1,0xC4,0xD2,0x03,0xCC,0x76,
                      0xA4,0x70,0xA3,0x3A,0xFD,0xCB,0xDD,0x92,
                      0x95,0x98,0x59,0xAB,0xD8,0xB5,0x6E,0x17,
                      0x25,0x25,0x2D,0x78,0xEA,0xC6,0x6E,0x71,
                      0xBA,0x9A,0xE3,0xF1,0xDD,0x24,0x87,0x19,
                      0x98,0x74,0x39,0x3C,0xD4,0xD8,0x32,0x18,
                      0x68,0x00,0x65,0x47,0x60,0xE1,0xE3,0x4C,
                      0x09,0xE4,0xD1,0x55,0x17,0x9F,0x9E,0xC0,
                      0xDC,0x44,0x73,0xF9,0x96,0xBD,0xCE,0x6E,
                      0xED,0x1C,0xAB,0xED,0x8B,0x6F,0x11,0x6F,
                      0x7A,0xD9,0xCF,0x50,0x5D,0xF0,0xF9,0x98,
                      0xE3,0x4A,0xB2,0x75,0x14,0xB0,0xFF,0xE7];
    let xbytes = vec![0x69,0xC7,0x54,0x8C,0x21,0xD0,0xDF,0xEA,
                      0x6B,0x9A,0x51,0xC9,0xEA,0xD4,0xE2,0x7C,
                      0x33,0xD3,0xB3,0xF1,0x80,0x31,0x6E,0x5B,
                      0xCA,0xB9,0x2C,0x93,0x3F,0x0E,0x4D,0xBC];
    let ybytes = vec![0x66,0x70,0x98,0xC6,0x54,0x42,0x6C,0x78,
                      0xD7,0xF8,0x20,0x1E,0xAC,0x6C,0x20,0x3E,
                      0xF0,0x30,0xD4,0x36,0x05,0x03,0x2C,0x2F,
                      0x1F,0xA9,0x37,0xE5,0x23,0x7D,0xBD,0x94,
                      0x9F,0x34,0xA0,0xA2,0x56,0x4F,0xE1,0x26,
                      0xDC,0x8B,0x71,0x5C,0x51,0x41,0x80,0x2C,
                      0xE0,0x97,0x9C,0x82,0x46,0x46,0x3C,0x40,
                      0xE6,0xB6,0xBD,0xAA,0x25,0x13,0xFA,0x61,
                      0x17,0x28,0x71,0x6C,0x2E,0x4F,0xD5,0x3B,
                      0xC9,0x5B,0x89,0xE6,0x99,0x49,0xD9,0x65,
                      0x12,0xE8,0x73,0xB9,0xC8,0xF8,0xDF,0xD4,
                      0x99,0xCC,0x31,0x28,0x82,0x56,0x1A,0xDE,
                      0xCB,0x31,0xF6,0x58,0xE9,0x34,0xC0,0xC1,
                      0x97,0xF2,0xC4,0xD9,0x6B,0x05,0xCB,0xAD,
                      0x67,0x38,0x1E,0x7B,0x76,0x88,0x91,0xE4,
                      0xDA,0x38,0x43,0xD2,0x4D,0x94,0xCD,0xFB,
                      0x51,0x26,0xE9,0xB8,0xBF,0x21,0xE8,0x35,
                      0x8E,0xE0,0xE0,0xA3,0x0E,0xF1,0x3F,0xD6,
                      0xA6,0x64,0xC0,0xDC,0xE3,0x73,0x1F,0x7F,
                      0xB4,0x9A,0x48,0x45,0xA4,0xFD,0x82,0x54,
                      0x68,0x79,0x72,0xA2,0xD3,0x82,0x59,0x9C,
                      0x9B,0xAC,0x4E,0x0E,0xD7,0x99,0x81,0x93,
                      0x07,0x89,0x13,0x03,0x25,0x58,0x13,0x49,
                      0x76,0x41,0x0B,0x89,0xD2,0xC1,0x71,0xD1,
                      0x23,0xAC,0x35,0xFD,0x97,0x72,0x19,0x59,
                      0x7A,0xA7,0xD1,0x5C,0x1A,0x9A,0x42,0x8E,
                      0x59,0x19,0x4F,0x75,0xC7,0x21,0xEB,0xCB,
                      0xCF,0xAE,0x44,0x69,0x6A,0x49,0x9A,0xFA,
                      0x74,0xE0,0x42,0x99,0xF1,0x32,0x02,0x66,
                      0x01,0x63,0x8C,0xB8,0x7A,0xB7,0x91,0x90,
                      0xD4,0xA0,0x98,0x63,0x15,0xDA,0x8E,0xEC,
                      0x65,0x61,0xC9,0x38,0x99,0x6B,0xEA,0xDF];
    //
    let p = U2048::from_bytes(&pbytes);
    let q = U256::from_bytes(&qbytes);
    let g = U2048::from_bytes(&gbytes);
    let params = L2048N256::new(p, g, q);
    let x = U256::from_bytes(&xbytes);
    let y = U2048::from_bytes(&ybytes);
    let private = DSAPrivKey::<L2048N256,U256>::new(params.clone(), x);
    let public = DSAPubKey::<L2048N256,U2048>::new(params.clone(), y);
    //
    let sample: [u8; 6] = [115, 97, 109, 112, 108, 101]; // "sample", ASCII
    let test:   [u8; 4] = [116, 101, 115, 116]; // "test", ASCII
    // With SHA-1, message = "sample":
    // k = 888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53E
    // r = 3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A
    // s = D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF
    run_rfc6979_test!(Sha1, U256, sample, params, public, private,
        k vec![0x88,0x8F,0xA6,0xF7,0x73,0x8A,0x41,0xBD,
               0xC9,0x84,0x64,0x66,0xAB,0xDB,0x81,0x74,
               0xC0,0x33,0x82,0x50,0xAE,0x50,0xCE,0x95,
               0x5C,0xA1,0x62,0x30,0xF9,0xCB,0xD5,0x3E],
        r vec![0x3A,0x1B,0x2D,0xBD,0x74,0x89,0xD6,0xED,
               0x7E,0x60,0x8F,0xD0,0x36,0xC8,0x3A,0xF3,
               0x96,0xE2,0x90,0xDB,0xD6,0x02,0x40,0x8E,
               0x86,0x77,0xDA,0xAB,0xD6,0xE7,0x44,0x5A],
        s vec![0xD2,0x6F,0xCB,0xA1,0x9F,0xA3,0xE3,0x05,
               0x8F,0xFC,0x02,0xCA,0x15,0x96,0xCD,0xBB,
               0x6E,0x0D,0x20,0xCB,0x37,0xB0,0x60,0x54,
               0xF7,0xE3,0x6D,0xED,0x0C,0xDB,0xBC,0xCF]);
    // With SHA-224, message = "sample":
    // k = BC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806
    // r = DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C
    // s = A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC
    run_rfc6979_test!(Sha224, U256, sample, params, public, private,
        k vec![0xBC,0x37,0x29,0x67,0x70,0x20,0x82,0xE1,
               0xAA,0x4F,0xCE,0x89,0x22,0x09,0xF7,0x1A,
               0xE4,0xAD,0x25,0xA6,0xDF,0xD8,0x69,0x33,
               0x4E,0x6F,0x15,0x3B,0xD0,0xC4,0xD8,0x06],
        r vec![0xDC,0x9F,0x4D,0xEA,0xDA,0x8D,0x8F,0xF5,
               0x88,0xE9,0x8F,0xED,0x0A,0xB6,0x90,0xFF,
               0xCE,0x85,0x8D,0xC8,0xC7,0x93,0x76,0x45,
               0x0E,0xB6,0xB7,0x6C,0x24,0x53,0x7E,0x2C],
        s vec![0xA6,0x5A,0x9C,0x3B,0xC7,0xBA,0xBE,0x28,
               0x6B,0x19,0x5D,0x5D,0xA6,0x86,0x16,0xDA,
               0x8D,0x47,0xFA,0x00,0x97,0xF3,0x6D,0xD1,
               0x9F,0x51,0x73,0x27,0xDC,0x84,0x8C,0xEC]);
    // With SHA-256, message = "sample":
    // k = 8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52
    // r = EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809
    // s = 7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53
    run_rfc6979_test!(Sha256, U256, sample, params, public, private,
        k vec![0x89,0x26,0xA2,0x7C,0x40,0x48,0x42,0x16,
               0xF0,0x52,0xF4,0x42,0x7C,0xFD,0x56,0x47,
               0x33,0x8B,0x7B,0x39,0x39,0xBC,0x65,0x73,
               0xAF,0x43,0x33,0x56,0x9D,0x59,0x7C,0x52],
        r vec![0xEA,0xCE,0x8B,0xDB,0xBE,0x35,0x3C,0x43,
               0x2A,0x79,0x5D,0x9E,0xC5,0x56,0xC6,0xD0,
               0x21,0xF7,0xA0,0x3F,0x42,0xC3,0x6E,0x9B,
               0xC8,0x7E,0x4A,0xC7,0x93,0x2C,0xC8,0x09],
        s vec![0x70,0x81,0xE1,0x75,0x45,0x5F,0x92,0x47,
               0xB8,0x12,0xB7,0x45,0x83,0xE9,0xE9,0x4F,
               0x9E,0xA7,0x9B,0xD6,0x40,0xDC,0x96,0x25,
               0x33,0xB0,0x68,0x07,0x93,0xA3,0x8D,0x53]);
    // With SHA-384, message = "sample":
    // k = C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920
    // r = B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B
    // s = 19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B
    run_rfc6979_test!(Sha384, U256, sample, params, public, private,
        k vec![0xC3,0x45,0xD5,0xAB,0x3D,0xA0,0xA5,0xBC,
               0xB7,0xEC,0x8F,0x8F,0xB7,0xA7,0xE9,0x60,
               0x69,0xE0,0x3B,0x20,0x63,0x71,0xEF,0x7D,
               0x83,0xE3,0x90,0x68,0xEC,0x56,0x49,0x20],
        r vec![0xB2,0xDA,0x94,0x5E,0x91,0x85,0x88,0x34,
               0xFD,0x9B,0xF6,0x16,0xEB,0xAC,0x15,0x1E,
               0xDB,0xC4,0xB4,0x5D,0x27,0xD0,0xDD,0x4A,
               0x7F,0x6A,0x22,0x73,0x9F,0x45,0xC0,0x0B],
        s vec![0x19,0x04,0x8B,0x63,0xD9,0xFD,0x6B,0xCA,
               0x1D,0x9B,0xAE,0x36,0x64,0xE1,0xBC,0xB9,
               0x7F,0x72,0x76,0xC3,0x06,0x13,0x09,0x69,
               0xF6,0x3F,0x38,0xFA,0x83,0x19,0x02,0x1B]);
    // With SHA-512, message = "sample":
    // k = 5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC
    // r = 2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E
    // s = D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351
    run_rfc6979_test!(Sha512, U256, sample, params, public, private,
        k vec![0x5A,0x12,0x99,0x44,0x31,0x78,0x54,0x85,
               0xB3,0xF5,0xF0,0x67,0x22,0x15,0x17,0x79,
               0x1B,0x85,0xA5,0x97,0xB7,0xA9,0x43,0x69,
               0x95,0xC8,0x9E,0xD0,0x37,0x46,0x68,0xFC],
        r vec![0x20,0x16,0xED,0x09,0x2D,0xC5,0xFB,0x66,
               0x9B,0x8E,0xFB,0x3D,0x1F,0x31,0xA9,0x1E,
               0xEC,0xB1,0x99,0x87,0x9B,0xE0,0xCF,0x78,
               0xF0,0x2B,0xA0,0x62,0xCB,0x4C,0x94,0x2E],
        s vec![0xD0,0xC7,0x6F,0x84,0xB5,0xF0,0x91,0xE1,
               0x41,0x57,0x2A,0x63,0x9A,0x4F,0xB8,0xC2,
               0x30,0x80,0x7E,0xEA,0x7D,0x55,0xC8,0xA1,
               0x54,0xA2,0x24,0x40,0x0A,0xFF,0x23,0x51]);
    // With SHA-1, message = "test":
    // k = 6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4F
    // r = C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0
    // s = 414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA
    run_rfc6979_test!(Sha1, U256, test, params, public, private,
        k vec![0x6E,0xEA,0x48,0x6F,0x9D,0x41,0xA0,0x37,
               0xB2,0xC6,0x40,0xBC,0x56,0x45,0x69,0x4F,
               0xF8,0xFF,0x4B,0x98,0xD0,0x66,0xA2,0x5F,
               0x76,0xBE,0x64,0x1C,0xCB,0x24,0xBA,0x4F],
        r vec![0xC1,0x82,0x70,0xA9,0x3C,0xFC,0x60,0x63,
               0xF5,0x7A,0x4D,0xFA,0x86,0x02,0x4F,0x70,
               0x0D,0x98,0x0E,0x4C,0xF4,0xE2,0xCB,0x65,
               0xA5,0x04,0x39,0x72,0x73,0xD9,0x8E,0xA0],
        s vec![0x41,0x4F,0x22,0xE5,0xF3,0x1A,0x8B,0x6D,
               0x33,0x29,0x5C,0x75,0x39,0xC1,0xC1,0xBA,
               0x3A,0x61,0x60,0xD7,0xD6,0x8D,0x50,0xAC,
               0x0D,0x3A,0x5B,0xEA,0xC2,0x88,0x4F,0xAA]);
    // With SHA-224, message = "test":
    // k = 06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670
    // r = 272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3
    // s = E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806
    run_rfc6979_test!(Sha224, U256, test, params, public, private,
        k vec![0x06,0xBD,0x4C,0x05,0xED,0x74,0x71,0x91,
               0x06,0x22,0x3B,0xE3,0x3F,0x2D,0x95,0xDA,
               0x6B,0x3B,0x54,0x1D,0xAD,0x7B,0xFB,0xD7,
               0xAC,0x50,0x82,0x13,0xB6,0xDA,0x66,0x70],
        r vec![0x27,0x2A,0xBA,0x31,0x57,0x2F,0x6C,0xC5,
               0x5E,0x30,0xBF,0x61,0x6B,0x7A,0x26,0x53,
               0x12,0x01,0x8D,0xD3,0x25,0xBE,0x03,0x1B,
               0xE0,0xCC,0x82,0xAA,0x17,0x87,0x0E,0xA3],
        s vec![0xE9,0xCC,0x28,0x6A,0x52,0xCC,0xE2,0x01,
               0x58,0x67,0x22,0xD3,0x6D,0x1E,0x91,0x7E,
               0xB9,0x6A,0x4E,0xBD,0xB4,0x79,0x32,0xF9,
               0x57,0x6A,0xC6,0x45,0xB3,0xA6,0x08,0x06]);
    // With SHA-256, message = "test":
    // k = 1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7
    // r = 8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0
    // s = 7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E
    run_rfc6979_test!(Sha256, U256, test, params, public, private,
        k vec![0x1D,0x6C,0xE6,0xDD,0xA1,0xC5,0xD3,0x73,
               0x07,0x83,0x9C,0xD0,0x3A,0xB0,0xA5,0xCB,
               0xB1,0x8E,0x60,0xD8,0x00,0x93,0x7D,0x67,
               0xDF,0xB4,0x47,0x9A,0xAC,0x8D,0xEA,0xD7],
        r vec![0x81,0x90,0x01,0x2A,0x19,0x69,0xF9,0x95,
               0x7D,0x56,0xFC,0xCA,0xAD,0x22,0x31,0x86,
               0xF4,0x23,0x39,0x8D,0x58,0xEF,0x5B,0x3C,
               0xEF,0xD5,0xA4,0x14,0x6A,0x44,0x76,0xF0],
        s vec![0x74,0x52,0xA5,0x3F,0x70,0x75,0xD4,0x17,
               0xB4,0xB0,0x13,0xB2,0x78,0xD1,0xBB,0x8B,
               0xBD,0x21,0x86,0x3F,0x5E,0x7B,0x1C,0xEE,
               0x67,0x9C,0xF2,0x18,0x8E,0x1A,0xB1,0x9E]);
    // With SHA-384, message = "test":
    // k = 206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C
    // r = 239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE
    // s = 6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961
    run_rfc6979_test!(Sha384, U256, test, params, public, private,
        k vec![0x20,0x6E,0x61,0xF7,0x3D,0xBE,0x1B,0x2D,
               0xC8,0xBE,0x73,0x6B,0x22,0xB0,0x79,0xE9,
               0xDA,0xCD,0x97,0x4D,0xB0,0x0E,0xEB,0xBC,
               0x5B,0x64,0xCA,0xD3,0x9C,0xF9,0xF9,0x1C],
        r vec![0x23,0x9E,0x66,0xDD,0xBE,0x8F,0x8C,0x23,
               0x0A,0x3D,0x07,0x1D,0x60,0x1B,0x6F,0xFB,
               0xDF,0xB5,0x90,0x1F,0x94,0xD4,0x44,0xC6,
               0xAF,0x56,0xF7,0x32,0xBE,0xB9,0x54,0xBE],
        s vec![0x6B,0xD7,0x37,0x51,0x3D,0x5E,0x72,0xFE,
               0x85,0xD1,0xC7,0x50,0xE0,0xF7,0x39,0x21,
               0xFE,0x29,0x9B,0x94,0x5A,0xAD,0x1C,0x80,
               0x2F,0x15,0xC2,0x6A,0x43,0xD3,0x49,0x61]);
    // With SHA-512, message = "test":
    // k = AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA
    // r = 89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307
    // s = C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1
    run_rfc6979_test!(Sha512, U256, test, params, public, private,
        k vec![0xAF,0xF1,0x65,0x1E,0x4C,0xD6,0x03,0x6D,
               0x57,0xAA,0x8B,0x2A,0x05,0xCC,0xF1,0xA9,
               0xD5,0xA4,0x01,0x66,0x34,0x0E,0xCB,0xBD,
               0xC5,0x5B,0xE1,0x0B,0x56,0x8A,0xA0,0xAA],
        r vec![0x89,0xEC,0x4B,0xB1,0x40,0x0E,0xCC,0xFF,
               0x8E,0x7D,0x9A,0xA5,0x15,0xCD,0x1D,0xE7,
               0x80,0x3F,0x2D,0xAF,0xF0,0x96,0x93,0xEE,
               0x7F,0xD1,0x35,0x3E,0x90,0xA6,0x83,0x07],
        s vec![0xC9,0xF0,0xBD,0xAB,0xCC,0x0D,0x88,0x0B,
               0xB1,0x37,0xA9,0x94,0xCC,0x7F,0x39,0x80,
               0xCE,0x91,0xCC,0x10,0xFA,0xF5,0x29,0xFC,
               0x46,0x56,0x5B,0x15,0xCE,0xA8,0x54,0xE1]);
}