use cryptonum::{SCN,UCN};

#[allow(non_snake_case)]
#[derive(Clone,Debug,PartialEq)]
pub struct EllipticCurve {
    pub p: UCN,
    pub n: UCN,
    pub SEED: UCN,
    pub c: UCN,
    pub a: UCN,
    pub b: UCN,
    pub Gx: SCN,
    pub Gy: SCN
}

impl EllipticCurve {
    /// Create a new elliptic curve structure that represents NIST's
    /// p192 curve.
    pub fn p192() -> EllipticCurve {
        EllipticCurve {
            p:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            n:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0x99, 0xde, 0xf8, 0x36,
                        0x14, 0x6b, 0xc9, 0xb1, 0xb4, 0xd2, 0x28, 0x31]),
            SEED:   UCN::from_bytes(&vec![
                        0x30, 0x45, 0xae, 0x6f, 0xc8, 0x42, 0x2f, 0x64,
                        0xed, 0x57, 0x95, 0x28, 0xd3, 0x81, 0x20, 0xea,
                        0xe1, 0x21, 0x96, 0xd5]),
            c:      UCN::from_bytes(&vec![
                        0x30, 0x99, 0xd2, 0xbb, 0xbf, 0xcb, 0x25, 0x38,
                        0x54, 0x2d, 0xcd, 0x5f, 0xb0, 0x78, 0xb6, 0xef,
                        0x5f, 0x3d, 0x6f, 0xe2, 0xc7, 0x45, 0xde, 0x65]),
            a:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc]),
            b:      UCN::from_bytes(&vec![
                        0x64, 0x21, 0x05, 0x19, 0xe5, 0x9c, 0x80, 0xe7,
                        0x0f, 0xa7, 0xe9, 0xab, 0x72, 0x24, 0x30, 0x49,
                        0xfe, 0xb8, 0xde, 0xec, 0xc1, 0x46, 0xb9, 0xb1]),
            Gx:     SCN::from(UCN::from_bytes(&vec![
                        0x18, 0x8d, 0xa8, 0x0e, 0xb0, 0x30, 0x90, 0xf6,
                        0x7c, 0xbf, 0x20, 0xeb, 0x43, 0xa1, 0x88, 0x00,
                        0xf4, 0xff, 0x0a, 0xfd, 0x82, 0xff, 0x10, 0x12])),
            Gy:     SCN::from(UCN::from_bytes(&vec![
                        0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78,
                        0x63, 0x10, 0x11, 0xed, 0x6b, 0x24, 0xcd, 0xd5,
                        0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11]))
        }
    }

    /// Create a new elliptic curve structure that represents NIST's
    /// p224 curve.
    pub fn p224() -> EllipticCurve {
        EllipticCurve {
            p:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01]),
            n:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16, 0xa2,
                        0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45,
                        0x5c, 0x5c, 0x2a, 0x3d]),
            SEED:   UCN::from_bytes(&vec![
                        0xbd, 0x71, 0x34, 0x47, 0x99, 0xd5, 0xc7, 0xfc,
                        0xdc, 0x45, 0xb5, 0x9f, 0xa3, 0xb9, 0xab, 0x8f,
                        0x6a, 0x94, 0x8b, 0xc5]),
            c:      UCN::from_bytes(&vec![
                        0x5b, 0x05, 0x6c, 0x7e, 0x11, 0xdd, 0x68, 0xf4,
                        0x04, 0x69, 0xee, 0x7f, 0x3c, 0x7a, 0x7d, 0x74,
                        0xf7, 0xd1, 0x21, 0x11, 0x65, 0x06, 0xd0, 0x31,
                        0x21, 0x82, 0x91, 0xfb]),
            a:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xfe]),
            b:      UCN::from_bytes(&vec![
                        0xb4, 0x05, 0x0a, 0x85, 0x0c, 0x04, 0xb3, 0xab,
                        0xf5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xb0, 0xb7,
                        0xd7, 0xbf, 0xd8, 0xba, 0x27, 0x0b, 0x39, 0x43,
                        0x23, 0x55, 0xff, 0xb4]),
            Gx:     SCN::from(UCN::from_bytes(&vec![
                        0xb7, 0x0e, 0x0c, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f,
                        0x32, 0x13, 0x90, 0xb9, 0x4a, 0x03, 0xc1, 0xd3,
                        0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6,
                        0x11, 0x5c, 0x1d, 0x21])),
            Gy:     SCN::from(UCN::from_bytes(&vec![
                        0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb,
                        0x4c, 0x22, 0xdf, 0xe6, 0xcd, 0x43, 0x75, 0xa0,
                        0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
                        0x85, 0x00, 0x7e, 0x34]))
        }
    }

    /// Create a new elliptic curve structure that represents NIST's
    /// p256 curve.
    pub fn p256() -> EllipticCurve {
        EllipticCurve {
            p:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            n:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51]),
            SEED:   UCN::from_bytes(&vec![
                        0xc4, 0x9d, 0x36, 0x08, 0x86, 0xe7, 0x04, 0x93,
                        0x6a, 0x66, 0x78, 0xe1, 0x13, 0x9d, 0x26, 0xb7,
                        0x81, 0x9f, 0x7e, 0x90]),
            c:      UCN::from_bytes(&vec![
                        0x7e, 0xfb, 0xa1, 0x66, 0x29, 0x85, 0xbe, 0x94,
                        0x03, 0xcb, 0x05, 0x5c, 0x75, 0xd4, 0xf7, 0xe0,
                        0xce, 0x8d, 0x84, 0xa9, 0xc5, 0x11, 0x4a, 0xbc,
                        0xaf, 0x31, 0x77, 0x68, 0x01, 0x04, 0xfa, 0x0d]),
            a:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc]),
            b:      UCN::from_bytes(&vec![
                        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
                        0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
                        0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
                        0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b]),
            Gx:     SCN::from(UCN::from_bytes(&vec![
                        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                        0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96])),
            Gy:     SCN::from(UCN::from_bytes(&vec![
                        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
                        0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                        0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5]))
        }
    }

    /// Create a new elliptic curve structure that represents NIST's
    /// p256 curve.
    pub fn p384() -> EllipticCurve {
        EllipticCurve {
            p:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]),
            n:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
                        0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
                        0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73]),
            SEED:   UCN::from_bytes(&vec![
                        0xa3, 0x35, 0x92, 0x6a, 0xa3, 0x19, 0xa2, 0x7a,
                        0x1d, 0x00, 0x89, 0x6a, 0x67, 0x73, 0xa4, 0x82,
                        0x7a, 0xcd, 0xac, 0x73]),
            c:      UCN::from_bytes(&vec![
                        0x79, 0xd1, 0xe6, 0x55, 0xf8, 0x68, 0xf0, 0x2f,
                        0xff, 0x48, 0xdc, 0xde, 0xe1, 0x41, 0x51, 0xdd,
                        0xb8, 0x06, 0x43, 0xc1, 0x40, 0x6d, 0x0c, 0xa1,
                        0x0d, 0xfe, 0x6f, 0xc5, 0x20, 0x09, 0x54, 0x0a,
                        0x49, 0x5e, 0x80, 0x42, 0xea, 0x5f, 0x74, 0x4f,
                        0x6e, 0x18, 0x46, 0x67, 0xcc, 0x72, 0x24, 0x83]),
            a:      UCN::from_bytes(&vec![
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc]),
            b:      UCN::from_bytes(&vec![
                        0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4,
                        0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
                        0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                        0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
                        0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d,
                        0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef]),
            Gx:     SCN::from(UCN::from_bytes(&vec![
                        0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
                        0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
                        0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                        0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
                        0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c,
                        0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7])),
            Gy:     SCN::from(UCN::from_bytes(&vec![
                        0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
                        0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
                        0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                        0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
                        0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
                        0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f]))
        }
    }

    /// Create a new elliptic curve structure that represents NIST's
    /// p256 curve.
    pub fn p521() -> EllipticCurve {
        EllipticCurve {
            p:      UCN::from_bytes(&vec![
                        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff]),
            n:      UCN::from_bytes(&vec![
                        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
                        0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
                        0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
                        0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
                        0x64, 0x09]),
            SEED:   UCN::from_bytes(&vec![
                        0xd0, 0x9e, 0x88, 0x00, 0x29, 0x1c, 0xb8, 0x53,
                        0x96, 0xcc, 0x67, 0x17, 0x39, 0x32, 0x84, 0xaa,
                        0xa0, 0xda, 0x64, 0xba]),
            c:      UCN::from_bytes(&vec![
                        0xb4, 0x8b, 0xfa, 0x5f, 0x42, 0x0a, 0x34, 0x94,
                        0x95, 0x39, 0xd2, 0xbd, 0xfc, 0x26, 0x4e, 0xee,
                        0xeb, 0x07, 0x76, 0x88, 0xe4, 0x4f, 0xbf, 0x0a,
                        0xd8, 0xf6, 0xd0, 0xed, 0xb3, 0x7b, 0xd6, 0xb5,
                        0x33, 0x28, 0x10, 0x00, 0x51, 0x8e, 0x19, 0xf1,
                        0xb9, 0xff, 0xbe, 0x0f, 0xe9, 0xed, 0x8a, 0x3c,
                        0x22, 0x00, 0xb8, 0xf8, 0x75, 0xe5, 0x23, 0x86,
                        0x8c, 0x70, 0xc1, 0xe5, 0xbf, 0x55, 0xba, 0xd6,
                        0x37]),
            a:      UCN::from_bytes(&vec![
                        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xfc]),
            b:      UCN::from_bytes(&vec![
                        0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a,
                        0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40,
                        0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15,
                        0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09,
                        0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93,
                        0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf,
                        0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34,
                        0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f,
                        0x00]),
            Gx:     SCN::from(UCN::from_bytes(&vec![
                        0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9,
                        0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23, 0x95, 0xb4,
                        0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5,
                        0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d,
                        0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59,
                        0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8,
                        0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42,
                        0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd,
                        0x66])),
            Gy:     SCN::from(UCN::from_bytes(&vec![
                        0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0,
                        0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d, 0x1b,
                        0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44,
                        0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66,
                        0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26,
                        0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07,
                        0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2,
                        0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66,
                        0x50]))
        }
    }
}


