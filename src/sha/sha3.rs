use super::super::Hash;

pub(crate) struct Keccak {
    rate_in_bytes: usize,
    rate_in_longs: usize,
    buffer: Vec<u8>,
    state: [u64; 25], // This is Keccak-f[1600]
    output: Option<Vec<u8>>
}

const KECCAK_ROUND_CONSTANTS: [u64; 24] =
  [ 0x0000000000000001u64, 0x0000000000008082u64,
    0x800000000000808au64, 0x8000000080008000u64,
    0x000000000000808bu64, 0x0000000080000001u64,
    0x8000000080008081u64, 0x8000000000008009u64,
    0x000000000000008au64, 0x0000000000000088u64,
    0x0000000080008009u64, 0x000000008000000au64,
    0x000000008000808bu64, 0x800000000000008bu64,
    0x8000000000008089u64, 0x8000000000008003u64,
    0x8000000000008002u64, 0x8000000000000080u64,
    0x000000000000800au64, 0x800000008000000au64,
    0x8000000080008081u64, 0x8000000000008080u64,
    0x0000000080000001u64, 0x8000000080008008u64,
  ];

macro_rules! absorb {
    ($self: ident, $block: expr, $sidx: expr) => {{
        let mut i = 0;
        let mut off = 0;

        while i < $self.rate_in_longs {
            let word = ($block[$sidx+off+0] as u64) << 00 |
                       ($block[$sidx+off+1] as u64) << 08 |
                       ($block[$sidx+off+2] as u64) << 16 |
                       ($block[$sidx+off+3] as u64) << 24 |
                       ($block[$sidx+off+4] as u64) << 32 |
                       ($block[$sidx+off+5] as u64) << 40 |
                       ($block[$sidx+off+6] as u64) << 48 |
                       ($block[$sidx+off+7] as u64) << 56;
            $self.state[i] ^= word;
            off += 8;
            i += 1; 
        }

        $self.permute(); 
    }};
}

impl Keccak {
    pub fn new(rate: usize) -> Self
    {
        assert_eq!(rate % 64, 0);
        Keccak {
            rate_in_bytes: rate / 8,
            rate_in_longs: rate / 64,
            buffer: Vec::with_capacity(rate),
            state: [0; 25],
            output: None,
        }
    }

    fn permute(&mut self)
    {
        // This is a translation of the very easy-to-read implementation in BouncyCastle
        for i in 0..24 {
            // Theta!
            let c0 = self.state[0] ^ self.state[5] ^ self.state[10] ^ self.state[15] ^ self.state[20];
            let c1 = self.state[1] ^ self.state[6] ^ self.state[11] ^ self.state[16] ^ self.state[21];
            let c2 = self.state[2] ^ self.state[7] ^ self.state[12] ^ self.state[17] ^ self.state[22];
            let c3 = self.state[3] ^ self.state[8] ^ self.state[13] ^ self.state[18] ^ self.state[23];
            let c4 = self.state[4] ^ self.state[9] ^ self.state[14] ^ self.state[19] ^ self.state[24];
            let d0 = c0.rotate_left(1) ^ c3;
            let d1 = c1.rotate_left(1) ^ c4;
            let d2 = c2.rotate_left(1) ^ c0;
            let d3 = c3.rotate_left(1) ^ c1;
            let d4 = c4.rotate_left(1) ^ c2;
            self.state[0] ^= d1; self.state[5] ^= d1; self.state[10] ^= d1; self.state[15] ^= d1; self.state[20] ^= d1;  
            self.state[1] ^= d2; self.state[6] ^= d2; self.state[11] ^= d2; self.state[16] ^= d2; self.state[21] ^= d2;  
            self.state[2] ^= d3; self.state[7] ^= d3; self.state[12] ^= d3; self.state[17] ^= d3; self.state[22] ^= d3;  
            self.state[3] ^= d4; self.state[8] ^= d4; self.state[13] ^= d4; self.state[18] ^= d4; self.state[23] ^= d4;  
            self.state[4] ^= d0; self.state[9] ^= d0; self.state[14] ^= d0; self.state[19] ^= d0; self.state[24] ^= d0;
            // Rho & Pi!
            let t1 = self.state[01].rotate_left(1);
            self.state[01] = self.state[06].rotate_left(44);
            self.state[06] = self.state[09].rotate_left(20);
            self.state[09] = self.state[22].rotate_left(61);
            self.state[22] = self.state[14].rotate_left(39);
            self.state[14] = self.state[20].rotate_left(18);
            self.state[20] = self.state[02].rotate_left(62);
            self.state[02] = self.state[12].rotate_left(43);
            self.state[12] = self.state[13].rotate_left(25);
            self.state[13] = self.state[19].rotate_left(8);
            self.state[19] = self.state[23].rotate_left(56);
            self.state[23] = self.state[15].rotate_left(41);
            self.state[15] = self.state[04].rotate_left(27);
            self.state[04] = self.state[24].rotate_left(14);
            self.state[24] = self.state[21].rotate_left(2);
            self.state[21] = self.state[08].rotate_left(55);
            self.state[08] = self.state[16].rotate_left(45);
            self.state[16] = self.state[05].rotate_left(36);
            self.state[05] = self.state[03].rotate_left(28);
            self.state[03] = self.state[18].rotate_left(21);
            self.state[18] = self.state[17].rotate_left(15);
            self.state[17] = self.state[11].rotate_left(10);
            self.state[11] = self.state[07].rotate_left(6);
            self.state[07] = self.state[10].rotate_left(3);
            self.state[10] = t1;
            // Chi!
            let t2 = self.state[00] ^ (!self.state[01] & self.state[02]);
            let t3 = self.state[01] ^ (!self.state[02] & self.state[03]);
            self.state[02] ^= !self.state[03] & self.state[04];
            self.state[03] ^= !self.state[04] & self.state[00];
            self.state[04] ^= !self.state[00] & self.state[01];
            self.state[00] = t2;
            self.state[01] = t3;

            let t4 = self.state[05] ^ (!self.state[06] & self.state[07]);
            let t5 = self.state[06] ^ (!self.state[07] & self.state[08]);
            self.state[07] ^= !self.state[08] & self.state[09];
            self.state[08] ^= !self.state[09] & self.state[05];
            self.state[09] ^= !self.state[05] & self.state[06];
            self.state[05] = t4;
            self.state[06] = t5;

            let t6 = self.state[10] ^ (!self.state[11] & self.state[12]);
            let t7 = self.state[11] ^ (!self.state[12] & self.state[13]);
            self.state[12] ^= !self.state[13] & self.state[14];
            self.state[13] ^= !self.state[14] & self.state[10];
            self.state[14] ^= !self.state[10] & self.state[11];
            self.state[10] = t6;
            self.state[11] = t7;

            let t8 = self.state[15] ^ (!self.state[16] & self.state[17]);
            let t9 = self.state[16] ^ (!self.state[17] & self.state[18]);
            self.state[17] ^= !self.state[18] & self.state[19];
            self.state[18] ^= !self.state[19] & self.state[15];
            self.state[19] ^= !self.state[15] & self.state[16];
            self.state[15] = t8;
            self.state[16] = t9;

            let ta = self.state[20] ^ (!self.state[21] & self.state[22]);
            let tb = self.state[21] ^ (!self.state[22] & self.state[23]);
            self.state[22] ^= !self.state[23] & self.state[24];
            self.state[23] ^= !self.state[24] & self.state[20];
            self.state[24] ^= !self.state[20] & self.state[21];
            self.state[20] = ta;
            self.state[21] = tb;

            // iota
            self.state[00] ^= KECCAK_ROUND_CONSTANTS[i];
        }
    }

    pub fn process(&mut self, bytes: &[u8])
    {
        if self.output.is_none() {
            let mut offset = 0;

            if self.buffer.len() + bytes.len() < self.rate_in_bytes {
                self.buffer.extend_from_slice(bytes);
                return;
            }

            if self.buffer.len() > 0 {
                // We must be able to build up a chunk at our absorbtion rate, at this
                // point, otherwise the math above would've been wrong.
                while self.buffer.len() < self.rate_in_bytes {
                    self.buffer.push(bytes[offset]);
                    offset += 1;
                }
                absorb!(self, self.buffer, 0);
                // Reset the buffer now, we're done with that nonsense for the moment
                self.buffer.resize(0,0);
            }

            while (offset + self.rate_in_bytes) <= bytes.len() {
                absorb!(self, bytes, offset);
                offset += self.rate_in_bytes;
            }

            if offset < bytes.len() {
                self.buffer.extend_from_slice(&bytes[offset..]);
            }
        }
    }

    pub fn tag_and_pad(&mut self, tag_byte: u8)
    {
        if self.output.is_none() {
            assert!(self.buffer.len() < self.rate_in_bytes);
            // what we need to do here is tag on a final 01, to tag that as SHA3,
            // and then pad it out, with an 0x80 at the end.
            self.buffer.push(tag_byte);
            self.buffer.resize(self.rate_in_bytes, 0);
            self.buffer[self.rate_in_bytes-1] |= 0x80;
            absorb!(self, self.buffer, 0);
        }
    }

    pub fn squeeze(&mut self, output_len: usize) -> Vec<u8>
    {
        if let Some(ref result) = self.output {
            result.clone()
        } else {
            let mut res = Vec::new();

            while res.len() < output_len {
                for i in 0..self.rate_in_longs {
                    res.push( (self.state[i] >> 00) as u8 );
                    res.push( (self.state[i] >> 08) as u8 );
                    res.push( (self.state[i] >> 16) as u8 );
                    res.push( (self.state[i] >> 24) as u8 );
                    res.push( (self.state[i] >> 32) as u8 );
                    res.push( (self.state[i] >> 40) as u8 );
                    res.push( (self.state[i] >> 48) as u8 );
                    res.push( (self.state[i] >> 56) as u8 );
                }
                self.permute();
            }

            res.resize(output_len, 0);
            self.output = Some(res.clone());
            res
        }
    }
}

/// The SHA3-224 hash.
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA3_224};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA3_224::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA3_224::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA3_224 {
    state: Keccak
}

impl Hash for SHA3_224 {
    fn new() -> Self
    {
        SHA3_224{ state: Keccak::new(1600 - 448) }
    }

    fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        self.state.tag_and_pad(0x06);
        self.state.squeeze(224 / 8)
    }

    fn block_size() -> usize
    {
        1152
    }
}

#[cfg(test)]
mod sha224 {
    use super::*;
    use testing::run_test;

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg0.pdf
    #[test]
    fn nist_empty_example() {
        let empty = [0; 0];
        let hashres = [0x6B,0x4E,0x03,0x42,0x36,0x67,0xDB,0xB7,0x3B,0x6E,0x15,
                       0x45,0x4F,0x0E,0xB1,0xAB,0xD4,0x59,0x7F,0x9A,0x1B,0x07,
                       0x8E,0x3F,0x5B,0x5A,0x6B,0xC7];
        let mine = SHA3_224::hash(&empty);
        assert_eq!(hashres.to_vec(), mine);
    }

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1600.pdf
    #[test]
    fn nist_1600_example() {
        let example = [0xA3; 200];
        let hashres = [0x93,0x76,0x81,0x6A,0xBA,0x50,0x3F,0x72,
                       0xF9,0x6C,0xE7,0xEB,0x65,0xAC,0x09,0x5D,
                       0xEE,0xE3,0xBE,0x4B,0xF9,0xBB,0xC2,0xA1,
                       0xCB,0x7E,0x11,0xE0];
        let mine = SHA3_224::hash(&example);
        assert_eq!(hashres.to_vec(), mine);
    }

    #[cfg(test)]
    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/sha/nist_sha3_224.test";
        run_test(fname.to_string(), 3, |case| {
            let (negl, lbytes) = case.get("l").unwrap();
            let (negm, mbytes) = case.get("m").unwrap();
            let (negd, dbytes) = case.get("d").unwrap();

            assert!(!negl && !negm && !negd);
            let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
            let digest = SHA3_224::hash(&msg);
            assert_eq!(dbytes, &digest);
        });
    }
}

/// The SHA3-256 hash. [GOOD]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA3_256};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA3_256::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA3_256::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA3_256 {
    state: Keccak
}

impl Hash for SHA3_256 {
    fn new() -> Self
    {
        SHA3_256{ state: Keccak::new(1600 - 512) }
    }

    fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        self.state.tag_and_pad(0x06);
        self.state.squeeze(256 / 8)
    }

    fn block_size() -> usize
    {
        1088
    }
}

#[cfg(test)]
mod sha256 {
    use super::*;
    use testing::run_test;

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256.pdf
    #[test]
    fn nist_empty_example() {
        let empty = [0; 0];
        let hashres = [0xA7,0xFF,0xC6,0xF8,0xBF,0x1E,0xD7,0x66,
                       0x51,0xC1,0x47,0x56,0xA0,0x61,0xD6,0x62,
                       0xF5,0x80,0xFF,0x4D,0xE4,0x3B,0x49,0xFA,
                       0x82,0xD8,0x0A,0x4B,0x80,0xF8,0x43,0x4A];
        let mine = SHA3_256::hash(&empty);
        assert_eq!(hashres.to_vec(), mine);
    }

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf
    #[test]
    fn nist_1600_example() {
        let example = [0xA3; 200];
        let hashres = [0x79,0xF3,0x8A,0xDE,0xC5,0xC2,0x03,0x07,
                       0xA9,0x8E,0xF7,0x6E,0x83,0x24,0xAF,0xBF,
                       0xD4,0x6C,0xFD,0x81,0xB2,0x2E,0x39,0x73,
                       0xC6,0x5F,0xA1,0xBD,0x9D,0xE3,0x17,0x87];
        let mine = SHA3_256::hash(&example);
        assert_eq!(hashres.to_vec(), mine);
    }

    #[cfg(test)]
    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/sha/nist_sha3_256.test";
        run_test(fname.to_string(), 3, |case| {
            let (negl, lbytes) = case.get("l").unwrap();
            let (negm, mbytes) = case.get("m").unwrap();
            let (negd, dbytes) = case.get("d").unwrap();

            assert!(!negl && !negm && !negd);
            let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
            let digest = SHA3_256::hash(&msg);
            assert_eq!(dbytes, &digest);
        });
    }
}

/// The SHA3-384 hash. [BETTER]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA3_384};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA3_384::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA3_384::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA3_384 {
    state: Keccak
}

impl Hash for SHA3_384 {
    fn new() -> Self
    {
        SHA3_384{ state: Keccak::new(1600 - 768) }
    }

    fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        self.state.tag_and_pad(0x06);
        self.state.squeeze(384 / 8)
    }

    fn block_size() -> usize
    {
        832
    }
}

#[cfg(test)]
mod sha384 {
    use super::*;
    use testing::run_test;

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg0.pdf
    #[test]
    fn nist_empty_example() {
        let empty = [0; 0];
        let hashres = [0x0C,0x63,0xA7,0x5B,0x84,0x5E,0x4F,0x7D,
                       0x01,0x10,0x7D,0x85,0x2E,0x4C,0x24,0x85,
                       0xC5,0x1A,0x50,0xAA,0xAA,0x94,0xFC,0x61,
                       0x99,0x5E,0x71,0xBB,0xEE,0x98,0x3A,0x2A,
                       0xC3,0x71,0x38,0x31,0x26,0x4A,0xDB,0x47,
                       0xFB,0x6B,0xD1,0xE0,0x58,0xD5,0xF0,0x04];
        let mine = SHA3_384::hash(&empty);
        assert_eq!(hashres.to_vec(), mine);
    }

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf
    #[test]
    fn nist_1600_example() {
        let example = [0xA3; 200];
        let hashres = [0x18,0x81,0xDE,0x2C,0xA7,0xE4,0x1E,0xF9,
                       0x5D,0xC4,0x73,0x2B,0x8F,0x5F,0x00,0x2B,
                       0x18,0x9C,0xC1,0xE4,0x2B,0x74,0x16,0x8E,
                       0xD1,0x73,0x26,0x49,0xCE,0x1D,0xBC,0xDD,
                       0x76,0x19,0x7A,0x31,0xFD,0x55,0xEE,0x98,
                       0x9F,0x2D,0x70,0x50,0xDD,0x47,0x3E,0x8F];
        let mine = SHA3_384::hash(&example);
        assert_eq!(hashres.to_vec(), mine);
    }

    #[cfg(test)]
    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/sha/nist_sha3_384.test";
        run_test(fname.to_string(), 3, |case| {
            let (negl, lbytes) = case.get("l").unwrap();
            let (negm, mbytes) = case.get("m").unwrap();
            let (negd, dbytes) = case.get("d").unwrap();

            assert!(!negl && !negm && !negd);
            let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
            let digest = SHA3_384::hash(&msg);
            assert_eq!(dbytes, &digest);
        });
    }
}

/// The SHA3-512 hash. [BEST]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA3_512};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA3_512::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA3_512::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA3_512 {
    state: Keccak
}

impl Hash for SHA3_512 {
    fn new() -> Self
    {
        SHA3_512{ state: Keccak::new(1600 - 1024) }
    }

    fn update(&mut self, buffer: &[u8])
    {
        self.state.process(&buffer);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        self.state.tag_and_pad(0x06);
        self.state.squeeze(512 / 8)
    }

    fn block_size() -> usize
    {
        576
    }
}

#[cfg(test)]
mod sha512 {
    use super::*;
    use testing::run_test;

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg0.pdf
    #[test]
    fn nist_empty_example() {
        let empty = [0; 0];
        let hashres = [0xA6,0x9F,0x73,0xCC,0xA2,0x3A,0x9A,0xC5,
                       0xC8,0xB5,0x67,0xDC,0x18,0x5A,0x75,0x6E,
                       0x97,0xC9,0x82,0x16,0x4F,0xE2,0x58,0x59,
                       0xE0,0xD1,0xDC,0xC1,0x47,0x5C,0x80,0xA6,
                       0x15,0xB2,0x12,0x3A,0xF1,0xF5,0xF9,0x4C,
                       0x11,0xE3,0xE9,0x40,0x2C,0x3A,0xC5,0x58,
                       0xF5,0x00,0x19,0x9D,0x95,0xB6,0xD3,0xE3,
                       0x01,0x75,0x85,0x86,0x28,0x1D,0xCD,0x26];
        let mine = SHA3_512::hash(&empty);
        assert_eq!(hashres.to_vec(), mine);
    }

    // see https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf
    #[test]
    fn nist_1600_example() {
        let example = [0xA3; 200];
        let hashres = [0xE7,0x6D,0xFA,0xD2,0x20,0x84,0xA8,0xB1,
                       0x46,0x7F,0xCF,0x2F,0xFA,0x58,0x36,0x1B,
                       0xEC,0x76,0x28,0xED,0xF5,0xF3,0xFD,0xC0,
                       0xE4,0x80,0x5D,0xC4,0x8C,0xAE,0xEC,0xA8,
                       0x1B,0x7C,0x13,0xC3,0x0A,0xDF,0x52,0xA3,
                       0x65,0x95,0x84,0x73,0x9A,0x2D,0xF4,0x6B,
                       0xE5,0x89,0xC5,0x1C,0xA1,0xA4,0xA8,0x41,
                       0x6D,0xF6,0x54,0x5A,0x1C,0xE8,0xBA,0x00];
        let mine = SHA3_512::hash(&example);
        assert_eq!(hashres.to_vec(), mine);
    }

    #[cfg(test)]
    #[test]
    fn nist_test_vectors() {
        let fname = "testdata/sha/nist_sha3_512.test";
        run_test(fname.to_string(), 3, |case| {
            let (negl, lbytes) = case.get("l").unwrap();
            let (negm, mbytes) = case.get("m").unwrap();
            let (negd, dbytes) = case.get("d").unwrap();

            assert!(!negl && !negm && !negd);
            let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
            let digest = SHA3_512::hash(&msg);
            assert_eq!(dbytes, &digest);
        });
    }
}