use byteorder::{BigEndian,ByteOrder,WriteBytesExt};
use sha::shared::calculate_k;
use super::super::Hash;

/// The SHA2-224 hash.
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA224};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA224::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA224::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA224 {
    state: SHA256State
}

impl Hash for SHA224 {
    fn new() -> Self
    {
        let state = SHA256State::new([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,
                                      0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
        SHA224{ state }
    }

    fn update(&mut self, data: &[u8])
    {
        self.state.update(data);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        if !self.state.done {
            self.state.finish();
        }

        let mut output = Vec::with_capacity(28);
        output.write_u32::<BigEndian>(self.state.state[0]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[1]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[2]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[3]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[4]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[5]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[6]).expect("Broken writing value to pre-allocated Vec?");
        output
     }

    fn block_size() -> usize
    {
        512
    }
}

/// The SHA2-256 hash. [GOOD]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA256};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA256::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA256::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA256 {
    state: SHA256State
}

impl Hash for SHA256 {
    fn new() -> Self
    {
        let state = SHA256State::new([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
        SHA256{ state }
    }

    fn update(&mut self, data: &[u8])
    {
        self.state.update(data);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        if !self.state.done {
            self.state.finish();
        }

        let mut output = Vec::with_capacity(28);
        output.write_u32::<BigEndian>(self.state.state[0]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[1]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[2]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[3]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[4]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[5]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[6]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state.state[7]).expect("Broken writing value to pre-allocated Vec?");
        output
    }

    fn block_size() -> usize
    {
        512
    }
}

/// The SHA2-384 hash. [BETTER]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA384};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA384::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA384::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA384 {
    state: SHA512State
}

impl Hash for SHA384 {
    fn new() -> Self
    {
        let state = SHA512State::new([0xcbbb9d5dc1059ed8,0x629a292a367cd507,
                                      0x9159015a3070dd17,0x152fecd8f70e5939,
                                      0x67332667ffc00b31,0x8eb44a8768581511,
                                      0xdb0c2e0d64f98fa7,0x47b5481dbefa4fa4]);
        SHA384{ state }
    }

    fn update(&mut self, data: &[u8])
    {
        self.state.update(data);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        if !self.state.done {
            self.state.finish();
        }

        let mut output = Vec::with_capacity(64);
        output.write_u64::<BigEndian>(self.state.state[0]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[1]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[2]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[3]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[4]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[5]).expect("Broken writing value to pre-allocated Vec?");
        output
     }

    fn block_size() -> usize
    {
        1024
    }
}

/// The SHA2-512 hash. [BEST]
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA512};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA512::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA512::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
pub struct SHA512 {
    state: SHA512State
}

impl Hash for SHA512 {
    fn new() -> Self
    {
        let state = SHA512State::new([0x6a09e667f3bcc908,0xbb67ae8584caa73b,
                                      0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
                                      0x510e527fade682d1,0x9b05688c2b3e6c1f,
                                      0x1f83d9abfb41bd6b,0x5be0cd19137e2179]);
        SHA512{ state }
    }

    fn update(&mut self, data: &[u8])
    {
        self.state.update(data);
    }

    fn finalize(&mut self) -> Vec<u8>
    {
        if !self.state.done {
            self.state.finish();
        }

        let mut output = Vec::with_capacity(64);
        output.write_u64::<BigEndian>(self.state.state[0]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[1]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[2]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[3]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[4]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[5]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[6]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u64::<BigEndian>(self.state.state[7]).expect("Broken writing value to pre-allocated Vec?");
        output
     }

    fn block_size() -> usize
    {
        1024
    }
}

macro_rules! bsig256_0 {
    ($x: ident) => {
       $x.rotate_right(2) ^ $x.rotate_right(13) ^ $x.rotate_right(22) 
    };
}

macro_rules! bsig256_1 {
    ($x: ident) => {
       $x.rotate_right(6) ^ $x.rotate_right(11) ^ $x.rotate_right(25) 
    };
}

macro_rules! lsig256_0 {
    ($x: ident) => {
       $x.rotate_right(7) ^ $x.rotate_right(18) ^ ($x >> 3)
    };
}

macro_rules! lsig256_1 {
    ($x: ident) => {
       $x.rotate_right(17) ^ $x.rotate_right(19) ^ ($x >> 10)
    };
}

struct SHA256State {
    state: [u32; 8],
    buffer: Vec<u8>,
    done: bool,
    l: usize
}

impl SHA256State {
    fn new(values: [u32; 8]) -> Self {
        SHA256State {
            state: values,
            buffer: Vec::with_capacity(64),
            done: false,
            l: 0,
        }
    }

    fn process(&mut self, w00: u32, w01: u32, w02: u32, w03: u32,
                          w04: u32, w05: u32, w06: u32, w07: u32,
                          w08: u32, w09: u32, w10: u32, w11: u32,
                          w12: u32, w13: u32, w14: u32, w15: u32)
    {
        let w16 = lsig256_1!(w14) + w09 + lsig256_0!(w01) + w00;
        let w17 = lsig256_1!(w15) + w10 + lsig256_0!(w02) + w01;
        let w18 = lsig256_1!(w16) + w11 + lsig256_0!(w03) + w02;
        let w19 = lsig256_1!(w17) + w12 + lsig256_0!(w04) + w03;
        let w20 = lsig256_1!(w18) + w13 + lsig256_0!(w05) + w04;
        let w21 = lsig256_1!(w19) + w14 + lsig256_0!(w06) + w05;
        let w22 = lsig256_1!(w20) + w15 + lsig256_0!(w07) + w06;
        let w23 = lsig256_1!(w21) + w16 + lsig256_0!(w08) + w07;
        let w24 = lsig256_1!(w22) + w17 + lsig256_0!(w09) + w08;
        let w25 = lsig256_1!(w23) + w18 + lsig256_0!(w10) + w09;
        let w26 = lsig256_1!(w24) + w19 + lsig256_0!(w11) + w10;
        let w27 = lsig256_1!(w25) + w20 + lsig256_0!(w12) + w11;
        let w28 = lsig256_1!(w26) + w21 + lsig256_0!(w13) + w12;
        let w29 = lsig256_1!(w27) + w22 + lsig256_0!(w14) + w13;
        let w30 = lsig256_1!(w28) + w23 + lsig256_0!(w15) + w14;
        let w31 = lsig256_1!(w29) + w24 + lsig256_0!(w16) + w15;
        let w32 = lsig256_1!(w30) + w25 + lsig256_0!(w17) + w16;
        let w33 = lsig256_1!(w31) + w26 + lsig256_0!(w18) + w17;
        let w34 = lsig256_1!(w32) + w27 + lsig256_0!(w19) + w18;
        let w35 = lsig256_1!(w33) + w28 + lsig256_0!(w20) + w19;
        let w36 = lsig256_1!(w34) + w29 + lsig256_0!(w21) + w20;
        let w37 = lsig256_1!(w35) + w30 + lsig256_0!(w22) + w21;
        let w38 = lsig256_1!(w36) + w31 + lsig256_0!(w23) + w22;
        let w39 = lsig256_1!(w37) + w32 + lsig256_0!(w24) + w23;
        let w40 = lsig256_1!(w38) + w33 + lsig256_0!(w25) + w24;
        let w41 = lsig256_1!(w39) + w34 + lsig256_0!(w26) + w25;
        let w42 = lsig256_1!(w40) + w35 + lsig256_0!(w27) + w26;
        let w43 = lsig256_1!(w41) + w36 + lsig256_0!(w28) + w27;
        let w44 = lsig256_1!(w42) + w37 + lsig256_0!(w29) + w28;
        let w45 = lsig256_1!(w43) + w38 + lsig256_0!(w30) + w29;
        let w46 = lsig256_1!(w44) + w39 + lsig256_0!(w31) + w30;
        let w47 = lsig256_1!(w45) + w40 + lsig256_0!(w32) + w31;
        let w48 = lsig256_1!(w46) + w41 + lsig256_0!(w33) + w32;
        let w49 = lsig256_1!(w47) + w42 + lsig256_0!(w34) + w33;
        let w50 = lsig256_1!(w48) + w43 + lsig256_0!(w35) + w34;
        let w51 = lsig256_1!(w49) + w44 + lsig256_0!(w36) + w35;
        let w52 = lsig256_1!(w50) + w45 + lsig256_0!(w37) + w36;
        let w53 = lsig256_1!(w51) + w46 + lsig256_0!(w38) + w37;
        let w54 = lsig256_1!(w52) + w47 + lsig256_0!(w39) + w38;
        let w55 = lsig256_1!(w53) + w48 + lsig256_0!(w40) + w39;
        let w56 = lsig256_1!(w54) + w49 + lsig256_0!(w41) + w40;
        let w57 = lsig256_1!(w55) + w50 + lsig256_0!(w42) + w41;
        let w58 = lsig256_1!(w56) + w51 + lsig256_0!(w43) + w42;
        let w59 = lsig256_1!(w57) + w52 + lsig256_0!(w44) + w43;
        let w60 = lsig256_1!(w58) + w53 + lsig256_0!(w45) + w44;
        let w61 = lsig256_1!(w59) + w54 + lsig256_0!(w46) + w45;
        let w62 = lsig256_1!(w60) + w55 + lsig256_0!(w47) + w46;
        let w63 = lsig256_1!(w61) + w56 + lsig256_0!(w48) + w47;
        let s01 = step256(self.state,0x428a2f98,w00);
        let s02 = step256(s01,0x71374491,w01);
        let s03 = step256(s02,0xb5c0fbcf,w02);
        let s04 = step256(s03,0xe9b5dba5,w03);
        let s05 = step256(s04,0x3956c25b,w04);
        let s06 = step256(s05,0x59f111f1,w05);
        let s07 = step256(s06,0x923f82a4,w06);
        let s08 = step256(s07,0xab1c5ed5,w07);
        let s09 = step256(s08,0xd807aa98,w08);
        let s10 = step256(s09,0x12835b01,w09);
        let s11 = step256(s10,0x243185be,w10);
        let s12 = step256(s11,0x550c7dc3,w11);
        let s13 = step256(s12,0x72be5d74,w12);
        let s14 = step256(s13,0x80deb1fe,w13);
        let s15 = step256(s14,0x9bdc06a7,w14);
        let s16 = step256(s15,0xc19bf174,w15);
        let s17 = step256(s16,0xe49b69c1,w16);
        let s18 = step256(s17,0xefbe4786,w17);
        let s19 = step256(s18,0x0fc19dc6,w18);
        let s20 = step256(s19,0x240ca1cc,w19);
        let s21 = step256(s20,0x2de92c6f,w20);
        let s22 = step256(s21,0x4a7484aa,w21);
        let s23 = step256(s22,0x5cb0a9dc,w22);
        let s24 = step256(s23,0x76f988da,w23);
        let s25 = step256(s24,0x983e5152,w24);
        let s26 = step256(s25,0xa831c66d,w25);
        let s27 = step256(s26,0xb00327c8,w26);
        let s28 = step256(s27,0xbf597fc7,w27);
        let s29 = step256(s28,0xc6e00bf3,w28);
        let s30 = step256(s29,0xd5a79147,w29);
        let s31 = step256(s30,0x06ca6351,w30);
        let s32 = step256(s31,0x14292967,w31);
        let s33 = step256(s32,0x27b70a85,w32);
        let s34 = step256(s33,0x2e1b2138,w33);
        let s35 = step256(s34,0x4d2c6dfc,w34);
        let s36 = step256(s35,0x53380d13,w35);
        let s37 = step256(s36,0x650a7354,w36);
        let s38 = step256(s37,0x766a0abb,w37);
        let s39 = step256(s38,0x81c2c92e,w38);
        let s40 = step256(s39,0x92722c85,w39);
        let s41 = step256(s40,0xa2bfe8a1,w40);
        let s42 = step256(s41,0xa81a664b,w41);
        let s43 = step256(s42,0xc24b8b70,w42);
        let s44 = step256(s43,0xc76c51a3,w43);
        let s45 = step256(s44,0xd192e819,w44);
        let s46 = step256(s45,0xd6990624,w45);
        let s47 = step256(s46,0xf40e3585,w46);
        let s48 = step256(s47,0x106aa070,w47);
        let s49 = step256(s48,0x19a4c116,w48);
        let s50 = step256(s49,0x1e376c08,w49);
        let s51 = step256(s50,0x2748774c,w50);
        let s52 = step256(s51,0x34b0bcb5,w51);
        let s53 = step256(s52,0x391c0cb3,w52);
        let s54 = step256(s53,0x4ed8aa4a,w53);
        let s55 = step256(s54,0x5b9cca4f,w54);
        let s56 = step256(s55,0x682e6ff3,w55);
        let s57 = step256(s56,0x748f82ee,w56);
        let s58 = step256(s57,0x78a5636f,w57);
        let s59 = step256(s58,0x84c87814,w58);
        let s60 = step256(s59,0x8cc70208,w59);
        let s61 = step256(s60,0x90befffa,w60);
        let s62 = step256(s61,0xa4506ceb,w61);
        let s63 = step256(s62,0xbef9a3f7,w62);
        let s64 = step256(s63,0xc67178f2,w63);
        self.state[0] += s64[0];
        self.state[1] += s64[1];
        self.state[2] += s64[2];
        self.state[3] += s64[3];
        self.state[4] += s64[4];
        self.state[5] += s64[5];
        self.state[6] += s64[6];
        self.state[7] += s64[7];
    }

    fn update(&mut self, block: &[u8]) {
        if !self.done {
            let mut offset = 0;

            self.l += block.len();

            if self.buffer.len() + block.len() < 64 {
                self.buffer.extend_from_slice(block);
                return;
            }

            if self.buffer.len() > 0 {
                // We must be able to build up a 64 byte chunk, at this point, otherwise
                // the math above would've been wrong.
                while self.buffer.len() < 64 {
                    self.buffer.push(block[offset]);
                    offset += 1;
                }
                process_u32_block!(self.buffer, 0, self);
                // Reset the buffer now, we're done with that nonsense for the moment
                self.buffer.resize(0,0);
            }

            while (offset + 64) <= block.len() {
                process_u32_block!(block, offset, self);
                offset += 64;
            }

            if offset < block.len() {
                self.buffer.extend_from_slice(&block[offset..]);
            }
        }
     }

    fn finish(&mut self) {
        let bitlen = self.l * 8;
        let k = calculate_k(448, 512, bitlen);
        // INVARIANT: k is necessarily > 0, and (k + 1) is a multiple of 8
        let bytes_to_add = (k + 1) / 8;
        let mut padvec = Vec::with_capacity(bytes_to_add + 8);
        padvec.push(0x80); // Set the high bit, since the first bit after the data
                           // should be set
        padvec.resize(bytes_to_add, 0);
        padvec.write_u64::<BigEndian>(bitlen as u64).expect("Broken writing value to pre-allocated Vec?");
        self.update(&padvec);
        self.done = true;
        assert_eq!(self.buffer.len(), 0);
     }
}

#[inline(always)]
fn step256(state0: [u32; 8], k: u32, w: u32) -> [u32; 8]
{
    let [a,b,c,d,e,f,g,h] = state0;
    let t1 = h + bsig256_1!(e) + ch!(e,f,g) + k + w;
    let t2 = bsig256_0!(a) + maj!(a,b,c);
    let hp = g;
    let gp = f;
    let fp = e;
    let ep = d + t1;
    let dp = c;
    let cp = b;
    let bp = a;
    let ap = t1 + t2;
    [ap,bp,cp,dp,ep,fp,gp,hp]
}

macro_rules! bsig512_0 {
    ($x: ident) => {
       $x.rotate_right(28) ^ $x.rotate_right(34) ^ $x.rotate_right(39) 
    };
}

macro_rules! bsig512_1 {
    ($x: ident) => {
       $x.rotate_right(14) ^ $x.rotate_right(18) ^ $x.rotate_right(41) 
    };
}

macro_rules! lsig512_0 {
    ($x: ident) => {
       $x.rotate_right(1) ^ $x.rotate_right(8) ^ ($x >> 7) 
    };
}

macro_rules! lsig512_1 {
    ($x: ident) => {
       $x.rotate_right(19) ^ $x.rotate_right(61) ^ ($x >> 6) 
    };
}

macro_rules! process_u64_block {
    ($buf: expr, $off: expr, $self: ident) => {{
        let w00 = BigEndian::read_u64(&$buf[$off+0..]);
        let w01 = BigEndian::read_u64(&$buf[$off+8..]);
        let w02 = BigEndian::read_u64(&$buf[$off+16..]);
        let w03 = BigEndian::read_u64(&$buf[$off+24..]);
        let w04 = BigEndian::read_u64(&$buf[$off+32..]);
        let w05 = BigEndian::read_u64(&$buf[$off+40..]);
        let w06 = BigEndian::read_u64(&$buf[$off+48..]);
        let w07 = BigEndian::read_u64(&$buf[$off+56..]);
        let w08 = BigEndian::read_u64(&$buf[$off+64..]);
        let w09 = BigEndian::read_u64(&$buf[$off+72..]);
        let w10 = BigEndian::read_u64(&$buf[$off+80..]);
        let w11 = BigEndian::read_u64(&$buf[$off+88..]);
        let w12 = BigEndian::read_u64(&$buf[$off+96..]);
        let w13 = BigEndian::read_u64(&$buf[$off+104..]);
        let w14 = BigEndian::read_u64(&$buf[$off+112..]);
        let w15 = BigEndian::read_u64(&$buf[$off+120..]);
        $self.process(w00, w01, w02, w03, w04, w05, w06, w07,
                      w08, w09, w10, w11, w12, w13, w14, w15);
    }};
}

struct SHA512State {
    state: [u64; 8],
    buffer: Vec<u8>,
    done: bool,
    l: usize
}

impl SHA512State {
    fn new(values: [u64; 8]) -> Self {
        SHA512State {
            state: values,
            buffer: Vec::with_capacity(128),
            done: false,
            l: 0,
        }
    }

    fn process(&mut self, w00: u64, w01: u64, w02: u64, w03: u64,
                          w04: u64, w05: u64, w06: u64, w07: u64,
                          w08: u64, w09: u64, w10: u64, w11: u64,
                          w12: u64, w13: u64, w14: u64, w15: u64)
    {
        let w16 = lsig512_1!(w14) + w09 + lsig512_0!(w01) + w00;
        let w17 = lsig512_1!(w15) + w10 + lsig512_0!(w02) + w01;
        let w18 = lsig512_1!(w16) + w11 + lsig512_0!(w03) + w02;
        let w19 = lsig512_1!(w17) + w12 + lsig512_0!(w04) + w03;
        let w20 = lsig512_1!(w18) + w13 + lsig512_0!(w05) + w04;
        let w21 = lsig512_1!(w19) + w14 + lsig512_0!(w06) + w05;
        let w22 = lsig512_1!(w20) + w15 + lsig512_0!(w07) + w06;
        let w23 = lsig512_1!(w21) + w16 + lsig512_0!(w08) + w07;
        let w24 = lsig512_1!(w22) + w17 + lsig512_0!(w09) + w08;
        let w25 = lsig512_1!(w23) + w18 + lsig512_0!(w10) + w09;
        let w26 = lsig512_1!(w24) + w19 + lsig512_0!(w11) + w10;
        let w27 = lsig512_1!(w25) + w20 + lsig512_0!(w12) + w11;
        let w28 = lsig512_1!(w26) + w21 + lsig512_0!(w13) + w12;
        let w29 = lsig512_1!(w27) + w22 + lsig512_0!(w14) + w13;
        let w30 = lsig512_1!(w28) + w23 + lsig512_0!(w15) + w14;
        let w31 = lsig512_1!(w29) + w24 + lsig512_0!(w16) + w15;
        let w32 = lsig512_1!(w30) + w25 + lsig512_0!(w17) + w16;
        let w33 = lsig512_1!(w31) + w26 + lsig512_0!(w18) + w17;
        let w34 = lsig512_1!(w32) + w27 + lsig512_0!(w19) + w18;
        let w35 = lsig512_1!(w33) + w28 + lsig512_0!(w20) + w19;
        let w36 = lsig512_1!(w34) + w29 + lsig512_0!(w21) + w20;
        let w37 = lsig512_1!(w35) + w30 + lsig512_0!(w22) + w21;
        let w38 = lsig512_1!(w36) + w31 + lsig512_0!(w23) + w22;
        let w39 = lsig512_1!(w37) + w32 + lsig512_0!(w24) + w23;
        let w40 = lsig512_1!(w38) + w33 + lsig512_0!(w25) + w24;
        let w41 = lsig512_1!(w39) + w34 + lsig512_0!(w26) + w25;
        let w42 = lsig512_1!(w40) + w35 + lsig512_0!(w27) + w26;
        let w43 = lsig512_1!(w41) + w36 + lsig512_0!(w28) + w27;
        let w44 = lsig512_1!(w42) + w37 + lsig512_0!(w29) + w28;
        let w45 = lsig512_1!(w43) + w38 + lsig512_0!(w30) + w29;
        let w46 = lsig512_1!(w44) + w39 + lsig512_0!(w31) + w30;
        let w47 = lsig512_1!(w45) + w40 + lsig512_0!(w32) + w31;
        let w48 = lsig512_1!(w46) + w41 + lsig512_0!(w33) + w32;
        let w49 = lsig512_1!(w47) + w42 + lsig512_0!(w34) + w33;
        let w50 = lsig512_1!(w48) + w43 + lsig512_0!(w35) + w34;
        let w51 = lsig512_1!(w49) + w44 + lsig512_0!(w36) + w35;
        let w52 = lsig512_1!(w50) + w45 + lsig512_0!(w37) + w36;
        let w53 = lsig512_1!(w51) + w46 + lsig512_0!(w38) + w37;
        let w54 = lsig512_1!(w52) + w47 + lsig512_0!(w39) + w38;
        let w55 = lsig512_1!(w53) + w48 + lsig512_0!(w40) + w39;
        let w56 = lsig512_1!(w54) + w49 + lsig512_0!(w41) + w40;
        let w57 = lsig512_1!(w55) + w50 + lsig512_0!(w42) + w41;
        let w58 = lsig512_1!(w56) + w51 + lsig512_0!(w43) + w42;
        let w59 = lsig512_1!(w57) + w52 + lsig512_0!(w44) + w43;
        let w60 = lsig512_1!(w58) + w53 + lsig512_0!(w45) + w44;
        let w61 = lsig512_1!(w59) + w54 + lsig512_0!(w46) + w45;
        let w62 = lsig512_1!(w60) + w55 + lsig512_0!(w47) + w46;
        let w63 = lsig512_1!(w61) + w56 + lsig512_0!(w48) + w47;
        let w64 = lsig512_1!(w62) + w57 + lsig512_0!(w49) + w48;
        let w65 = lsig512_1!(w63) + w58 + lsig512_0!(w50) + w49;
        let w66 = lsig512_1!(w64) + w59 + lsig512_0!(w51) + w50;
        let w67 = lsig512_1!(w65) + w60 + lsig512_0!(w52) + w51;
        let w68 = lsig512_1!(w66) + w61 + lsig512_0!(w53) + w52;
        let w69 = lsig512_1!(w67) + w62 + lsig512_0!(w54) + w53;
        let w70 = lsig512_1!(w68) + w63 + lsig512_0!(w55) + w54;
        let w71 = lsig512_1!(w69) + w64 + lsig512_0!(w56) + w55;
        let w72 = lsig512_1!(w70) + w65 + lsig512_0!(w57) + w56;
        let w73 = lsig512_1!(w71) + w66 + lsig512_0!(w58) + w57;
        let w74 = lsig512_1!(w72) + w67 + lsig512_0!(w59) + w58;
        let w75 = lsig512_1!(w73) + w68 + lsig512_0!(w60) + w59;
        let w76 = lsig512_1!(w74) + w69 + lsig512_0!(w61) + w60;
        let w77 = lsig512_1!(w75) + w70 + lsig512_0!(w62) + w61;
        let w78 = lsig512_1!(w76) + w71 + lsig512_0!(w63) + w62;
        let w79 = lsig512_1!(w77) + w72 + lsig512_0!(w64) + w63;
        let s01 = step512(self.state,0x428a2f98d728ae22,w00);
        let s02 = step512(s01,0x7137449123ef65cd,w01);
        let s03 = step512(s02,0xb5c0fbcfec4d3b2f,w02);
        let s04 = step512(s03,0xe9b5dba58189dbbc,w03);
        let s05 = step512(s04,0x3956c25bf348b538,w04);
        let s06 = step512(s05,0x59f111f1b605d019,w05);
        let s07 = step512(s06,0x923f82a4af194f9b,w06);
        let s08 = step512(s07,0xab1c5ed5da6d8118,w07);
        let s09 = step512(s08,0xd807aa98a3030242,w08);
        let s10 = step512(s09,0x12835b0145706fbe,w09);
        let s11 = step512(s10,0x243185be4ee4b28c,w10);
        let s12 = step512(s11,0x550c7dc3d5ffb4e2,w11);
        let s13 = step512(s12,0x72be5d74f27b896f,w12);
        let s14 = step512(s13,0x80deb1fe3b1696b1,w13);
        let s15 = step512(s14,0x9bdc06a725c71235,w14);
        let s16 = step512(s15,0xc19bf174cf692694,w15);
        let s17 = step512(s16,0xe49b69c19ef14ad2,w16);
        let s18 = step512(s17,0xefbe4786384f25e3,w17);
        let s19 = step512(s18,0x0fc19dc68b8cd5b5,w18);
        let s20 = step512(s19,0x240ca1cc77ac9c65,w19);
        let s21 = step512(s20,0x2de92c6f592b0275,w20);
        let s22 = step512(s21,0x4a7484aa6ea6e483,w21);
        let s23 = step512(s22,0x5cb0a9dcbd41fbd4,w22);
        let s24 = step512(s23,0x76f988da831153b5,w23);
        let s25 = step512(s24,0x983e5152ee66dfab,w24);
        let s26 = step512(s25,0xa831c66d2db43210,w25);
        let s27 = step512(s26,0xb00327c898fb213f,w26);
        let s28 = step512(s27,0xbf597fc7beef0ee4,w27);
        let s29 = step512(s28,0xc6e00bf33da88fc2,w28);
        let s30 = step512(s29,0xd5a79147930aa725,w29);
        let s31 = step512(s30,0x06ca6351e003826f,w30);
        let s32 = step512(s31,0x142929670a0e6e70,w31);
        let s33 = step512(s32,0x27b70a8546d22ffc,w32);
        let s34 = step512(s33,0x2e1b21385c26c926,w33);
        let s35 = step512(s34,0x4d2c6dfc5ac42aed,w34);
        let s36 = step512(s35,0x53380d139d95b3df,w35);
        let s37 = step512(s36,0x650a73548baf63de,w36);
        let s38 = step512(s37,0x766a0abb3c77b2a8,w37);
        let s39 = step512(s38,0x81c2c92e47edaee6,w38);
        let s40 = step512(s39,0x92722c851482353b,w39);
        let s41 = step512(s40,0xa2bfe8a14cf10364,w40);
        let s42 = step512(s41,0xa81a664bbc423001,w41);
        let s43 = step512(s42,0xc24b8b70d0f89791,w42);
        let s44 = step512(s43,0xc76c51a30654be30,w43);
        let s45 = step512(s44,0xd192e819d6ef5218,w44);
        let s46 = step512(s45,0xd69906245565a910,w45);
        let s47 = step512(s46,0xf40e35855771202a,w46);
        let s48 = step512(s47,0x106aa07032bbd1b8,w47);
        let s49 = step512(s48,0x19a4c116b8d2d0c8,w48);
        let s50 = step512(s49,0x1e376c085141ab53,w49);
        let s51 = step512(s50,0x2748774cdf8eeb99,w50);
        let s52 = step512(s51,0x34b0bcb5e19b48a8,w51);
        let s53 = step512(s52,0x391c0cb3c5c95a63,w52);
        let s54 = step512(s53,0x4ed8aa4ae3418acb,w53);
        let s55 = step512(s54,0x5b9cca4f7763e373,w54);
        let s56 = step512(s55,0x682e6ff3d6b2b8a3,w55);
        let s57 = step512(s56,0x748f82ee5defb2fc,w56);
        let s58 = step512(s57,0x78a5636f43172f60,w57);
        let s59 = step512(s58,0x84c87814a1f0ab72,w58);
        let s60 = step512(s59,0x8cc702081a6439ec,w59);
        let s61 = step512(s60,0x90befffa23631e28,w60);
        let s62 = step512(s61,0xa4506cebde82bde9,w61);
        let s63 = step512(s62,0xbef9a3f7b2c67915,w62);
        let s64 = step512(s63,0xc67178f2e372532b,w63);
        let s65 = step512(s64,0xca273eceea26619c,w64);
        let s66 = step512(s65,0xd186b8c721c0c207,w65);
        let s67 = step512(s66,0xeada7dd6cde0eb1e,w66);
        let s68 = step512(s67,0xf57d4f7fee6ed178,w67);
        let s69 = step512(s68,0x06f067aa72176fba,w68);
        let s70 = step512(s69,0x0a637dc5a2c898a6,w69);
        let s71 = step512(s70,0x113f9804bef90dae,w70);
        let s72 = step512(s71,0x1b710b35131c471b,w71);
        let s73 = step512(s72,0x28db77f523047d84,w72);
        let s74 = step512(s73,0x32caab7b40c72493,w73);
        let s75 = step512(s74,0x3c9ebe0a15c9bebc,w74);
        let s76 = step512(s75,0x431d67c49c100d4c,w75);
        let s77 = step512(s76,0x4cc5d4becb3e42b6,w76);
        let s78 = step512(s77,0x597f299cfc657e2a,w77);
        let s79 = step512(s78,0x5fcb6fab3ad6faec,w78);
        let s80 = step512(s79,0x6c44198c4a475817,w79);
        self.state[0] += s80[0];
        self.state[1] += s80[1];
        self.state[2] += s80[2];
        self.state[3] += s80[3];
        self.state[4] += s80[4];
        self.state[5] += s80[5];
        self.state[6] += s80[6];
        self.state[7] += s80[7];
    }

    fn update(&mut self, block: &[u8]) {
        if !self.done {
            let mut offset = 0;

            self.l += block.len();

            if self.buffer.len() + block.len() < 128 {
                self.buffer.extend_from_slice(block);
                return;
            }

            if self.buffer.len() > 0 {
                // We must be able to build up a 128 byte chunk, at this point, otherwise
                // the math above would've been wrong.
                while self.buffer.len() < 128 {
                    self.buffer.push(block[offset]);
                    offset += 1;
                }
                process_u64_block!(self.buffer, 0, self);
                // Reset the buffer now, we're done with that nonsense for the moment
                self.buffer.resize(0,0);
            }

            while (offset + 128) <= block.len() {
                process_u64_block!(block, offset, self);
                offset += 128;
            }

            if offset < block.len() {
                self.buffer.extend_from_slice(&block[offset..]);
            }
        }
     }

    fn finish(&mut self) {
        let bitlen = self.l * 8;
        let k = calculate_k(896, 1024, bitlen);
        // INVARIANT: k is necessarily > 0, and (k + 1) is a multiple of 8
        let bytes_to_add = (k + 1) / 8;
        let mut padvec = Vec::with_capacity(bytes_to_add + 16);
        padvec.push(0x80); // Set the high bit, since the first bit after the data
                           // should be set
        padvec.resize(bytes_to_add, 0);
        padvec.write_u128::<BigEndian>(bitlen as u128).expect("Broken writing value to pre-allocated Vec?");
        self.update(&padvec);
        self.done = true;
        assert_eq!(self.buffer.len(), 0);
     }
}

#[inline(always)]
fn step512(state0: [u64; 8], k: u64, w: u64) -> [u64; 8]
{
    let [a,b,c,d,e,f,g,h] = state0;
    let t1 = h + bsig512_1!(e) + ch!(e,f,g) + k + w;
    let t2 = bsig512_0!(a) + maj!(a,b,c);
    let hp = g;
    let gp = f;
    let fp = e;
    let ep = d + t1;
    let dp = c;
    let cp = b;
    let bp = a;
    let ap = t1 + t2;
    [ap,bp,cp,dp,ep,fp,gp,hp]
}

#[cfg(test)]
use testing::run_test;

#[cfg(test)]
#[test]
fn nist_sha224() {
    let fname = "testdata/sha/nist_sha224.test";
    run_test(fname.to_string(), 3, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!negl && !negm && !negd);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let digest = SHA224::hash(&msg);
        assert_eq!(dbytes, &digest);
    });
}

#[cfg(test)]
#[test]
fn nist_sha256() {
    let fname = "testdata/sha/nist_sha256.test";
    run_test(fname.to_string(), 3, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!negl && !negm && !negd);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let digest = SHA256::hash(&msg);
        assert_eq!(dbytes, &digest);
    });
}

#[cfg(test)]
#[test]
fn nist_sha384() {
    let fname = "testdata/sha/nist_sha384.test";
    run_test(fname.to_string(), 3, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!negl && !negm && !negd);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let digest = SHA384::hash(&msg);
        assert_eq!(dbytes, &digest);
    });
}

#[cfg(test)]
#[test]
fn nist_sha512() {
    let fname = "testdata/sha/nist_sha512.test";
    run_test(fname.to_string(), 3, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!negl && !negm && !negd);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let digest = SHA512::hash(&msg);
        assert_eq!(dbytes, &digest);
    });
}