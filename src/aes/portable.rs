const RIJNDAEL_KEY_SCHEDULE: [u32; 11] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 
    0x08000000, 0x10000000, 0x20000000, 0x40000000, 
    0x80000000, 0x1b000000, 0x36000000, 
    ];

const SUB_BYTES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

const INVSUB_BYTES_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];

fn word(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) |
    ((c as u32) << 08) | ((d as u32) << 00)
}

fn rot_word(x: u32) -> u32 {
    x.rotate_left(8)
}

fn sub_word(x: u32) -> u32 {
    (((SUB_BYTES_SBOX[((x >> 24) & 0xff) as usize]) as u32) << 24) |
    (((SUB_BYTES_SBOX[((x >> 16) & 0xff) as usize]) as u32) << 16) |
    (((SUB_BYTES_SBOX[((x >> 08) & 0xff) as usize]) as u32) << 08) |
    (((SUB_BYTES_SBOX[((x >> 00) & 0xff) as usize]) as u32) << 00)
}

/**************************************************************************************************/
/*                                                                                                */
/* AES State                                                                                      */
/*                                                                                                */
/**************************************************************************************************/

struct AESState {
    state: [[u8; 4]; 4]
}

macro_rules! xtime {
    ($e: expr) => {{
        let base: u8 = $e;
        let dbl = base << 1;
        let high = base & 0x80;
        let xorval = if high == 0x80 { 0x1b } else { 0x00 };
        dbl ^ xorval 
    }};
}

macro_rules! field_09 {
    ($e: expr) => {{
        let base = $e;
        base ^ xtime!(xtime!(xtime!(base)))
    }}
}

macro_rules! field_0b {
    ($e: expr) => {{
        let base = $e;
        // 1 + 8                         + 2 = 11 = 0xb
        base ^ xtime!(xtime!(xtime!(base))) ^ xtime!(base)
    }}
}

macro_rules! field_0d {
    ($e: expr) => {{
        let base = $e;
        // 1 + 8                         + 4 = 13 = 0xd
        base ^ xtime!(xtime!(xtime!(base))) ^ xtime!(xtime!(base))
    }}
}

macro_rules! field_0e {
    ($e: expr) => {{
        let base = $e;
        // 2 + 8                         + 4 = 14 = 0xe
        xtime!(base) ^ xtime!(xtime!(xtime!(base))) ^ xtime!(xtime!(base))
    }}
}

impl AESState {
    fn new(inkey: &[u8]) -> AESState {
        assert_eq!(inkey.len(), 16);
        AESState {
            state: [[inkey[00], inkey[04], inkey[08], inkey[12]],
                    [inkey[01], inkey[05], inkey[09], inkey[13]],
                    [inkey[02], inkey[06], inkey[10], inkey[14]],
                    [inkey[03], inkey[07], inkey[11], inkey[15]]]
        }
    }

//    fn print_state(&self) {
//        println!("{:02x} {:02x} {:02x} {:02x}", self.state[0][0], self.state[0][1], self.state[0][2], self.state[0][3]);
//        println!("{:02x} {:02x} {:02x} {:02x}", self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3]);
//        println!("{:02x} {:02x} {:02x} {:02x}", self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3]);
//        println!("{:02x} {:02x} {:02x} {:02x}", self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3]);
//        println!("-----------");
//    }

    fn add_round_key(&mut self, w: &[u32]) {
        assert_eq!(w.len(), 4);
        for i in 0..4 {
            self.state[0][i] ^= (w[i] >> 24) as u8;
            self.state[1][i] ^= (w[i] >> 16) as u8;
            self.state[2][i] ^= (w[i] >> 08) as u8;
            self.state[3][i] ^= (w[i] >> 00) as u8;
        }
    }

    fn sub_bytes(&mut self) {
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] = SUB_BYTES_SBOX[self.state[i][j] as usize];
            }
        }
    }

    fn inv_sub_bytes(&mut self) {
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] = INVSUB_BYTES_SBOX[self.state[i][j] as usize];
            }
        }
    }

    fn shift_rows(&mut self) {
        let temp1 = self.state[1][0];
        self.state[1][0] = self.state[1][1];
        self.state[1][1] = self.state[1][2];
        self.state[1][2] = self.state[1][3];
        self.state[1][3] = temp1;
        let temp2a = self.state[2][0];
        let temp2b = self.state[2][1];
        self.state[2][0] = self.state[2][2];
        self.state[2][1] = self.state[2][3];
        self.state[2][2] = temp2a;
        self.state[2][3] = temp2b;
        let temp3 = self.state[3][3];
        self.state[3][3] = self.state[3][2];
        self.state[3][2] = self.state[3][1];
        self.state[3][1] = self.state[3][0];
        self.state[3][0] = temp3;
    }

    fn inv_shift_rows(&mut self) {
        let temp1 = self.state[1][3];
        self.state[1][3] = self.state[1][2];
        self.state[1][2] = self.state[1][1];
        self.state[1][1] = self.state[1][0];
        self.state[1][0] = temp1;
        let temp2a = self.state[2][0];
        let temp2b = self.state[2][1];
        self.state[2][0] = self.state[2][2];
        self.state[2][1] = self.state[2][3];
        self.state[2][2] = temp2a;
        self.state[2][3] = temp2b;
        let temp3 = self.state[3][0];
        self.state[3][0] = self.state[3][1];
        self.state[3][1] = self.state[3][2];
        self.state[3][2] = self.state[3][3];
        self.state[3][3] = temp3;
    }

    fn mix_columns(&mut self) {
        for c in 0..4 {
            // get the base values
            let s0c = self.state[0][c];
            let s1c = self.state[1][c];
            let s2c = self.state[2][c];
            let s3c = self.state[3][c];

            // get the doubled values, forced to be within the field
            let d0c = xtime!(s0c);
            let d1c = xtime!(s1c);
            let d2c = xtime!(s2c);
            let d3c = xtime!(s3c);

            self.state[0][c] = d0c ^ d1c ^ s2c ^ s3c ^ s1c;
            self.state[1][c] = s0c ^ d1c ^ d2c ^ s3c ^ s2c;
            self.state[2][c] = s0c ^ s1c ^ d2c ^ d3c ^ s3c;
            self.state[3][c] = d0c ^ s1c ^ s2c ^ d3c ^ s0c;
        }
    }

    fn inv_mix_columns(&mut self) {
        for c in 0..4 {
            // get the base values
            let s0c = self.state[0][c];
            let s1c = self.state[1][c];
            let s2c = self.state[2][c];
            let s3c = self.state[3][c];

            self.state[0][c] = field_0e!(s0c) ^ field_0b!(s1c) ^ field_0d!(s2c) ^ field_09!(s3c); 
            self.state[1][c] = field_09!(s0c) ^ field_0e!(s1c) ^ field_0b!(s2c) ^ field_0d!(s3c); 
            self.state[2][c] = field_0d!(s0c) ^ field_09!(s1c) ^ field_0e!(s2c) ^ field_0b!(s3c); 
            self.state[3][c] = field_0b!(s0c) ^ field_0d!(s1c) ^ field_09!(s2c) ^ field_0e!(s3c); 
        }
    }

    fn decant(&self) -> Vec<u8> {
        vec![self.state[0][0], self.state[1][0], self.state[2][0], self.state[3][0],
             self.state[0][1], self.state[1][1], self.state[2][1], self.state[3][1],
             self.state[0][2], self.state[1][2], self.state[2][2], self.state[3][2],
             self.state[0][3], self.state[1][3], self.state[2][3], self.state[3][3],
            ]
    }
}

#[cfg(test)]
mod state {
    use quickcheck::{Arbitrary,Gen};
    use std::fmt;
    use super::*;

    #[test]
    fn xtime_works() {
        assert_eq!(xtime!(0x57), 0xae);
        assert_eq!(xtime!(0xae), 0x47);
        assert_eq!(xtime!(0x47), 0x8e);
        assert_eq!(xtime!(0x8e), 0x07);
        assert_eq!(xtime!(xtime!(0x57)), 0x47);
    }

    impl PartialEq for AESState {
        fn eq(&self, other: &AESState) -> bool {
            for i in 0..4 {
                for j in 0..4 {
                    if self.state[i][j] != other.state[i][j] {
                        return false;
                    }
                }
            }
            true
        }
    }

    impl fmt::Debug for AESState {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "[{:02x} {:02x} {:02x} {:02x}",  self.state[0][0], self.state[0][1], self.state[0][2], self.state[0][3])?;
            write!(f, " {:02x} {:02x} {:02x} {:02x}",  self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3])?;
            write!(f, " {:02x} {:02x} {:02x} {:02x}",  self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3])?;
            write!(f, " {:02x} {:02x} {:02x} {:02x}]", self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3])
        }
    }

    #[test]
    fn fips197_add_round_example() {
        let mut input = AESState{ state: [[0x32, 0x88, 0x31, 0xe0],
                                          [0x43, 0x5a, 0x31, 0x37],
                                          [0xf6, 0x30, 0x98, 0x07],
                                          [0xa8, 0x8d, 0xa2, 0x34]] };
        let       key = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
        let    output = AESState{ state: [[0x19, 0xa0, 0x9a, 0xe9],
                                          [0x3d, 0xf4, 0xc6, 0xf8],
                                          [0xe3, 0xe2, 0x8d, 0x48],
                                          [0xbe, 0x2b, 0x2a, 0x08]] };
        input.add_round_key(&key);
        assert_eq!(input, output);
    }

    #[test]
    fn fips197_sub_bytes_example() {
        let mut input = AESState{ state: [[0x19, 0xa0, 0x9a, 0xe9],
                                          [0x3d, 0xf4, 0xc6, 0xf8],
                                          [0xe3, 0xe2, 0x8d, 0x48],
                                          [0xbe, 0x2b, 0x2a, 0x08]] };
        let    output = AESState{ state: [[0xd4, 0xe0, 0xb8, 0x1e],
                                          [0x27, 0xbf, 0xb4, 0x41],
                                          [0x11, 0x98, 0x5d, 0x52],
                                          [0xae, 0xf1, 0xe5, 0x30]] };
        input.sub_bytes();
        assert_eq!(input, output);
    }

    #[test]
    fn fips197_shift_rows_example() {
        let mut input = AESState{ state: [[0xd4, 0xe0, 0xb8, 0x1e],
                                          [0x27, 0xbf, 0xb4, 0x41],
                                          [0x11, 0x98, 0x5d, 0x52],
                                          [0xae, 0xf1, 0xe5, 0x30]] };
        let    output = AESState{ state: [[0xd4, 0xe0, 0xb8, 0x1e],
                                          [0xbf, 0xb4, 0x41, 0x27],
                                          [0x5d, 0x52, 0x11, 0x98],
                                          [0x30, 0xae, 0xf1, 0xe5]] };
        input.shift_rows();
        assert_eq!(input, output);
    }

    #[test]
    fn fips197_mix_columns_example() {
        let mut input = AESState{ state: [[0xd4, 0xe0, 0xb8, 0x1e],
                                          [0xbf, 0xb4, 0x41, 0x27],
                                          [0x5d, 0x52, 0x11, 0x98],
                                          [0x30, 0xae, 0xf1, 0xe5]] };
        let    output = AESState{ state: [[0x04, 0xe0, 0x48, 0x28],
                                          [0x66, 0xcb, 0xf8, 0x06],
                                          [0x81, 0x19, 0xd3, 0x26],
                                          [0xe5, 0x9a, 0x7a, 0x4c]] };
        input.mix_columns();
        assert_eq!(input, output);
    }

    impl Clone for AESState {
        fn clone(&self) -> AESState {
            AESState{ state: self.state.clone() }
        }
    }

    impl Arbitrary for AESState {
        fn arbitrary<G: Gen>(g: &mut G) -> AESState {
            let mut base = [0; 16];
            g.fill_bytes(&mut base);
            AESState::new(&base)
        }
    }

    quickcheck! {
        fn check_sub_bytes_inverse(input: AESState) -> bool {
            let mut output = input.clone();
            output.sub_bytes();
            output.inv_sub_bytes();
            input == output
        }

        fn check_shift_rows_inverse(input: AESState) -> bool {
            let mut output = input.clone();
            output.shift_rows();
            output.inv_shift_rows();
            input == output
        }

        fn check_mix_columns_inverse(input: AESState) -> bool {
            let mut output = input.clone();
            output.mix_columns();
            output.inv_mix_columns();
            input == output
        }
    }
}

/**************************************************************************************************/
/*                                                                                                */
/* AES128 Implementation                                                                          */
/*                                                                                                */
/**************************************************************************************************/

const AES128_KEY_LENGTH: usize = 4;  // Nk
const AES128_BLOCK_SIZE: usize = 4;  // Nb
const AES128_NUM_ROUNDS: usize = 10; // Nr
const AES128_STATE_WORDS: usize = AES128_BLOCK_SIZE * (AES128_NUM_ROUNDS + 1);

pub struct AES128 {
    expanded: [u32; AES128_STATE_WORDS]
}

impl AES128 {
    pub fn new(base_key: &[u8]) -> AES128 {
        let mut expanded = [0; AES128_STATE_WORDS];
        let mut i = 0;

        assert_eq!(base_key.len(), 16);
        // while (i < Nk)
        //    w[i] = word(key[4*i],key[4*i+1],key[4*i+2],key[4*i+3])
        //    i = i+1
        // end while
        while i < AES128_KEY_LENGTH {
            expanded[i] = word(base_key[(4*i)+0], base_key[(4*i)+1],
                               base_key[(4*i)+2], base_key[(4*i)+3]);
            //println!("{:02}: expanded[{}] = {:08x}", i, i, expanded[i]);
            i = i + 1;
        }

        // i = Nk
        assert_eq!(i, AES128_KEY_LENGTH);

        // while (i < Nb * (Nr + 1))
        while i < AES128_BLOCK_SIZE * (AES128_NUM_ROUNDS+1) {
            // temp = w[i-1]
            let mut temp = expanded[i-1];
            //println!("{:02}: temp = {:08x}", i, temp);
            // if (i mod Nk = 0)
            //    temp = sub_word(rot_word(temp)) xor Rcon[i/Nk]
            // else
            //    temp = sub_word(temp)
            // end if
            if i % AES128_KEY_LENGTH == 0 {
                temp = rot_word(temp);
                //println!("{:02}: after rotword = {:08x}", i, temp);
                temp = sub_word(temp);
                //println!("{:02}: after subword = {:08x}", i, temp);
                temp ^= RIJNDAEL_KEY_SCHEDULE[i/AES128_KEY_LENGTH];
                //println!("{:02}: after rcon xor = {:08x}", i, temp);
            }
            // w[i] = w[i-Nk] ^ temp;
            //println!("{:02}: w[{}-{}] = {:08x}", i, i, AES128_KEY_LENGTH, expanded[i-AES128_KEY_LENGTH]);
            expanded[i] = expanded[i-AES128_KEY_LENGTH] ^ temp;
            //println!("{:02}: expanded[{:02}] = {:08x}", i, i, expanded[i]);
            // i = i + 1
            i = i + 1;
        }

        AES128{ expanded }
    }

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        let mut state = AESState::new(block);

        state.add_round_key(&self.expanded[0..4]);
        for round in 1..AES128_NUM_ROUNDS {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            let start = round * AES128_BLOCK_SIZE;
            let end = (round + 1) * AES128_BLOCK_SIZE;
            state.add_round_key(&self.expanded[start..end]);
        }

        state.sub_bytes();
        state.shift_rows();
        let start = AES128_NUM_ROUNDS * AES128_BLOCK_SIZE;
        state.add_round_key(&self.expanded[start..]);

        state.decant()
    }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        let mut state = AESState::new(block);

        let last_chunk_start = AES128_NUM_ROUNDS * AES128_BLOCK_SIZE;
        state.add_round_key(&self.expanded[last_chunk_start..]);

        let mut round = AES128_NUM_ROUNDS - 1;
        while round > 0 {
            state.inv_shift_rows();
            state.inv_sub_bytes();
            let start = round * AES128_BLOCK_SIZE;
            let end = start + AES128_BLOCK_SIZE;
            state.add_round_key(&self.expanded[start..end]);
            state.inv_mix_columns();
            round -= 1;
        }
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&self.expanded[0..4]);

        state.decant()
    }
}

#[cfg(test)]
mod aes128 {
    use super::*;
    use super::aes256::RandomBlock;
    use testing::run_test;

    #[test]
    fn fips197_key_expansion_example() {
        let cipher_key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let expanded = AES128::new(&cipher_key);
        assert_eq!(expanded.expanded[00], 0x2b7e1516);
        assert_eq!(expanded.expanded[01], 0x28aed2a6);
        assert_eq!(expanded.expanded[02], 0xabf71588);
        assert_eq!(expanded.expanded[03], 0x09cf4f3c);
        assert_eq!(expanded.expanded[04], 0xa0fafe17);
        assert_eq!(expanded.expanded[05], 0x88542cb1);
        assert_eq!(expanded.expanded[06], 0x23a33939);
        assert_eq!(expanded.expanded[07], 0x2a6c7605);
        assert_eq!(expanded.expanded[08], 0xf2c295f2);
        assert_eq!(expanded.expanded[09], 0x7a96b943);
        assert_eq!(expanded.expanded[10], 0x5935807a);
        assert_eq!(expanded.expanded[11], 0x7359f67f);
        assert_eq!(expanded.expanded[12], 0x3d80477d);
        assert_eq!(expanded.expanded[13], 0x4716fe3e);
        assert_eq!(expanded.expanded[14], 0x1e237e44);
        assert_eq!(expanded.expanded[15], 0x6d7a883b);
        assert_eq!(expanded.expanded[16], 0xef44a541);
        assert_eq!(expanded.expanded[17], 0xa8525b7f);
        assert_eq!(expanded.expanded[18], 0xb671253b);
        assert_eq!(expanded.expanded[19], 0xdb0bad00);
        assert_eq!(expanded.expanded[20], 0xd4d1c6f8);
        assert_eq!(expanded.expanded[21], 0x7c839d87);
        assert_eq!(expanded.expanded[22], 0xcaf2b8bc);
        assert_eq!(expanded.expanded[23], 0x11f915bc);
        assert_eq!(expanded.expanded[24], 0x6d88a37a);
        assert_eq!(expanded.expanded[25], 0x110b3efd);
        assert_eq!(expanded.expanded[26], 0xdbf98641);
        assert_eq!(expanded.expanded[27], 0xca0093fd);
        assert_eq!(expanded.expanded[28], 0x4e54f70e);
        assert_eq!(expanded.expanded[29], 0x5f5fc9f3);
        assert_eq!(expanded.expanded[30], 0x84a64fb2);
        assert_eq!(expanded.expanded[31], 0x4ea6dc4f);
        assert_eq!(expanded.expanded[32], 0xead27321);
        assert_eq!(expanded.expanded[33], 0xb58dbad2);
        assert_eq!(expanded.expanded[34], 0x312bf560);
        assert_eq!(expanded.expanded[35], 0x7f8d292f);
        assert_eq!(expanded.expanded[36], 0xac7766f3);
        assert_eq!(expanded.expanded[37], 0x19fadc21);
        assert_eq!(expanded.expanded[38], 0x28d12941);
        assert_eq!(expanded.expanded[39], 0x575c006e);
        assert_eq!(expanded.expanded[40], 0xd014f9a8);
        assert_eq!(expanded.expanded[41], 0xc9ee2589);
        assert_eq!(expanded.expanded[42], 0xe13f0cc8);
        assert_eq!(expanded.expanded[43], 0xb6630ca6);
    }

    #[test]
    fn fips197_encrypt_examples() {
        let input1 = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
        let cipher_key1 = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let expanded1 = AES128::new(&cipher_key1);
        let ciphertext1 = expanded1.encrypt(&input1);
        assert_eq!(ciphertext1, vec![0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                                     0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32]);
        assert_eq!(input1.to_vec(), expanded1.decrypt(&ciphertext1));
        //
        let input2 = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
        let cipher_key2 = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f];
        let expanded2 = AES128::new(&cipher_key2);
        let ciphertext2 = expanded2.encrypt(&input2);
        assert_eq!(ciphertext2, vec![0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                     0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a]);
        assert_eq!(input2.to_vec(), expanded2.decrypt(&ciphertext2));
    }

    quickcheck! {
        fn encrypt_decrypt_is_identity(key: RandomBlock, block: RandomBlock) -> bool {
            let key = AES128::new(&key.block);
            let cipher = key.encrypt(&block.block);
            let block2 = key.decrypt(&cipher);
            block2 == block.block.to_vec()
        }
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

/**************************************************************************************************/
/*                                                                                                */
/* AES256 Implementation                                                                          */
/*                                                                                                */
/**************************************************************************************************/

const AES256_KEY_LENGTH: usize = 8;  // Nk
const AES256_BLOCK_SIZE: usize = 4;  // Nb
const AES256_NUM_ROUNDS: usize = 14; // Nr
const AES256_STATE_WORDS: usize = AES256_BLOCK_SIZE * (AES256_NUM_ROUNDS + 1);

pub struct AES256 {
    expanded: [u32; AES256_STATE_WORDS]
}

impl AES256 {
    pub fn new(base_key: &[u8]) -> AES256 {
        let mut expanded = [0; AES256_STATE_WORDS];
        let mut i = 0;

        assert_eq!(base_key.len(), 32);
        // while (i < Nk)
        //    w[i] = word(key[4*i],key[4*i+1],key[4*i+2],key[4*i+3])
        //    i = i+1
        // end while
        while i < AES256_KEY_LENGTH {
            expanded[i] = word(base_key[(4*i)+0], base_key[(4*i)+1],
                               base_key[(4*i)+2], base_key[(4*i)+3]);
            //println!("{:02}: expanded[{}] = {:08x}", i, i, expanded[i]);
            i = i + 1;
        }

        // i = Nk
        assert_eq!(i, AES256_KEY_LENGTH);

        // while (i < Nb * (Nr + 1))
        while i < AES256_BLOCK_SIZE * (AES256_NUM_ROUNDS+1) {
            // temp = w[i-1]
            let mut temp = expanded[i-1];
            //println!("{:02}: temp = {:08x}", i, temp);
            // if (i mod Nk = 0)
            //    temp = sub_word(rot_word(temp)) xor Rcon[i/Nk]
            // else
            //    temp = sub_word(temp)
            // end if
            if i % AES256_KEY_LENGTH == 0 {
                temp = rot_word(temp);
                //println!("{:02}: after rotword = {:08x}", i, temp);
                temp = sub_word(temp);
                //println!("{:02}: after subword = {:08x}", i, temp);
                temp ^= RIJNDAEL_KEY_SCHEDULE[i/AES256_KEY_LENGTH];
                //println!("{:02}: after rcon xor = {:08x}", i, temp);
            } else if i % 4 == 0 {
                temp = sub_word(temp);
                //println!("{:02}: after subword' = {:08x}", i, temp);
            }
            // w[i] = w[i-Nk] ^ temp;
            //println!("{:02}: w[{}-{}] = {:08x}", i, i, AES256_KEY_LENGTH, expanded[i-AES256_KEY_LENGTH]);
            expanded[i] = expanded[i-AES256_KEY_LENGTH] ^ temp;
            //println!("{:02}: expanded[{:02}] = {:08x}", i, i, expanded[i]);
            // i = i + 1
            i = i + 1;
        }

        AES256{ expanded }
    }

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        let mut state = AESState::new(block);

        assert_eq!(block.len(), 16);
        state.add_round_key(&self.expanded[0..4]);
        for round in 1..AES256_NUM_ROUNDS {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            let start = round * AES256_BLOCK_SIZE;
            let end = (round + 1) * AES256_BLOCK_SIZE;
            state.add_round_key(&self.expanded[start..end]);
        }

        state.sub_bytes();
        state.shift_rows();
        let start = AES256_NUM_ROUNDS * AES256_BLOCK_SIZE;
        state.add_round_key(&self.expanded[start..]);

        state.decant()
    }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        let mut state = AESState::new(block);

        let last_chunk_start = AES256_NUM_ROUNDS * AES256_BLOCK_SIZE;
        state.add_round_key(&self.expanded[last_chunk_start..]);

        let mut round = AES256_NUM_ROUNDS - 1;
        while round > 0 {
            state.inv_shift_rows();
            state.inv_sub_bytes();
            let start = round * AES256_BLOCK_SIZE;
            let end = start + AES256_BLOCK_SIZE;
            state.add_round_key(&self.expanded[start..end]);
            state.inv_mix_columns();
            round -= 1;
        }
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&self.expanded[0..4]);

        state.decant()
    }
}

#[cfg(test)]
pub(crate) mod aes256 {
    use quickcheck::{Arbitrary,Gen};
    use super::*;
    use testing::run_test;

    #[test]
    fn fips197_key_expansion_example() {
        let cipher_key = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                          0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                          0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                          0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4];
        let expanded = AES256::new(&cipher_key);
        assert_eq!(expanded.expanded[00], 0x603deb10);
        assert_eq!(expanded.expanded[01], 0x15ca71be);
        assert_eq!(expanded.expanded[02], 0x2b73aef0);
        assert_eq!(expanded.expanded[03], 0x857d7781);
        assert_eq!(expanded.expanded[04], 0x1f352c07);
        assert_eq!(expanded.expanded[05], 0x3b6108d7);
        assert_eq!(expanded.expanded[06], 0x2d9810a3);
        assert_eq!(expanded.expanded[07], 0x0914dff4);
        assert_eq!(expanded.expanded[08], 0x9ba35411);
        assert_eq!(expanded.expanded[09], 0x8e6925af);
        assert_eq!(expanded.expanded[10], 0xa51a8b5f);
        assert_eq!(expanded.expanded[11], 0x2067fcde);
        assert_eq!(expanded.expanded[12], 0xa8b09c1a);
        assert_eq!(expanded.expanded[13], 0x93d194cd);
        assert_eq!(expanded.expanded[14], 0xbe49846e);
        assert_eq!(expanded.expanded[15], 0xb75d5b9a);
        assert_eq!(expanded.expanded[16], 0xd59aecb8);
        assert_eq!(expanded.expanded[17], 0x5bf3c917);
        assert_eq!(expanded.expanded[18], 0xfee94248);
        assert_eq!(expanded.expanded[19], 0xde8ebe96);
        assert_eq!(expanded.expanded[20], 0xb5a9328a);
        assert_eq!(expanded.expanded[21], 0x2678a647);
        assert_eq!(expanded.expanded[22], 0x98312229);
        assert_eq!(expanded.expanded[23], 0x2f6c79b3);
        assert_eq!(expanded.expanded[24], 0x812c81ad);
        assert_eq!(expanded.expanded[25], 0xdadf48ba);
        assert_eq!(expanded.expanded[26], 0x24360af2);
        assert_eq!(expanded.expanded[27], 0xfab8b464);
        assert_eq!(expanded.expanded[28], 0x98c5bfc9);
        assert_eq!(expanded.expanded[29], 0xbebd198e);
        assert_eq!(expanded.expanded[30], 0x268c3ba7);
        assert_eq!(expanded.expanded[31], 0x09e04214);
        assert_eq!(expanded.expanded[32], 0x68007bac);
        assert_eq!(expanded.expanded[33], 0xb2df3316);
        assert_eq!(expanded.expanded[34], 0x96e939e4);
        assert_eq!(expanded.expanded[35], 0x6c518d80);
        assert_eq!(expanded.expanded[36], 0xc814e204);
        assert_eq!(expanded.expanded[37], 0x76a9fb8a);
        assert_eq!(expanded.expanded[38], 0x5025c02d);
        assert_eq!(expanded.expanded[39], 0x59c58239);
        assert_eq!(expanded.expanded[40], 0xde136967);
        assert_eq!(expanded.expanded[41], 0x6ccc5a71);
        assert_eq!(expanded.expanded[42], 0xfa256395);
        assert_eq!(expanded.expanded[43], 0x9674ee15);
        assert_eq!(expanded.expanded[44], 0x5886ca5d);
        assert_eq!(expanded.expanded[45], 0x2e2f31d7);
        assert_eq!(expanded.expanded[46], 0x7e0af1fa);
        assert_eq!(expanded.expanded[47], 0x27cf73c3);
        assert_eq!(expanded.expanded[48], 0x749c47ab);
        assert_eq!(expanded.expanded[49], 0x18501dda);
        assert_eq!(expanded.expanded[50], 0xe2757e4f);
        assert_eq!(expanded.expanded[51], 0x7401905a);
        assert_eq!(expanded.expanded[52], 0xcafaaae3);
        assert_eq!(expanded.expanded[53], 0xe4d59b34);
        assert_eq!(expanded.expanded[54], 0x9adf6ace);
        assert_eq!(expanded.expanded[55], 0xbd10190d);
        assert_eq!(expanded.expanded[56], 0xfe4890d1);
        assert_eq!(expanded.expanded[57], 0xe6188d0b);
        assert_eq!(expanded.expanded[58], 0x046df344);
        assert_eq!(expanded.expanded[59], 0x706c631e);
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

    #[derive(Clone,Debug)]
    pub(crate) struct RandomKey {
        pub(crate) key: [u8; 32]
    }

    impl Arbitrary for RandomKey {
        fn arbitrary<G: Gen>(g: &mut G) -> RandomKey {
            let mut res = RandomKey{ key: [0; 32] };
            g.fill_bytes(&mut res.key);
            res
        }
    }

    #[derive(Clone,Debug)]
    pub(crate) struct RandomBlock {
        pub(crate) block: [u8; 16]
    }

    impl Arbitrary for RandomBlock {
        fn arbitrary<G: Gen>(g: &mut G) -> RandomBlock {
            let mut res = RandomBlock{ block: [0; 16] };
            g.fill_bytes(&mut res.block);
            res
        }
    }

    quickcheck! {
        fn encrypt_decrypt_is_identity(key: RandomKey, block: RandomBlock) -> bool {
            let key = AES256::new(&key.key);
            let cipher = key.encrypt(&block.block);
            let block2 = key.decrypt(&cipher);
            block2 == block.block.to_vec()
        }
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

