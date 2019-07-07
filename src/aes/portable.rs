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
/* AES256 Implementation                                                                          */
/*                                                                                                */
/**************************************************************************************************/

const AES128_KEY_LENGTH: usize = 4;  // Nk
const AES128_BLOCK_SIZE: usize = 4;  // Nb
const AES128_NUM_ROUNDS: usize = 10; // Nr
const AES128_STATE_WORDS: usize = AES128_BLOCK_SIZE * (AES128_NUM_ROUNDS + 1);

struct AES128 {
    expanded: [u32; AES128_STATE_WORDS]
}

impl AES128 {
    pub fn new(base_key: &[u8; 16]) -> AES128 {
        let mut expanded = [0; AES128_STATE_WORDS];
        let mut i = 0;

        // while (i < Nk)
        //    w[i] = word(key[4*i],key[4*i+1],key[4*i+2],key[4*i+3])
        //    i = i+1
        // end while
        while i < AES128_KEY_LENGTH {
            expanded[i] = word(base_key[(4*i)+0], base_key[(4*i)+1],
                               base_key[(4*i)+2], base_key[(4*i)+3]);
            println!("{:02}: expanded[{}] = {:08x}", i, i, expanded[i]);
            i = i + 1;
        }

        // i = Nk
        assert_eq!(i, AES128_KEY_LENGTH);

        // while (i < Nb * (Nr + 1))
        while i < AES128_BLOCK_SIZE * (AES128_NUM_ROUNDS+1) {
            // temp = w[i-1]
            let mut temp = expanded[i-1];
            println!("{:02}: temp = {:08x}", i, temp);
            // if (i mod Nk = 0)
            //    temp = sub_word(rot_word(temp)) xor Rcon[i/Nk]
            // else
            //    temp = sub_word(temp)
            // end if
            if i % AES128_KEY_LENGTH == 0 {
                temp = rot_word(temp);
                println!("{:02}: after rotword = {:08x}", i, temp);
                temp = sub_word(temp);
                println!("{:02}: after subword = {:08x}", i, temp);
                temp ^= RIJNDAEL_KEY_SCHEDULE[i/AES128_KEY_LENGTH];
                println!("{:02}: after rcon xor = {:08x}", i, temp);
            }
            // w[i] = w[i-Nk] ^ temp;
            println!("{:02}: w[{}-{}] = {:08x}", i, i, AES128_KEY_LENGTH, expanded[i-AES128_KEY_LENGTH]);
            expanded[i] = expanded[i-AES128_KEY_LENGTH] ^ temp;
            println!("{:02}: expanded[{:02}] = {:08x}", i, i, expanded[i]);
            // i = i + 1
            i = i + 1;
        }

        AES128{ expanded }
    }
}

#[cfg(test)]
mod aes128 {
    use super::*;

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

struct AES256 {
    expanded: [u32; AES256_STATE_WORDS]
}

impl AES256 {
    pub fn new(base_key: &[u8; 32]) -> AES256 {
        let mut expanded = [0; AES256_STATE_WORDS];
        let mut i = 0;

        // while (i < Nk)
        //    w[i] = word(key[4*i],key[4*i+1],key[4*i+2],key[4*i+3])
        //    i = i+1
        // end while
        while i < AES256_KEY_LENGTH {
            expanded[i] = word(base_key[(4*i)+0], base_key[(4*i)+1],
                               base_key[(4*i)+2], base_key[(4*i)+3]);
            println!("{:02}: expanded[{}] = {:08x}", i, i, expanded[i]);
            i = i + 1;
        }

        // i = Nk
        assert_eq!(i, AES256_KEY_LENGTH);

        // while (i < Nb * (Nr + 1))
        while i < AES256_BLOCK_SIZE * (AES256_NUM_ROUNDS+1) {
            // temp = w[i-1]
            let mut temp = expanded[i-1];
            println!("{:02}: temp = {:08x}", i, temp);
            // if (i mod Nk = 0)
            //    temp = sub_word(rot_word(temp)) xor Rcon[i/Nk]
            // else
            //    temp = sub_word(temp)
            // end if
            if i % AES256_KEY_LENGTH == 0 {
                temp = rot_word(temp);
                println!("{:02}: after rotword = {:08x}", i, temp);
                temp = sub_word(temp);
                println!("{:02}: after subword = {:08x}", i, temp);
                temp ^= RIJNDAEL_KEY_SCHEDULE[i/AES256_KEY_LENGTH];
                println!("{:02}: after rcon xor = {:08x}", i, temp);
            } else if i % 4 == 0 {
                temp = sub_word(temp);
                println!("{:02}: after subword' = {:08x}", i, temp);
            }
            // w[i] = w[i-Nk] ^ temp;
            println!("{:02}: w[{}-{}] = {:08x}", i, i, AES256_KEY_LENGTH, expanded[i-AES256_KEY_LENGTH]);
            expanded[i] = expanded[i-AES256_KEY_LENGTH] ^ temp;
            println!("{:02}: expanded[{:02}] = {:08x}", i, i, expanded[i]);
            // i = i + 1
            i = i + 1;
        }

        AES256{ expanded }
    }
}

#[cfg(test)]
mod aes256 {
    use super::*;

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
}

