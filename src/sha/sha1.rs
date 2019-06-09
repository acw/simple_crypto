use byteorder::{BigEndian,WriteBytesExt};
use super::super::Hash;
use sha::shared::calculate_k;

/// The SHA1 hash. Don't use this except to support legacy systems.
/// 
/// To use, you can run it in incremental mode -- by calling new(),
/// update() zero or more times, and then finalize() -- or you can
/// just invoke the hash directly. For example:
/// 
/// ```rust
/// use simple_crypto::sha::{Hash,SHA1};
/// 
/// let empty = [0; 0];
/// // Do the hash using the incremental API
/// let mut hashf = SHA1::new();
/// hashf.update(&empty);
/// let result_incremental = hashf.finalize();
/// // Do the hash using the direct API
/// let result_direct = SHA1::hash(&empty);
/// // ... and they should be the same
/// assert_eq!(result_incremental,result_direct);
/// ```
#[derive(Clone)]
pub struct SHA1 {
    state: [u32; 5],
    buffer: Vec<u8>,
    done: bool,
    l: usize
}

macro_rules! sha1_step {
    ($op: ident, $out: ident, $ins: expr, $k: expr, $w: ident) => {
        let $out = {
            let [a,b,c,d,e] = $ins;
            let ap = a.rotate_left(5) + $op!(b,c,d) + e + $k + $w;
            let bp = a;
            let cp = b.rotate_left(30);
            let dp = c;
            let ep = d;
            [ap, bp, cp, dp, ep]    
        };
     };
}

impl SHA1 {
    fn process(&mut self, w00: u32, w01: u32, w02: u32, w03: u32,
                          w04: u32, w05: u32, w06: u32, w07: u32,
                          w08: u32, w09: u32, w10: u32, w11: u32,
                          w12: u32, w13: u32, w14: u32, w15: u32)
    {
        let w16 = (w13 ^ w08 ^ w02 ^ w00).rotate_left(1);
        let w17 = (w14 ^ w09 ^ w03 ^ w01).rotate_left(1);
        let w18 = (w15 ^ w10 ^ w04 ^ w02).rotate_left(1);
        let w19 = (w16 ^ w11 ^ w05 ^ w03).rotate_left(1);
        let w20 = (w17 ^ w12 ^ w06 ^ w04).rotate_left(1);
        let w21 = (w18 ^ w13 ^ w07 ^ w05).rotate_left(1);
        let w22 = (w19 ^ w14 ^ w08 ^ w06).rotate_left(1);
        let w23 = (w20 ^ w15 ^ w09 ^ w07).rotate_left(1);
        let w24 = (w21 ^ w16 ^ w10 ^ w08).rotate_left(1);
        let w25 = (w22 ^ w17 ^ w11 ^ w09).rotate_left(1);
        let w26 = (w23 ^ w18 ^ w12 ^ w10).rotate_left(1);
        let w27 = (w24 ^ w19 ^ w13 ^ w11).rotate_left(1);
        let w28 = (w25 ^ w20 ^ w14 ^ w12).rotate_left(1);
        let w29 = (w26 ^ w21 ^ w15 ^ w13).rotate_left(1);
        let w30 = (w27 ^ w22 ^ w16 ^ w14).rotate_left(1);
        let w31 = (w28 ^ w23 ^ w17 ^ w15).rotate_left(1);
        let w32 = (w29 ^ w24 ^ w18 ^ w16).rotate_left(1);
        let w33 = (w30 ^ w25 ^ w19 ^ w17).rotate_left(1);
        let w34 = (w31 ^ w26 ^ w20 ^ w18).rotate_left(1);
        let w35 = (w32 ^ w27 ^ w21 ^ w19).rotate_left(1);
        let w36 = (w33 ^ w28 ^ w22 ^ w20).rotate_left(1);
        let w37 = (w34 ^ w29 ^ w23 ^ w21).rotate_left(1);
        let w38 = (w35 ^ w30 ^ w24 ^ w22).rotate_left(1);
        let w39 = (w36 ^ w31 ^ w25 ^ w23).rotate_left(1);
        let w40 = (w37 ^ w32 ^ w26 ^ w24).rotate_left(1);
        let w41 = (w38 ^ w33 ^ w27 ^ w25).rotate_left(1);
        let w42 = (w39 ^ w34 ^ w28 ^ w26).rotate_left(1);
        let w43 = (w40 ^ w35 ^ w29 ^ w27).rotate_left(1);
        let w44 = (w41 ^ w36 ^ w30 ^ w28).rotate_left(1);
        let w45 = (w42 ^ w37 ^ w31 ^ w29).rotate_left(1);
        let w46 = (w43 ^ w38 ^ w32 ^ w30).rotate_left(1);
        let w47 = (w44 ^ w39 ^ w33 ^ w31).rotate_left(1);
        let w48 = (w45 ^ w40 ^ w34 ^ w32).rotate_left(1);
        let w49 = (w46 ^ w41 ^ w35 ^ w33).rotate_left(1);
        let w50 = (w47 ^ w42 ^ w36 ^ w34).rotate_left(1);
        let w51 = (w48 ^ w43 ^ w37 ^ w35).rotate_left(1);
        let w52 = (w49 ^ w44 ^ w38 ^ w36).rotate_left(1);
        let w53 = (w50 ^ w45 ^ w39 ^ w37).rotate_left(1);
        let w54 = (w51 ^ w46 ^ w40 ^ w38).rotate_left(1);
        let w55 = (w52 ^ w47 ^ w41 ^ w39).rotate_left(1);
        let w56 = (w53 ^ w48 ^ w42 ^ w40).rotate_left(1);
        let w57 = (w54 ^ w49 ^ w43 ^ w41).rotate_left(1);
        let w58 = (w55 ^ w50 ^ w44 ^ w42).rotate_left(1);
        let w59 = (w56 ^ w51 ^ w45 ^ w43).rotate_left(1);
        let w60 = (w57 ^ w52 ^ w46 ^ w44).rotate_left(1);
        let w61 = (w58 ^ w53 ^ w47 ^ w45).rotate_left(1);
        let w62 = (w59 ^ w54 ^ w48 ^ w46).rotate_left(1);
        let w63 = (w60 ^ w55 ^ w49 ^ w47).rotate_left(1);
        let w64 = (w61 ^ w56 ^ w50 ^ w48).rotate_left(1);
        let w65 = (w62 ^ w57 ^ w51 ^ w49).rotate_left(1);
        let w66 = (w63 ^ w58 ^ w52 ^ w50).rotate_left(1);
        let w67 = (w64 ^ w59 ^ w53 ^ w51).rotate_left(1);
        let w68 = (w65 ^ w60 ^ w54 ^ w52).rotate_left(1);
        let w69 = (w66 ^ w61 ^ w55 ^ w53).rotate_left(1);
        let w70 = (w67 ^ w62 ^ w56 ^ w54).rotate_left(1);
        let w71 = (w68 ^ w63 ^ w57 ^ w55).rotate_left(1);
        let w72 = (w69 ^ w64 ^ w58 ^ w56).rotate_left(1);
        let w73 = (w70 ^ w65 ^ w59 ^ w57).rotate_left(1);
        let w74 = (w71 ^ w66 ^ w60 ^ w58).rotate_left(1);
        let w75 = (w72 ^ w67 ^ w61 ^ w59).rotate_left(1);
        let w76 = (w73 ^ w68 ^ w62 ^ w60).rotate_left(1);
        let w77 = (w74 ^ w69 ^ w63 ^ w61).rotate_left(1);
        let w78 = (w75 ^ w70 ^ w64 ^ w62).rotate_left(1);
        let w79 = (w76 ^ w71 ^ w65 ^ w63).rotate_left(1);
        sha1_step!(ch, s01, self.state, 0x5a827999, w00);
        sha1_step!(ch, s02, s01, 0x5a827999, w01);
        sha1_step!(ch, s03, s02, 0x5a827999, w02);
        sha1_step!(ch, s04, s03, 0x5a827999, w03);
        sha1_step!(ch, s05, s04, 0x5a827999, w04);
        sha1_step!(ch, s06, s05, 0x5a827999, w05);
        sha1_step!(ch, s07, s06, 0x5a827999, w06);
        sha1_step!(ch, s08, s07, 0x5a827999, w07);
        sha1_step!(ch, s09, s08, 0x5a827999, w08);
        sha1_step!(ch, s10, s09, 0x5a827999, w09);
        sha1_step!(ch, s11, s10, 0x5a827999, w10);
        sha1_step!(ch, s12, s11, 0x5a827999, w11);
        sha1_step!(ch, s13, s12, 0x5a827999, w12);
        sha1_step!(ch, s14, s13, 0x5a827999, w13);
        sha1_step!(ch, s15, s14, 0x5a827999, w14);
        sha1_step!(ch, s16, s15, 0x5a827999, w15);
        sha1_step!(ch, s17, s16, 0x5a827999, w16);
        sha1_step!(ch, s18, s17, 0x5a827999, w17);
        sha1_step!(ch, s19, s18, 0x5a827999, w18);
        sha1_step!(ch, s20, s19, 0x5a827999, w19);
        sha1_step!(parity, s21, s20, 0x6ed9eba1, w20);
        sha1_step!(parity, s22, s21, 0x6ed9eba1, w21);
        sha1_step!(parity, s23, s22, 0x6ed9eba1, w22);
        sha1_step!(parity, s24, s23, 0x6ed9eba1, w23);
        sha1_step!(parity, s25, s24, 0x6ed9eba1, w24);
        sha1_step!(parity, s26, s25, 0x6ed9eba1, w25);
        sha1_step!(parity, s27, s26, 0x6ed9eba1, w26);
        sha1_step!(parity, s28, s27, 0x6ed9eba1, w27);
        sha1_step!(parity, s29, s28, 0x6ed9eba1, w28);
        sha1_step!(parity, s30, s29, 0x6ed9eba1, w29);
        sha1_step!(parity, s31, s30, 0x6ed9eba1, w30);
        sha1_step!(parity, s32, s31, 0x6ed9eba1, w31);
        sha1_step!(parity, s33, s32, 0x6ed9eba1, w32);
        sha1_step!(parity, s34, s33, 0x6ed9eba1, w33);
        sha1_step!(parity, s35, s34, 0x6ed9eba1, w34);
        sha1_step!(parity, s36, s35, 0x6ed9eba1, w35);
        sha1_step!(parity, s37, s36, 0x6ed9eba1, w36);
        sha1_step!(parity, s38, s37, 0x6ed9eba1, w37);
        sha1_step!(parity, s39, s38, 0x6ed9eba1, w38);
        sha1_step!(parity, s40, s39, 0x6ed9eba1, w39);
        sha1_step!(maj, s41, s40, 0x8f1bbcdc, w40);
        sha1_step!(maj, s42, s41, 0x8f1bbcdc, w41);
        sha1_step!(maj, s43, s42, 0x8f1bbcdc, w42);
        sha1_step!(maj, s44, s43, 0x8f1bbcdc, w43);
        sha1_step!(maj, s45, s44, 0x8f1bbcdc, w44);
        sha1_step!(maj, s46, s45, 0x8f1bbcdc, w45);
        sha1_step!(maj, s47, s46, 0x8f1bbcdc, w46);
        sha1_step!(maj, s48, s47, 0x8f1bbcdc, w47);
        sha1_step!(maj, s49, s48, 0x8f1bbcdc, w48);
        sha1_step!(maj, s50, s49, 0x8f1bbcdc, w49);
        sha1_step!(maj, s51, s50, 0x8f1bbcdc, w50);
        sha1_step!(maj, s52, s51, 0x8f1bbcdc, w51);
        sha1_step!(maj, s53, s52, 0x8f1bbcdc, w52);
        sha1_step!(maj, s54, s53, 0x8f1bbcdc, w53);
        sha1_step!(maj, s55, s54, 0x8f1bbcdc, w54);
        sha1_step!(maj, s56, s55, 0x8f1bbcdc, w55);
        sha1_step!(maj, s57, s56, 0x8f1bbcdc, w56);
        sha1_step!(maj, s58, s57, 0x8f1bbcdc, w57);
        sha1_step!(maj, s59, s58, 0x8f1bbcdc, w58);
        sha1_step!(maj, s60, s59, 0x8f1bbcdc, w59);
        sha1_step!(parity, s61, s60, 0xca62c1d6, w60);
        sha1_step!(parity, s62, s61, 0xca62c1d6, w61);
        sha1_step!(parity, s63, s62, 0xca62c1d6, w62);
        sha1_step!(parity, s64, s63, 0xca62c1d6, w63);
        sha1_step!(parity, s65, s64, 0xca62c1d6, w64);
        sha1_step!(parity, s66, s65, 0xca62c1d6, w65);
        sha1_step!(parity, s67, s66, 0xca62c1d6, w66);
        sha1_step!(parity, s68, s67, 0xca62c1d6, w67);
        sha1_step!(parity, s69, s68, 0xca62c1d6, w68);
        sha1_step!(parity, s70, s69, 0xca62c1d6, w69);
        sha1_step!(parity, s71, s70, 0xca62c1d6, w70);
        sha1_step!(parity, s72, s71, 0xca62c1d6, w71);
        sha1_step!(parity, s73, s72, 0xca62c1d6, w72);
        sha1_step!(parity, s74, s73, 0xca62c1d6, w73);
        sha1_step!(parity, s75, s74, 0xca62c1d6, w74);
        sha1_step!(parity, s76, s75, 0xca62c1d6, w75);
        sha1_step!(parity, s77, s76, 0xca62c1d6, w76);
        sha1_step!(parity, s78, s77, 0xca62c1d6, w77);
        sha1_step!(parity, s79, s78, 0xca62c1d6, w78);
        sha1_step!(parity, s80, s79, 0xca62c1d6, w79);
        self.state[0] += s80[0];
        self.state[1] += s80[1];
        self.state[2] += s80[2];
        self.state[3] += s80[3];
        self.state[4] += s80[4];
    }

    fn finish(&mut self)
    {
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

impl Hash for SHA1
{
    fn new() -> SHA1
    {
        SHA1 {
            state: [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ],
            buffer: Vec::with_capacity(64),
            done: false,
            l: 0
        }
    }

    fn update(&mut self, block: &[u8])
    {
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

    fn finalize(&mut self) -> Vec<u8>
    {
        if !self.done {
            self.finish();
        }

        let mut output = Vec::with_capacity(20);
        output.write_u32::<BigEndian>(self.state[0]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state[1]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state[2]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state[3]).expect("Broken writing value to pre-allocated Vec?");
        output.write_u32::<BigEndian>(self.state[4]).expect("Broken writing value to pre-allocated Vec?");
        output
    }

    fn block_size() -> usize
    {
        512
    }
}

#[cfg(test)]
use testing::run_test;

#[cfg(test)]
#[test]
fn nist() {
    let fname = "testdata/sha/nist_sha1.test";
    run_test(fname.to_string(), 3, |case| {
        let (negl, lbytes) = case.get("l").unwrap();
        let (negm, mbytes) = case.get("m").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!negl && !negm && !negd);
        let msg = if lbytes[0] == 0 { Vec::new() } else { mbytes.clone() }; 
        let digest = SHA1::hash(&msg);
        assert_eq!(dbytes, &digest);
    });
}

