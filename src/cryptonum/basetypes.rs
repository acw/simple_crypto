use std::fmt;
use std::fmt::Write;

pub trait CryptoNum {
    fn zero() -> Self;
    fn is_odd(&self) -> bool;
    fn is_even(&self) -> bool;
    fn is_zero(&self) -> bool;
}

macro_rules! generate_unsigned
{
    ($name: ident, $size: expr) => {
        pub struct $name {
            pub(crate) values: [u64; $size/64]
        }

        impl Clone for $name {
            fn clone(&self) -> $name {
                let mut result = $name{ values: [0; $size/64] };
                result.values.copy_from_slice(&self.values);
                result
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, stringify!($name))?;
                write!(f, "{{ ")?;
                for x in self.values.iter() {
                    write!(f, "{:X} ", *x)?;
                }
                write!(f, "}} ")
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for x in self.values.iter().rev() {
                    f.write_char(tochar_upper(x >> 60))?;
                    f.write_char(tochar_upper(x >> 56))?;
                    f.write_char(tochar_upper(x >> 52))?;
                    f.write_char(tochar_upper(x >> 48))?;
                    f.write_char(tochar_upper(x >> 44))?;
                    f.write_char(tochar_upper(x >> 40))?;
                    f.write_char(tochar_upper(x >> 36))?;
                    f.write_char(tochar_upper(x >> 32))?;
                    f.write_char(tochar_upper(x >> 28))?;
                    f.write_char(tochar_upper(x >> 24))?;
                    f.write_char(tochar_upper(x >> 20))?;
                    f.write_char(tochar_upper(x >> 16))?;
                    f.write_char(tochar_upper(x >> 12))?;
                    f.write_char(tochar_upper(x >>  8))?;
                    f.write_char(tochar_upper(x >>  4))?;
                    f.write_char(tochar_upper(x >>  0))?;
                }
                Ok(())
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for x in self.values.iter().rev() {
                    f.write_char(tochar_lower(x >> 60))?;
                    f.write_char(tochar_lower(x >> 56))?;
                    f.write_char(tochar_lower(x >> 52))?;
                    f.write_char(tochar_lower(x >> 48))?;
                    f.write_char(tochar_lower(x >> 44))?;
                    f.write_char(tochar_lower(x >> 40))?;
                    f.write_char(tochar_lower(x >> 36))?;
                    f.write_char(tochar_lower(x >> 32))?;
                    f.write_char(tochar_lower(x >> 28))?;
                    f.write_char(tochar_lower(x >> 24))?;
                    f.write_char(tochar_lower(x >> 20))?;
                    f.write_char(tochar_lower(x >> 16))?;
                    f.write_char(tochar_lower(x >> 12))?;
                    f.write_char(tochar_lower(x >>  8))?;
                    f.write_char(tochar_lower(x >>  4))?;
                    f.write_char(tochar_lower(x >>  0))?;
                }
                Ok(())
            }
        }

        impl CryptoNum for $name {
            fn zero() -> $name {
                $name{ values: [0; $size/64 ] }
            }

            fn is_odd(&self) -> bool {
                (self.values[0] & 1) == 1
            }

            fn is_even(&self) -> bool {
                (self.values[0] & 1) == 0
            }

            fn is_zero(&self) -> bool {
                for x in self.values.iter() {
                    if *x != 0 {
                        return false;
                    }
                }
                true
            }
        }
    }
}

fn tochar_upper(x: u64) -> char {
    match (x as u8) & (0xF as u8) {
        0x0 => '0',
        0x1 => '1',
        0x2 => '2',
        0x3 => '3',
        0x4 => '4',
        0x5 => '5',
        0x6 => '6',
        0x7 => '7',
        0x8 => '8',
        0x9 => '9',
        0xA => 'A',
        0xB => 'B',
        0xC => 'C',
        0xD => 'D',
        0xE => 'E',
        0xF => 'F',
        _   => panic!("the world is broken")
    }
}

fn tochar_lower(x: u64) -> char {
    match (x as u8) & (0xF as u8) {
        0x0 => '0',
        0x1 => '1',
        0x2 => '2',
        0x3 => '3',
        0x4 => '4',
        0x5 => '5',
        0x6 => '6',
        0x7 => '7',
        0x8 => '8',
        0x9 => '9',
        0xA => 'a',
        0xB => 'b',
        0xC => 'c',
        0xD => 'd',
        0xE => 'e',
        0xF => 'f',
        _   => panic!("the world is broken")
    }
}

generate_unsigned!(U192,     192);
generate_unsigned!(U256,     256);
generate_unsigned!(U320,     320); // this is just for expansion
generate_unsigned!(U384,     384);
generate_unsigned!(U448,     448); // this is just for expansion
generate_unsigned!(U512,     512);
generate_unsigned!(U576,     576);
generate_unsigned!(U640,     640); // this is just for expansion
generate_unsigned!(U768,     768); // this is just for expansion
generate_unsigned!(U832,     832); // this is just for Barrett
generate_unsigned!(U896,     896); // this is just for Barrett
generate_unsigned!(U1024,   1024);
generate_unsigned!(U1088,   1088); // this is just for expansion
generate_unsigned!(U1152,   1152); // this is just for expansion
generate_unsigned!(U1216,   1216); // this is just for Barrett
generate_unsigned!(U1536,   1536); // this is just for expansion
generate_unsigned!(U1664,   1664); // this is just for Barrett
generate_unsigned!(U2048,   2048);
generate_unsigned!(U2112,   2112); // this is just for expansion
generate_unsigned!(U2176,   2176); // this is just for Barrett
generate_unsigned!(U2304,   2304); // this is just for expansion
generate_unsigned!(U2432,   2432); // this is just for Barrett
generate_unsigned!(U3072,   3072);
generate_unsigned!(U3136,   3136); // this is just for expansion
generate_unsigned!(U4096,   4096);
generate_unsigned!(U4160,   4160); // this is just for expansion
generate_unsigned!(U4224,   4224); // this is just for Barrett
generate_unsigned!(U6144,   6144); // this is just for expansion
generate_unsigned!(U6208,   6208); // this is just for Barrett
generate_unsigned!(U7680,   7680); // Useful for RSA key generation
generate_unsigned!(U7744,   7744); // Addition on previous
generate_unsigned!(U8192,   8192);
generate_unsigned!(U8256,   8256); // this is just for expansion
generate_unsigned!(U8320,   8320); // this is just for Barrett
generate_unsigned!(U12288, 12288); // this is just for expansion
generate_unsigned!(U12416, 12416); // this is just for Barrett
generate_unsigned!(U15360, 15360);
generate_unsigned!(U15424, 15424); // this is just for expansion
generate_unsigned!(U16384, 16384); // this is just for expansion
generate_unsigned!(U16448, 16448); // this is just for Barrett
generate_unsigned!(U16512, 16512); // this is just for Barrett
generate_unsigned!(U30720, 30720); // this is just for expansion
generate_unsigned!(U30784, 30784); // this is just for Barrett
generate_unsigned!(U32768, 32768); // this is just for expansion
generate_unsigned!(U32896, 32896); // this is just for Barrett
generate_unsigned!(U61440, 61440); // this is just for expansion
generate_unsigned!(U61568, 61568); // this is just for Barrett
