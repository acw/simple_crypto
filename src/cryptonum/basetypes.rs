use std::fmt;
use std::fmt::Write;

macro_rules! generate_unsigned
{
    ($name: ident, $size: expr) => {
        pub struct $name {
            pub(crate) values: [u64; $size/64]
        }

        impl Clone for $name {
            fn clone(&self) -> $name {
                let mut result = $name{ values: [0; $size/64] };
                for (idx,val) in self.values.iter().enumerate() {
                    result.values[idx] = *val;
                }
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
                let mut wrote_something = false;
                
                for x in self.values.iter() {
                    if !wrote_something && (*x == 0) {
                        continue;
                    } else {
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
                        wrote_something = true;
                    }
                }
                if !wrote_something {
                    f.write_char('0')?
                }
                Ok(())
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut wrote_something = false;
                
                for x in self.values.iter() {
                    if !wrote_something && (*x == 0) {
                        continue;
                    } else {
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
                        wrote_something = true;
                    }
                }
                if !wrote_something {
                    f.write_char('0')?
                }
                Ok(())
            }
        }

        impl $name {
            pub fn new() -> $name {
                $name{ values: [0; $size/64 ] }
            }

            pub fn is_odd(&self) -> bool {
                (self.values[0] & 1) == 1
            }

            pub fn is_even(&self) -> bool {
                (self.values[0] & 1) == 0
            }
        }
    }
}

generate_unsigned!(U192,     192);
generate_unsigned!(U256,     256);
generate_unsigned!(U384,     384);
generate_unsigned!(U512,     512);
generate_unsigned!(U576,     576);
generate_unsigned!(U1024,   1024);
generate_unsigned!(U2048,   2048);
generate_unsigned!(U3072,   3072);
generate_unsigned!(U4096,   4096);
generate_unsigned!(U8192,   8192);
generate_unsigned!(U15360, 15360);

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