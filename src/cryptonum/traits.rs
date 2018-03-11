pub trait CryptoNumBase {
    /// Generate the zero value for this type.
    fn zero() -> Self;
    /// Generate the maximum possible value for this type.
    fn max_value() -> Self;
    /// Test if the number is zero.
    fn is_zero(&self) -> bool;
    /// Test if the number is odd (a.k.a., the low bit is set)
    fn is_odd(&self) -> bool;
    /// Test if the number is even (a.k.a., the low bit is clear)
    fn is_even(&self) -> bool;
    /// Translate a `u8` to this type. This must be safe.
    fn from_u8(x: u8) -> Self;
    /// Convert this back into a `u8`. This is the equivalent of masking off
    /// the lowest 8 bits and then casting to a `u8`.
    fn to_u8(&self) -> u8;
    /// Translate a `u16` to this type. This must be safe.
    fn from_u16(x: u16) -> Self;
    /// Convert this back into a `u16`. This is the equivalent of masking off
    /// the lowest 16 bits and then casting to a `u16`.
    fn to_u16(&self) -> u16;
    /// Translate a `u32` to this type. This must be safe.
    fn from_u32(x: u32) -> Self;
    /// Convert this back into a `u32`. This is the equivalent of masking off
    /// the lowest 32 bits and then casting to a `u32`.
    fn to_u32(&self) -> u32;
    /// Translate a `u64` to this type. This must be safe.
    fn from_u64(x: u64) -> Self;
    /// Convert this back into a `u64`. This is the equivalent of masking off
    /// the lowest 64 bits and then casting to a `u64`.
    fn to_u64(&self) -> u64;
}

pub trait CryptoNumSerialization {
    /// Convert a number to a series of bytes, in standard order (most to
    /// least significant)
    fn to_bytes(&self) -> Vec<u8>;
    /// Convert a series of bytes into the number. The size of the given slice
    /// must be greater than or equal to the size of the number, and must be
    /// a multiple of 8 bytes long. Unused bytes should be ignored.
    fn from_bytes(&[u8]) -> Self;
}

pub trait CryptoNumFastMod {
    /// A related type that can hold the constant required for Barrett
    /// reduction.
    type BarrettMu;

    /// Compute the Barett constant mu, using this as a modulus, which we can
    /// use later to perform faster mod operations.
    fn barrett_mu(&self) -> Option<Self::BarrettMu>;
    /// Faster modulo through the use of the Barrett constant, above.
    fn fastmod(&self, &Self::BarrettMu) -> Self;
}
