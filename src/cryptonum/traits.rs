pub trait CryptoNum {
    /// Simultaneously compute the quotient and remainder of this number and
    /// the given divisor.
    fn divmod(&self, a: &Self, q: &mut Self, r: &mut Self);
    /// Convert a number to a series of bytes, in standard order (most to
    /// least significant)
    fn to_bytes(&self) -> Vec<u8>;
    /// Convert a series of bytes into the number. The size of the given slice
    /// must be greater than or equal to the size of the number, and must be
    /// a multiple of 8 bytes long. Unused bytes should be ignored.
    fn from_bytes(&[u8]) -> Self;
}
