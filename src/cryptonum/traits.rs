use rand::Rng;

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
    /// The number of bits used when this number is serialized.
    fn bit_size(&self) -> usize;
    /// The number of bytes used when this number is serialized.
    fn byte_size(&self) -> usize;
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

pub trait CryptoNumSigned {
    /// The unsigned type that this type is related to.
    type Unsigned;

    /// Generate a new signed number based on the given unsigned number.
    fn new(x: Self::Unsigned) -> Self;
    /// Get the absolute value of the signed number, turning it back into an
    /// unsigned number.
    fn abs(&self) -> Self::Unsigned;
    /// Test if the number is negative.
    fn is_negative(&self) -> bool;
    /// Test if the number is positive.
    fn is_positive(&self) -> bool;
}

pub trait CryptoNumModOps: Sized
{
    /// Compute the modular inverse of the number.
    fn modinv(&self, b: &Self) -> Self;
    /// Raise the number to the power of the first value, mod the second.
    fn modexp(&self, a: &Self, b: &Self) -> Self;
    /// Square the number, mod the given value.
    fn modsq(&self, v: &Self) -> Self;
}

pub trait CryptoNumPrimes
{
    /// Determine if the given number is probably prime using a quick spot
    /// check and Miller-Rabin, using the given random number generator
    /// and number of iterations.
    fn probably_prime<G: Rng>(g: &mut G, iters: usize) -> bool;
    /// Generate a prime using the given random number generator, using
    /// the given number of rounds to determine if the number is probably
    /// prime. The other two numbers are a number for which the generator
    /// should have a GCD of 1, and the minimum value for the number.
    fn generate_prime<G: Rng>(g: &mut G, iters: usize, e: &Self, min: &Self)
        -> Self;
}
