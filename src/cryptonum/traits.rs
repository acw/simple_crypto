
pub trait CryptoNum {
    fn divmod(&self, a: &Self, q: &mut Self, r: &mut Self);
}

