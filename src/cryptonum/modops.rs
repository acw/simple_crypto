macro_rules! derive_modulo_operations
{
    ($type: ident) => {
        impl CryptoNumModOps for $type {
            fn modinv(&self, _b: &Self) -> Self {
                panic!("modinv");
            }
            fn modexp(&self, _a: &Self, _b: &Self) -> Self {
                panic!("modexp");
            }
            fn modsq(&self, _v: &Self) -> Self {
                panic!("modsq");
            }
        }
    }
}
