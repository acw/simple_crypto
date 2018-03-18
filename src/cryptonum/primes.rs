macro_rules! derive_prime_operations
{
    ($type: ident) => {
        impl CryptoNumPrimes for $type {
            fn probably_prime<G: Rng>(_g: &mut G, _iters: usize) -> bool {
                panic!("probably_prime");
            }
            fn generate_prime<G: Rng>(_g: &mut G, _iters: usize, _e: &Self, _min: &Self) -> Self {
                panic!("generate_prime");
            }
        }
    }
}
