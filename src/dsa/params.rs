use cryptonum::unsigned::{CryptoNum,Decoder,Encoder,ModExp,PrimeGen};
use cryptonum::unsigned::{U192,U256,U1024,U2048,U3072};
use digest::Digest;
use sha2::Sha256;
use simple_asn1::{ToASN1,ASN1Block,ASN1Class,ASN1EncodeErr};
use rand::Rng;
use utils::TranslateNums;

/// A trait that describes what a set of DSA parameters must support in
/// order to be used by the rest of the system.
pub trait DSAParameters : ToASN1
{
    /// The fixed-width, unsigned type of values in L.
    type L;
    /// The fixed-width, unsigned type of values in N.
    type N;

    /// Given a `p`, `g`, and `q`, generate a new structure that includes
    /// this information. Optionally, do any cross-checks needed.
    fn new(p: Self::L, g: Self::L, q: Self::N) -> Self;
    /// Generate a new set of DSA parameters given the provided random
    /// number generator. Just as with key generation, this should be a
    /// cryptographically-strong random number generator. If it's not,
    /// you may be writing compromisable code.
    fn generate<G: Rng>(rng: &mut G) -> Self;
    /// Return the size of values of N in bits.
    fn n_size() -> usize;
    /// Return the size of values of L in bits.
    fn l_size() -> usize;
    /// Return the size of `q` in this particular instance of the parameters.
    /// (Should be the same as `n_size()`, and the default implementation
    /// simply uses `n_size(), but included for convenience)
    fn n_bits(&self) -> usize {
        Self::n_size()
    }
}

macro_rules! generate_parameters {
    ($name: ident, $ltype: ident, $ntype: ident, $l: expr, $n: expr) => {
        /// DSA parameters to the given L and N, with the values given in bits.
        #[derive(Clone,PartialEq)]
        pub struct $name {
            pub p: $ltype,
            pub g: $ltype,
            pub q: $ntype
        }

        impl ToASN1 for $name {
            type Error = ASN1EncodeErr;

            fn to_asn1_class(&self, c: ASN1Class)
                -> Result<Vec<ASN1Block>,ASN1EncodeErr>
            {
                let p = ASN1Block::Integer(c, 0, self.p.to_num());
                let q = ASN1Block::Integer(c, 0, self.q.to_num());
                let g = ASN1Block::Integer(c, 0, self.g.to_num());
                Ok(vec![ASN1Block::Sequence(c, 0, vec![p, q, g])])
            }
        }

        impl DSAParameters for $name
        {
            type L = $ltype;
            type N = $ntype;

            fn new(p: $ltype, g: $ltype, q: $ntype) -> $name
            {
                $name{ p: p, g: g, q: q }
            }

            fn generate<G: Rng>(rng: &mut G) -> $name
            {
                let (p, q, _, _) = $name::generate_primes(rng);
                let g = $name::generate_g(rng, &p, &q);
                $name{ p: p, g: g, q: q }
            }

            fn l_size() -> usize {
                $l
            }

            fn n_size() -> usize {
                $n
            }
        }

        impl $name
        {
            fn generate_primes<G: Rng>(rng: &mut G) -> ($ltype,$ntype,U256,usize)
            {
                // This is A.1.1.2 from FIPS 186-4, with seedlen hardcoded to 256
                // (since that's guaranteed to be >= N), and with the hash
                // hardcoded as SHA-256.
                #[allow(non_snake_case)]
                let L = $ltype::bit_length();
                #[allow(non_snake_case)]
                let N = $ntype::bit_length();
                let seedlen = 256;
                let outlen = 256;
                //
                // 1. Check that the (L,N) pair is in the list of acceptable
                //    (L,N) pairs (see Section 4.2). If the pair is not in the
                //    list, then return INVALID.
                // [This is always true.]
                //
                // 2. If (seedlen < N), then return INVALID.
                // [This is always true.]
                //
                // 3. n = L/outlen – 1. 
                let n = ((L + 255) / 256) - 1;
                // 4. b = L – 1 – (n ∗ outlen). 
                let b = L - 1 - (n * outlen);
                loop {
                    // 5. Get an arbitrary sequence of seedlen bits as the
                    //    domain_parameter_seed.
                    let domain_parameter_seed: U256 = rng.gen();
                    // 6. U = Hash (domain_parameter_seed) mod 2^(N–1).
                    let mut ubytes = hash(&domain_parameter_seed, 32);
                    while ubytes.len() > (N / 8) { ubytes.remove(0); }
                    #[allow(non_snake_case)]
                    let U = $ntype::from_bytes(&ubytes);
                    // 7. q = 2^(N–1) + U + 1 – (U mod 2).
                    let ulow = if U.is_even() { 0 } else { 1 };
                    let mut q = $ntype::from(1u64) << (N - 1);
                    q += U;
                    q += $ntype::from(1u64 + ulow);
                    // 8. Test whether or not q is prime as specified in Appendix C.3. 
                    let q_is_prime = q.probably_prime(rng, 40);
                    // 9. If q is not a prime, then go to step 5. 
                    if !q_is_prime {
                        continue;
                    }
                    // 10. offset = 1. 
                    let mut offset = 1;
                    // 11. For counter = 0 to (4L – 1) do
                    for counter in 0..(4*L)-1 {
                        // 11.1 For j = 0 to n do
                        //    Vj = Hash ((domain_parameter_seed + offset + j) mod 2^seedlen).
                        #[allow(non_snake_case)]
                        let mut V = Vec::new();
                        for j in 0..n {
                            let val = &domain_parameter_seed + U256::from(offset + j);
                            let bytes = hash(&val, 32);
                            assert_eq!(seedlen, bytes.len());
                            V.push(bytes);
                        }
                        // 11.2 W = V_0 + ( V_1 ∗ 2^outlen) + ... + ( V_(n–1) ∗ 2^(n –1) ∗ outlen) + ((V_n mod 2^b) ∗ 2^(n ∗ outlen).
                        #[allow(non_snake_case)]
                        let mut W = $ltype::zero();
                        for (idx, val) in V.iter().enumerate() {
                            if idx < n {
                                let mut base = val.clone();
                                let baselen = base.len();
                                base.resize(baselen + (idx * (outlen / 8)), 0);
                                W += $ltype::from_bytes(&base);
                            } else {
                                let base = $ltype::from_bytes(val);
                                let twob = $ltype::from(1u64) << b;
                                let val = base % twob;
                                W += val << (n * outlen);
                            }
                        }
                        // 11.3 X = W + 2^(L – 1).
                        //   Comment: 0 ≤ W < 2 L – 1 ; hence, 2 L – 1  ≤ X < 2 L . 
                        #[allow(non_snake_case)]
                        let mut X = $ltype::from(1u64) << (L - 1);
                        X += W;
                        // 11.4 c = X mod 2q. 
                        let c = &X % ($ltype::from(&q) << 1);
                        // 11.5 p = X – ( c – 1). 
                        //   Comment: p ≡ 1 ( mod 2 q) .
                        let p = &X - (c - $ltype::from(1u64));
                        // 11.6 If ( p < 2L – 1), then go to step 11.9. 
                        if p >= $ltype::from((2*L) - 1) {
                            // 11.7 Test whether or not p is prime as specified in Appendix C .3. 
                            if p.probably_prime(rng, 40) {
                                // 11.8 If p is determined to be prime, then return VALID and the values of p , q and (optionally) the values of domain_parameter_seed and counter . 
                                return (p, q, domain_parameter_seed, counter);
                            }
                        }
                        // 11.9 offset = offset + n + 1. 
                        offset = offset + n + 1;
                    }
                }
            }

            fn generate_g<G: Rng>(rng: &mut G, p: &$ltype, q: &$ntype) -> $ltype
            {
                let bigq = $ltype::from(q);
                let p_minus_1 = p - $ltype::from(1u64);
                // This is A.2.1 (Unverifiable Generation of g) from FIPS 186-4.
                // 1. e = (p – 1) / q.
                let e = (p - $ltype::from(1u64)) / bigq;
                loop {
                    // 2. Set h = any integer satisfying 1 < h < ( p – 1), such that
                    //    h differs from any value previously tried. Note that h could
                    //    be obtained from a random number generator or from a counter
                    //    that changes after each use.
                    let h = rng.gen_range($ltype::from(2u64), &p_minus_1);
                    // 3. g = h^e mod p.
                    let g = h.modexp(&e, p);
                    // 4. If ( g = 1), then go to step 2. 
                    if g != $ltype::from(1u64) {
                        // 5. Return g
                        return g;
                    }
                }
            }
        }
    };
}

generate_parameters!(L1024N160, U1024, U192, 1024, 160);
generate_parameters!(L2048N224, U2048, U256, 2048, 224);
generate_parameters!(L2048N256, U2048, U256, 2048, 256);
generate_parameters!(L3072N256, U3072, U256, 3072, 256);

fn hash<T>(x: &T, len: usize) -> Vec<u8>
 where T: Encoder
{
    let mut base = x.to_bytes();
    let bytelen = len / 8;
    while base.len() < bytelen {
        base.insert(0,0);
    }
    Sha256::digest(&base).as_slice().to_vec()
}