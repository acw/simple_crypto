use cryptonum::UCN;
use dsa::errors::*;
use dsa::generation::{DSAGenEvidence,verify_generator,
                      get_input_seed,generate_provable_primes,
                      generate_verifiable_generator,
                      validate_provable_primes};
use rand::{OsRng,Rng};

/// These are the legal lengths for L and N when using DSA; essentially,
/// the bit sizes available for the algorithms.
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum DSAParameterSize { L1024N160, L2048N224, L2048N256, L3072N256 }

pub fn n_bits(ps: DSAParameterSize) -> usize {
    match ps {
        DSAParameterSize::L1024N160 => 160,
        DSAParameterSize::L2048N224 => 224,
        DSAParameterSize::L2048N256 => 256,
        DSAParameterSize::L3072N256 => 256,
    }
}

pub fn l_bits(ps: DSAParameterSize) -> usize {
    match ps {
        DSAParameterSize::L1024N160 => 1024,
        DSAParameterSize::L2048N224 => 2048,
        DSAParameterSize::L2048N256 => 2048,
        DSAParameterSize::L3072N256 => 3072,
    }
}

/// A set of DSA parameters, which are shared across both the public and private
/// keys.
#[derive(Clone,Debug,PartialEq)]
pub struct DSAParameters {
    pub size: DSAParameterSize,
    pub p: UCN,
    pub g: UCN,
    pub q: UCN,
}

impl DSAParameters {
    /// Generate a new set of DSA parameters, from a certificate file or some
    /// other source. This will try to find an appropriate size based on the
    /// size of the values provided, but will fail (returning
    /// `DSAError::InvalidParamSize`) if it can't find a reasonable one.
    pub fn new(p: UCN, g: UCN, q: UCN)
        -> Result<DSAParameters,DSAError>
    {
        let l = ((p.bits() + 255) / 256) * 256;
        let n = ((q.bits() + 15) / 16) * 16;
        let size  = match (l, n) {
                        (1024, 160) => DSAParameterSize::L1024N160,
                        (2048, 224) => DSAParameterSize::L2048N224,
                        (2048, 256) => DSAParameterSize::L2048N256,
                        (3072, 256) => DSAParameterSize::L3072N256,
                        _           => return Err(DSAError::InvalidParamSize)
                    };
        Ok(DSAParameters{ size: size, p: p, g: g, q: q })
    }

    /// Generate a new set of DSA parameters for use. You probably shouldn't be
    /// doing this.  This is equivalent to calling `generate_w_rng` with
    /// `OsRng`, which is supposed to be cryptographically sound.
    pub fn generate(ps: DSAParameterSize)
        -> Result<DSAParameters,DSAGenError>
    {
        let mut rng = OsRng::new()?;
        DSAParameters::generate_w_rng(&mut rng, ps)
    }

    /// Generate a new set of DSA parameters for use, using the given entropy
    /// source. I would normally include a note here about making sure to use
    /// a good one, but if you're using DSA you've already given up a little
    /// bit of the high ground, there.
    pub fn generate_w_rng<G: Rng>(rng: &mut G, ps: DSAParameterSize)
        -> Result<DSAParameters,DSAGenError>
    {
        let firstseed  = get_input_seed(rng, ps, n_bits(ps))?;
        let (p, q, ev) = generate_provable_primes(rng, &firstseed, ps)?;
        DSAParameters::generate_g(ps, p, q, ev, 0)
    }

    /// Using the given p and q values and an index, create a new DSAParameters
    /// by creating a new generator g that works with p and q.
    fn generate_g(ps: DSAParameterSize,
                  p: UCN, q: UCN,
                  ev: DSAGenEvidence,
                  idx: u8)
        -> Result<DSAParameters, DSAGenError>
    {
        let g = generate_verifiable_generator(&p, &q, &ev, idx)?;
        Ok(DSAParameters{ size: ps, p: p, q: q, g: g })
    }

    /// Given the provided evidence, validate that the domain parameters
    /// were appropriately constructed.
    pub fn verify(&self, ev: &DSAGenEvidence, idx: u8) -> bool {
        let mut rng = OsRng::new().unwrap();
        self.verify_w_rng(&mut rng, ev, idx)
    }

    /// Given the set of inputs you used to generate your system, verify that
    /// everything makes sense.
    pub fn verify_w_rng<G: Rng>(&self, r: &mut G, ev: &DSAGenEvidence, idx: u8)
        -> bool
    {
        validate_provable_primes(r, &self.p, &self.q, ev) &&
        verify_generator(&self.p, &self.q, ev, idx, &self.g)
    }
}


