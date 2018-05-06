use cryptonum::UCN;
use digest::{FixedOutput,Input};
use dsa::errors::DSAGenError;
use dsa::parameters::{DSAParameterSize,n_bits,l_bits};
use rand::Rng;
use sha2::Sha256;
use std::ops::{Add,Div,Rem,Sub};

#[derive(Debug,PartialEq)]
pub struct DSAGenEvidence {
    pub first_seed:   UCN,
    pub p_seed:       UCN,
    pub q_seed:       UCN,
    pub pgen_counter: usize,
    pub qgen_counter: usize
}

fn get_domain_parameter_seed(ev: &DSAGenEvidence) -> Vec<u8> {
    let mut output = Vec::new();
    let fssize = (ev.first_seed.bits() + 7) / 8;
    output.append(&mut ev.first_seed.to_bytes(fssize));
    let psize = (ev.p_seed.bits() + 7) / 8;
    output.append(&mut ev.p_seed.to_bytes(psize));
    let qsize = (ev.q_seed.bits() + 7) / 8;
    output.append(&mut ev.q_seed.to_bytes(qsize));
    output
}

pub fn generate_provable_primes<G: Rng>(rng: &mut G,
                                        firstseed: &UCN,
                                        ps: DSAParameterSize)
    -> Result<(UCN, UCN, DSAGenEvidence),DSAGenError>
{
    let one: UCN = UCN::from(1u64);
    let two: UCN = UCN::from(2u64);
    let three: UCN = UCN::from(3u64);
    // See Page 38 of FIPS 186-4!
    let n = n_bits(ps);
    let l = l_bits(ps);
    // 1. Check that the (L, N) pair is in the list of acceptable (L, N) pairs
    //    (see Section 4.2). If the pair is not in the list, return FAILURE.
    //
    //  Done because sum types are cool.
    //
    // 2. Using N as the length and firstseed as the input_seed, use the random
    //    prime generation routine in Appendix C.6 to obtain q, qseed and
    //    qgen_counter. If FAILURE is returned, then return FAILURE.
    let (q, qseed, qgen_counter) = shawe_taylor(rng, n, &firstseed)?;
    // 3. Using ceiling(L / 2 + 1) as the length and qseed as the input_seed,
    //    use the random prime generation routine in Appendix C.6 to obtain
    //    p0, pseed, and pgen_counter. If FAILURE is returned, then return
    //    FAILURE.
    //
    //  NOTE: The ceiling isn't required. All of the values of L divide
    //        evenly by 2, so it's just l / 2 + 1. I'm not sure why the
    //        spec mentions it, frankly.
    let (p0, mut pseed, mut pgen_counter) = shawe_taylor(rng, l/2 + 1, &qseed)?;
    // 4. iterations = ceiling(L / outlen) - 1.
    let iterations = ceildiv(&l, &256) - 1;
    // 5. old_counter = pgen_counter.
    let old_counter = pgen_counter;
    // 6. x = 0.
    let mut x_bytes = Vec::new();
    // 7. For i = 0 to iterations fo
    //      x + x + (Hash(pseed + i) * 2^(i * outlen).
    //  NOTE: WE run this backwards, much like we do in shawe_taylor()
    let mut i: i64 = iterations as i64;
    while i >= 0 {
        let bigi = UCN::from(i as u64);
        let prime_i = &pseed + &bigi;
        let mut hash_i = hash(&prime_i, l);
        x_bytes.append(&mut hash_i);
        i -= 1;
    }
    let x = UCN::from_bytes(&x_bytes);
    // 8. pseed = pseed + iterations + 1.
    pseed = &pseed + UCN::from(iterations) + &one;
    // 9. x = 2^(L-1) + (x mod 2^(L-1));
    let twol1: UCN = &one << (l - 1);
    // 10. t = ceiling(x / (2 * q * p_0))
    let twoqp0 = &two * &q * &p0;
    let mut t = ceildiv(&x, &twoqp0);
    loop {
        // 11. If (2tqp_0 + 1) > 2^L, then t = ceiling(2^(L-1)/2qp0).
        let twotqp0p1 = (&t * &twoqp0) + &one;
        let twol = &one << l;
        if &twotqp0p1 > &twol {
            t = ceildiv(&twol1, &twoqp0);
        }
        // 12. p = 2tqp_0 + 1
        let p = twotqp0p1;
        // 13. pgen_counter = pgen_counter + 1
        pgen_counter = &pgen_counter + 1;
        // 14. a = 0
        let mut a_bytes = Vec::new();
        // 15. For i = 0 to iterations do
        //       a = a + (Hash(pseed + i) * 2^(i*outlen).
        i = iterations as i64;
        while i >= 0 {
            let bigi = UCN::from(i as u64);
            let prime_i = &pseed + &bigi;
            let mut hash_i = hash(&prime_i, l);
            a_bytes.append(&mut hash_i);
            i -= 1;
        }
        let mut a = UCN::from_bytes(&a_bytes);
        // 16. pseed = pseed + iterations + 1.
        pseed = &pseed + UCN::from(iterations) + &one;
        // 17. a = 2 + (a mod (p - 3))
        let pm3 = &p - &three;
        let amodpm3 = &a % &pm3;
        a = &two + &amodpm3;
        // 18. z = a^(2tq) mod p.
        let twotq = &two * &t * &q;
        let z = a.modexp(&twotq, &p);
        // 19. If ((1 = GCD(z-1,p)) and (1 = z^p0 mod p)), then return SUCCESS
        // and the values of p, q, and (optionally) pseed, qseed, pgen_counter,
        // and qgen_counter.
        let zm1 = &z - &one;
        if (&one == &zm1.gcd(&p)) && (&one == &z.modexp(&p0, &p)) {
            let evidence = DSAGenEvidence {
                             first_seed: firstseed.clone(),
                             p_seed: pseed,
                             q_seed: qseed,
                             pgen_counter: pgen_counter,
                             qgen_counter: qgen_counter
                           };
            return Ok((p, q, evidence));
        }
        // 20. If (pgen_counter > (4L + old_counter)), then return FAILURE.
        if pgen_counter > ((4 * l) + old_counter) {
            return Err(DSAGenError::TooManyGenAttempts);
        }
        // 21. t = t + 1
        t = &t + &one;
        // 22. Go to step 11.
    }
}

pub fn validate_provable_primes<G: Rng>(rng: &mut G,
                                        p: &UCN, q: &UCN,
                                        ev: &DSAGenEvidence)
    -> bool
{
    let one = UCN::from(1u64);
    // This is from Page 40 of 186-4, section A.1.2.2.
    // 1. L = len(p);
    let l = ((p.bits() + 255) / 256) * 256;
    // 2. N = len(q);
    let n = ((q.bits() + 15) / 16) * 16;
    // 3. Check that the (L, N) pair is in the list of acceptable (L, N) pairs.
    //    If the pair is not in the list, then return failure.
    let params = match (l, n) {
                     (1024, 160) => DSAParameterSize::L1024N160,
                     (2048, 224) => DSAParameterSize::L2048N224,
                     (2048, 256) => DSAParameterSize::L2048N256,
                     (3072, 256) => DSAParameterSize::L3072N256,
                     _           => return false
                 };
    // 4. If (firstseed < 2^(n-1), then return FAILURE.
    let twon1 = &one << (n - 1);
    if &ev.first_seed < &twon1 {
        return false;
    }
    // 5. If (2^n <= q), then return FAILURE.
    let twon = &one << n;
    if &twon <= q {
        return false;
    }
    // 6. If (2^l <= p), then return FAILURE.
    let twol = &one << l;
    if &twol <= p {
        return false;
    }
    // 7. If ((p - 1) mod q /= 0), then return FAILURE.
    let pm1 = p - &one;
    if !pm1.rem(q).is_zero() {
        return false;
    }
    // 8. Using L, N and firstseed, perform the constructive prime generation
    //    procedure in Appendix A.1.2.1.2 to obtain p_val, q_val, pseed_val,
    //    qseed_val, pgen_counter_val, and qgen_counter_val. If FAILURE is
    //    returned, or if (q_val ≠ q) or (qseed_val ≠ qseed) or
    //    (qgen_counter_val ≠ qgen_counter) or (p_val ≠ p) or (pseed_val ≠
    //    pseed) or (pgen_counter_val ≠ pgen_counter), then return FAILURE.
    match generate_provable_primes(rng, &ev.first_seed, params) {
        Err(_) => false,
        Ok((p_val, q_val, ev2)) => {
            // 9. Return SUCCESS
            (&q_val == q) && (&p_val == p) && (ev == &ev2)
        }
    }
}

pub fn generate_verifiable_generator(p: &UCN,
                                     q: &UCN,
                                     ev: &DSAGenEvidence,
                                     index: u8)
    -> Result<UCN,DSAGenError>
{
    // See FIPS 186-4, Section A.2.3: Verifiable Canonical Generatio of the
    // Generator g
    let one = UCN::from(1u64);
    let two = UCN::from(2u64);
    // 1. If (index is incorrect), then return INVALID.
    //   NOTE: Can't happen, because types.
    // 2. N = len(q)
    let _n = q.bits();
    // 3. e = (p - 1)/q.
    let e = (p - &one) / q;
    // 4. count = 0.
    let mut count: u16 = 0;

    loop {
        // 5. count = count + 1;
        count = count + 1;
        // 6. if (count = 0), then return INVALID.
        if count == 0 {
            return Err(DSAGenError::TooManyGenAttempts);
        }
        // 7. U = domain_parameter_seed || "ggen" || index || count
        //     Comment: "ggen" is the bit string 0x6767656E.
        let mut u = get_domain_parameter_seed(&ev);
        u.push(0x67); u.push(0x67); u.push(0x65); u.push(0x6E);
        u.push(index);
        u.push((count >> 8) as u8); u.push((count & 0xFF) as u8);
        // 8. W = hash(U)
        let mut dgst = Sha256::default();
        dgst.process(&u);
        let w = UCN::from_bytes(dgst.fixed_result().as_slice());
        // 9. g = W^e mod p
        let g = w.modexp(&e, &p);
        // 10. if (g < 2), then go to step 5.
        if &g >= &two {
            // 11. Return VALID and the value of g.
            return Ok(g);
        }
    }
}

pub fn verify_generator(p: &UCN, q: &UCN, ev: &DSAGenEvidence,
                        index: u8, g: &UCN)
    -> bool
{
    // FIPS 186.4, Section A.2.4!
    let one = UCN::from(1u64);
    let two = UCN::from(2u64);
    // 1. If (index is incorrect), then return INVALID.
    //    NOTE: Not sure how this can be invalid.
    // 2. Verify that 2 <= g <= (p - 1). If not true, return INVALID.
    if g < &two {
        return false;
    }
    if g >= p {
        return false;
    }
    // 3. If (g^q /= 1 mod p), then return INVALID.
    if g.modexp(q, p) != one {
        return false;
    }
    // 4. N = len(q)
    // let n = ((q.bits() + 15) / 15) * 15;
    // 5. e = (p - 1) / q
    let e = (p - &one) / q;
    // 6. count = 0
    let mut count: u16 = 0;
    loop {
        // 7. count = count + 1
        count = count + 1;
        // 8. if (count == 0), then return INVALID
        if count == 0 {
            return false;
        }
        // 9. U = domain_parameter_seed || "ggen" || index || count.
        let mut u = get_domain_parameter_seed(&ev);
        u.push(0x67); u.push(0x67); u.push(0x65); u.push(0x6E);
        u.push(index);
        u.push((count >> 8) as u8); u.push((count & 0xFF) as u8);
        // 10. W = Hash(U)
        let mut dgst = Sha256::default();
        dgst.process(&u);
        let w = UCN::from_bytes(dgst.fixed_result().as_slice());
        // 11. computed_g = W^e mod p
        let computed_g = w.modexp(&e, &p);
        // 12. if (computed_g < 2), then go to step 7.
        if &computed_g < &two {
            continue;
        }
        // 13. if (computed_g == g), then return VALID, else return INVALID
        return &computed_g == g;
    }
}

pub fn get_input_seed<G: Rng>(rng: &mut G,
                              size: DSAParameterSize,
                              seedlen: usize)
    -> Result<UCN,DSAGenError>
{
    let mut firstseed = UCN::from(0u64);
    let one = UCN::from(1u64);
    let n = n_bits(size);

    // 3. If (seedlen < N), then return FAILURE
    if seedlen < n {
        return Err(DSAGenError::InvalidSeedLength)
    }
    // 4. While firstseed < 2^(n-1) ...
    let twonm1 = one << (n - 1);
    while &firstseed < &twonm1 {
        // Get an arbitrary sequence of seedlen bits as firstseed.
        let bytes: Vec<u8> = rng.gen_iter().take(seedlen / 8).collect();
        firstseed = UCN::from_bytes(&bytes);
    }
    // 5. Return SUCCESS and the value of firstseed
    Ok(firstseed)
}

// Appendix C.6: Shawe-Taylor Random_Prime Routine. Also referenced in 186-4
// as ST_Random_Prime, so when you see that in a bit, understand that it's a
// recursive call.
fn shawe_taylor<G: Rng>(rng: &mut G, length: usize, input_seed: &UCN)
    -> Result<(UCN,UCN,usize),DSAGenError>
{
    // 1. If (length < 2), then return (FAILURE, 0, 0 {, 0}).
    if length < 2 {
        return Err(DSAGenError::InvalidPrimeLength);
    }
    // 2. If (length ≥ 33), then go to step 14.
    if length >= 33 {
        shawe_taylor_large(rng, length, input_seed)
    } else {
        shawe_taylor_small(length, input_seed)
    }
}

fn shawe_taylor_small(length: usize, input_seed: &UCN)
    -> Result<(UCN,UCN,usize),DSAGenError>
{
    let one = UCN::from(1u64);
    let two = UCN::from(2u64);
    // 3. prime_seed = input_seed.
    let mut prime_seed: UCN = input_seed.clone();
    // 4. prime_gen_counter = 0
    let mut prime_gen_counter = 0;
    loop {
        // 5. c = Hash(prime_seed) ⊕ Hash(prime_seed + 1).
        let cbs = xorvecs(hash(&prime_seed, length),
                          hash(&(&prime_seed + &one), length));
        let mut c = UCN::from_bytes(&cbs);
        // 6. c = 2^(length – 1) + (c mod 2^(length – 1))
        let twolm1: UCN = &one << (length - 1);
        c = &twolm1 + (c % &twolm1);
        // 7. c = (2 ∗ floor(c / 2)) + 1.
        c = ((c >> 1) << 1) + &one;
        // 8. prime_gen_counter = prime_gen_counter + 1.
        prime_gen_counter = prime_gen_counter + 1;
        // 9. prime_seed = prime_seed + 2.
        prime_seed = prime_seed + &two;
        // 10. Perform a deterministic primality test on c. For example, since
        //     c is small, its primality can be tested by trial division. See
        //     Appendix C.7.
        let c_is_prime = prime_test(&c);
        // 11. If (c is a prime number), then
        if c_is_prime {
            // 11.1 prime = c.
            let prime = c;
            // 11.2 Return (SUCCESS, prime, prime_seed {, prime_gen_counter}).
            return Ok((prime, prime_seed.clone(), prime_gen_counter))
        }
        // 12. If (prime_gen_counter > (4 ∗ length)), then
        //     return (FAILURE, 0, 0 {, 0}).
        if prime_gen_counter > (4 * length) {
            return Err(DSAGenError::TooManyGenAttempts);
        }
        // 13. Go to step 5.
    }
}

fn shawe_taylor_large<G: Rng>(rng: &mut G, length: usize, input_seed: &UCN)
    -> Result<(UCN,UCN,usize),DSAGenError>
{
    let one = UCN::from(1u64);
    let two = UCN::from(2u64);
    let three = UCN::from(3u64);
    // 14. (status, c0, prime_seed, prime_gen_counter) =
    //          (ST_Random_Prime ((ceiling(length / 2) + 1), input_seed).
    let len2: usize = ceildiv(&length, &2);
    let (c0, mut prime_seed, mut prime_gen_counter) =
        shawe_taylor( rng, len2 + 1, input_seed )?;
    // 15. If FAILURE is returned, return (FAILURE, 0, 0 {, 0}).
    // 16. iterations = ceiling(length / outlen) – 1.
    let outlen = 256; // the size of the hash function output in bits
    let iterations = ceildiv(&length, &outlen) - 1;
    // 17. old_counter = prime_gen_counter.
    let old_counter = prime_gen_counter;
    // 18. x = 0.
    let mut x_bytes = Vec::new();
    // 19. For i = 0 to iterations do
    //        x = x + (Hash(prime_seed + i) ∗ 2^(i * outlen)).
    //
    //  We're going to actually run this backwards. What this computation
    //  does is essentially built up a large vector of hashes, one per
    //  iteration, shifting them bast each other via the 2^(i * outlen)
    //  term. So we'll just do this directly.
    let mut i: i64 = iterations as i64;
    while i >= 0 {
        let bigi = UCN::from(i as u64);
        let prime_i = &prime_seed + &bigi;
        let mut hash_i = hash(&prime_i, length);
        x_bytes.append(&mut hash_i);
        i -= 1;
    }
    let mut x = UCN::from_bytes(&x_bytes);
    // 20. prime_seed = prime_seed + iterations + 1.
    prime_seed = &prime_seed + UCN::from(iterations) + &one;
    // 21. x = 2^(length – 1) + (x mod 2^(length – 1)).
    let twolm1 = &one << (length - 1);
    x = &twolm1 + (&x % &twolm1);
    // 22. t = ceiling(x / (2c0)).
    let twoc0 = &two * &c0;
    let mut t: UCN = ceildiv(&x, &twoc0);
    loop {
        // 23. If (2tc0 + 1 > 2^length), then
        //       t = ceiling(2^(length – 1) / (2c0)).
        let twotc0 = &t * &twoc0;
        if (&twotc0 + &one) > (&one << length) {
            t = ceildiv(&twolm1, &twoc0);
        }
        // 24. c = 2tc0 + 1.
        let c = &twotc0 + &one;

        // 25. prime_gen_counter = prime_gen_counter + 1.
        prime_gen_counter = prime_gen_counter + 1;
        // 26. a = 0.
        let mut a_bytes = Vec::new();
        // 27. For i = 0 to iterations do
        //           a = a + (Hash(prime_seed + i) ∗ 2 i * outlen).
        //
        //  As with the last time we did this, we're going to do this more
        //  constructively
        i = iterations as i64;
        while i >= 0 {
            let bigi = UCN::from(i as u64);
            let prime_i = &prime_seed + &bigi;
            let mut hash_i = hash(&prime_i, length);
            a_bytes.append(&mut hash_i);
            i -= 1;
        }
        let mut a = UCN::from_bytes(&a_bytes);
        // 28. prime_seed = prime_seed + iterations + 1.
        prime_seed = &prime_seed + UCN::from(iterations) + &one;
        // 29. a = 2 + (a mod (c – 3)).
        a = &two + (a % (&c - &three));
        // 30. z = a^2t mod c.
        let z: UCN = a.modexp(&(&two * &t), &c);
        // 31. If ((1 = GCD(z – 1, c)) and (1 = z^c_0 mod c)), then
        let gcd_ok = &one == &c.gcd(&(&z - &one));
        let modexp_ok = &one == &z.modexp(&c0, &c);
        if gcd_ok && modexp_ok {
            // 31.1 prime = c.
            let prime = c;
            // 31.2 Return (SUCCESS, prime, prime_seed {, prime_gen_counter}).
            return Ok((prime, prime_seed, prime_gen_counter));
        }
        // 32. If (prime_gen_counter ≥ ((4 ∗ length) + old_counter)), then
        //     return (FAILURE, 0, 0 {, 0}).
        let limit = (4 * length) + old_counter;
        if prime_gen_counter >= limit {
            return Err(DSAGenError::TooManyGenAttempts)
        }
        // 33. t = t + 1.
        t = t + &one;
        // 34. Go to step 23.
    }
}

fn ceildiv<T>(a: &T, b: &T) -> T
 where T: Add<Output=T>,
       T: Sub<Output=T>,
       T: Div<Output=T>,
       T: From<usize>,
       T: Clone
{
    let aclone: T = a.clone();
    let bclone: T = b.clone();
    let one: T = T::from(1 as usize);
    let x: T = (aclone + bclone.clone()) - one;
    let res = x / bclone;
    res
}

fn prime_test(x: &UCN) -> bool {
    let two = UCN::from(2 as u64);
    let three = UCN::from(3 as u64);
    let five = UCN::from(5 as u64);

    if x.is_even() {
        if x == &two {
            return true;
        }
        return false;
    }

    if x.is_multiple_of(&three) {
        return false;
    }

    if x.is_multiple_of(&five) {
        return false;
    }

    let mut divisor = UCN::from(7 as u32);
    let sqrtx = isqrt(&x);
    while &divisor < &sqrtx {
        if x.is_multiple_of(&divisor) {
            return false;
        }
        divisor = next_divisor(divisor);
    }

    true
}

fn isqrt(x: &UCN) -> UCN {
    let mut num = x.clone();
    let mut res = UCN::from(0u64);
    let one = UCN::from(1u64);
    let mut bit = one << num.bits();

    while &bit > &num {
        bit >>= 2;
    }

    while !bit.is_zero() {
        if num >= (&res + &bit) {
            num = &num - (&res + &bit);
            res  = (&res >> 1) + &bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }

    res
}

fn next_divisor(input: UCN) -> UCN {
    let two = UCN::from(2 as u64);
    let three = UCN::from(3 as u64);
    let five = UCN::from(5 as u64);
    let mut x = input;

    loop {
        x = &x + &two;

        if x.is_multiple_of(&three) {
            continue;
        }
        if x.is_multiple_of(&five) {
            continue;
        }

        return x;
    }
}

fn hash(x: &UCN, len: usize) -> Vec<u8> {
    let bytelen = len / 8;
    let base = x.to_bytes(bytelen);
    let mut dgst = Sha256::default();
    dgst.process(&base);
    dgst.fixed_result().as_slice().to_vec()
}

fn xorvecs(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    assert!(a.len() == b.len());
    let mut c = Vec::with_capacity(a.len());

    for (a,b) in a.iter().zip(b.iter()) {
        c.push(a ^ b);
    }
    c
}


