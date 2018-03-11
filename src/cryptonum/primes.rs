use cryptonum::extended_math::modexp;
use cryptonum::traits::*;
use rand::Rng;
use std::ops::*;

static SMALL_PRIMES: [u64; 310] = [
      2,     3,     5,     7,    11,    13,    17,    19,    23,    29,
     31,    37,    41,    43,    47,    53,    59,    61,    67,    71,
     73,    79,    83,    89,    97,   101,   103,   107,   109,   113,
    127,   131,   137,   139,   149,   151,   157,   163,   167,   173,
    179,   181,   191,   193,   197,   199,   211,   223,   227,   229,
    233,   239,   241,   251,   257,   263,   269,   271,   277,   281,
    283,   293,   307,   311,   313,   317,   331,   337,   347,   349,
    353,   359,   367,   373,   379,   383,   389,   397,   401,   409,
    419,   421,   431,   433,   439,   443,   449,   457,   461,   463,
    467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
    547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
    607,   613,   617,   619,   631,   641,   643,   647,   653,   659,
    661,   673,   677,   683,   691,   701,   709,   719,   727,   733,
    739,   743,   751,   757,   761,   769,   773,   787,   797,   809,
    811,   821,   823,   827,   829,   839,   853,   857,   859,   863,
    877,   881,   883,   887,   907,   911,   919,   929,   937,   941,
    947,   953,   967,   971,   977,   983,   991,   997,  1009,  1013,
   1019,  1021,  1031,  1033,  1039,  1049,  1051,  1061,  1063,  1069,
   1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,  1129,  1151,
   1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223,
   1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,  1289,  1291,
   1297,  1301,  1303,  1307,  1319,  1321,  1327,  1361,  1367,  1373,
   1381,  1399,  1409,  1423,  1427,  1429,  1433,  1439,  1447,  1451,
   1453,  1459,  1471,  1481,  1483,  1487,  1489,  1493,  1499,  1511,
   1523,  1531,  1543,  1549,  1553,  1559,  1567,  1571,  1579,  1583,
   1597,  1601,  1607,  1609,  1613,  1619,  1621,  1627,  1637,  1657,
   1663,  1667,  1669,  1693,  1697,  1699,  1709,  1721,  1723,  1733,
   1741,  1747,  1753,  1759,  1777,  1783,  1787,  1789,  1801,  1811,
   1823,  1831,  1847,  1861,  1867,  1871,  1873,  1877,  1879,  1889,
   1901,  1907,  1913,  1931,  1933,  1949,  1951,  1973,  1979,  1987,
   1993,  1997,  1999,  2003,  2011,  2017,  2027,  2029,  2039,  2053];


pub fn probably_prime<G,T>(x: &T, g: &mut G, iters: usize) -> bool
  where
   G: Rng,
   T: Clone + PartialOrd + Rem + Sub,
   T: CryptoNumBase + CryptoNumSerialization,
{
    for tester in SMALL_PRIMES.iter() {
        if (x % T::from_u64(*tester)) == T::zero() {
            return false;
        }
    }
    miller_rabin(g, x, iters)
}

fn miller_rabin<G,T>(g: &mut G, n: T, iters: usize) -> bool
  where
   G: Rng,
   T: Clone + PartialEq + PartialOrd + Sub,
   T: CryptoNumBase + CryptoNumSerialization,
{
    let one = T::from_u8(1);
    let two = T::from_u8(2);
    let nm1 = n - one;
    // Quoth Wikipedia:
    // write n - 1 as 2^r*d with d odd by factoring powers of 2 from n - 1
    let mut d = nm1.clone();
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
        assert!(r < n.bit_size());
    }
    // WitnessLoop: repeat k times
    'WitnessLoop: for _k in 0..iters {
        // pick a random integer a in the range [2, n - 2]
        let a = random_in_range(g, &two, &nm1);
        // x <- a^d mod n
        let mut x = modexp(&a, &d, &n);
        // if x = 1 or x = n - 1 then
        if (&x == &one) || (&x == &nm1) {
            // continue WitnessLoop
            continue 'WitnessLoop;
        }
        // repeat r - 1 times:
        for _i in 0..r {
            // x <- x^2 mod n
            x = modexp(&x, &two, &n);
            // if x = 1 then
            if &x == &one {
                // return composite
                return false;
            }
            // if x = n - 1 then
            if &x == &nm1 {
                // continue WitnessLoop
                continue 'WitnessLoop;
            }
        }
        // return composite
        return false;
    }
    // return probably prime
    true
}

fn random_in_range<G,T>(rng: &mut G, min: &T, max: &T) -> T
  where
    G: Rng,
    T: CryptoNumSerialization + PartialOrd
{
    assert_eq!(min.byte_size(), max.byte_size());
    loop {
        let candidate = random_number(rng, min.byte_size());

        if (&candidate >= min) && (&candidate < max) {
            return candidate;
        }
    }
}

fn random_number<G,T>(rng: &mut G, bytelen: usize) -> T
  where
    G: Rng,
    T: CryptoNumSerialization
{
    let components: Vec<u8> = rng.gen_iter().take(bytelen).collect();
    T::from_bytes(&components)
}


