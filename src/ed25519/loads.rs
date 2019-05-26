#[cfg(test)]
use cryptonum::unsigned::{Decoder,U192};
#[cfg(test)]
use testing::run_test;

pub fn load3(x: &[u8]) -> u64
{
    (x[0] as u64) | ((x[1] as u64) << 8) | ((x[2] as u64) << 16)
}

pub fn load4(x: &[u8]) -> u64
{
    (x[0] as u64)         | ((x[1] as u64) << 8) |
    ((x[2] as u64) << 16) | ((x[3] as u64) << 24)
}

#[cfg(test)]
#[test]
fn loads() {
    let fname = "testdata/ed25519/load.test";
    run_test(fname.to_string(), 3, |case| {
        let (negx, xbytes) = case.get("x").unwrap();
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!negx && !nega && !negb);
        let res3 = u64::from(U192::from_bytes(abytes));
        let res4 = u64::from(U192::from_bytes(bbytes));
        assert_eq!(res3, load3(&xbytes), "load3");
        assert_eq!(res4, load4(&xbytes), "load4");
    });
}

