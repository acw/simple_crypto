use rsa::*;
use testing::run_test;

fn get_signing_hash(s: usize) -> &'static SigningHash {
    match s {
        0x1   => &SIGNING_HASH_SHA1,
        0x224 => &SIGNING_HASH_SHA224,
        0x256 => &SIGNING_HASH_SHA256,
        0x384 => &SIGNING_HASH_SHA384,
        0x512 => &SIGNING_HASH_SHA512,
        _     => panic!("Unacceptable hash")
    }
}

#[test]
fn rsa_signing_tests()
{
    run_test("tests/rsa/signature.test", 7, |case| {
        let (neg0, dbytes) = case.get("d").unwrap();
        let (neg1, nbytes) = case.get("n").unwrap();
        let (neg2, hbytes) = case.get("h").unwrap();
        let (neg3, kbytes) = case.get("k").unwrap();
        let (neg4, msg)    = case.get("m").unwrap();
        let (neg5, sig)    = case.get("s").unwrap();

        assert!(!neg0 & !neg1 & !neg2 & !neg3 & !neg4 & !neg5);
        let hash = get_signing_hash(usize::from(UCN::from_bytes(hbytes)));
        let size = usize::from(UCN::from_bytes(kbytes));
        let key  = RSAPrivate::new(UCN::from_bytes(nbytes),
                                   UCN::from_bytes(dbytes));

        assert!(size % 8 == 0);
        assert_eq!(key.byte_len * 8, size);
        let sig2 = key.sign(hash, &msg);
        assert_eq!(*sig, sig2);
    });
}

#[test]
fn rsa_verification_tests()
{
    run_test("tests/rsa/signature.test", 7, |case| {
        let (neg1, nbytes) = case.get("n").unwrap();
        let (neg2, hbytes) = case.get("h").unwrap();
        let (neg3, kbytes) = case.get("k").unwrap();
        let (neg4, msg)    = case.get("m").unwrap();
        let (neg5, sig)    = case.get("s").unwrap();

        assert!(!neg1 & !neg2 & !neg3 & !neg4 & !neg5);
        let hash = get_signing_hash(usize::from(UCN::from_bytes(hbytes)));
        let size = usize::from(UCN::from_bytes(kbytes));
        let key  = RSAPublic::new(UCN::from_bytes(nbytes),
                                  UCN::from(65537u64));

        assert_eq!(key.byte_len * 8, size);
        assert!(key.verify(hash, &msg, sig));
    });
}
