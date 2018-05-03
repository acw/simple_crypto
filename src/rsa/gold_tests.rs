use rsa::*;
use rsa::oaep::OAEPParams;
use sha1::Sha1;
use sha2::{Sha224,Sha256,Sha384,Sha512};
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

#[test]
fn rsa_decryption_tests()
{
    run_test("tests/rsa/encryption.test", 6, |case| {
        let (neg1, dbytes) = case.get("d").unwrap();
        let (neg2, nbytes) = case.get("n").unwrap();
        let (neg3, hbytes) = case.get("h").unwrap();
        let (neg4, lbytes) = case.get("l").unwrap();
        let (neg5, msg)    = case.get("m").unwrap();
        let (neg6, cphtxt) = case.get("c").unwrap();

        assert!(!neg1 & !neg2 & !neg3 & !neg4 & !neg5 & !neg6);
        let label = String::from_utf8(lbytes.clone()).unwrap();
        let key = RSAPrivate::new(UCN::from_bytes(nbytes),
                                  UCN::from_bytes(dbytes));
        let wrapped = match usize::from(UCN::from_bytes(hbytes)) {
            0x1   => key.decrypt(&OAEPParams::new(Sha1::default(),  label),cphtxt),
            0x224 => key.decrypt(&OAEPParams::new(Sha224::default(),label),cphtxt),
            0x256 => key.decrypt(&OAEPParams::new(Sha256::default(),label),cphtxt),
            0x384 => key.decrypt(&OAEPParams::new(Sha384::default(),label),cphtxt),
            0x512 => key.decrypt(&OAEPParams::new(Sha512::default(),label),cphtxt),
            _     => panic!("Unacceptable hash")
        };
        let mymsg = wrapped.unwrap();
        assert_eq!(msg, &mymsg);
    });
}

#[test]
fn rsa_encryption_tests()
{
    run_test("tests/rsa/encryption.test", 6, |case| {
        let (neg1, dbytes) = case.get("d").unwrap();
        let (neg2, nbytes) = case.get("n").unwrap();
        let (neg3, hbytes) = case.get("h").unwrap();
        let (neg4, lbytes) = case.get("l").unwrap();
        let (neg5, msg)    = case.get("m").unwrap();

        // This one's a little tricky, because there's randomness in the
        // encryption phase. So we can't just encrypt and see if we get the
        // same value. Instead, we just use this as a test vector to round
        // trip, and trust that the decryption test above makes sure we're
        // not going off into la la land.
        assert!(!neg1 & !neg2 & !neg3 & !neg4 & !neg5);
        let label = String::from_utf8(lbytes.clone()).unwrap();
        let private = RSAPrivate::new(UCN::from_bytes(nbytes),
                                      UCN::from_bytes(dbytes));
        let public = RSAPublic::new(UCN::from_bytes(nbytes),
                                    UCN::from(65537u64));
        let wrappedc = match usize::from(UCN::from_bytes(hbytes)) {
            0x1   => public.encrypt(&OAEPParams::new(Sha1::default(),  label.clone()), &msg),
            0x224 => public.encrypt(&OAEPParams::new(Sha224::default(),label.clone()), &msg),
            0x256 => public.encrypt(&OAEPParams::new(Sha256::default(),label.clone()), &msg),
            0x384 => public.encrypt(&OAEPParams::new(Sha384::default(),label.clone()), &msg),
            0x512 => public.encrypt(&OAEPParams::new(Sha512::default(),label.clone()), &msg),
            _     => panic!("Unacceptable hash")
        };
        let ciphertext = wrappedc.unwrap();
        let wrappedm = match usize::from(UCN::from_bytes(hbytes)) {
            0x1   => private.decrypt(&OAEPParams::new(Sha1::default(),  label), &ciphertext),
            0x224 => private.decrypt(&OAEPParams::new(Sha224::default(),label), &ciphertext),
            0x256 => private.decrypt(&OAEPParams::new(Sha256::default(),label), &ciphertext),
            0x384 => private.decrypt(&OAEPParams::new(Sha384::default(),label), &ciphertext),
            0x512 => private.decrypt(&OAEPParams::new(Sha512::default(),label), &ciphertext),
            _     => panic!("Unacceptable hash")
        };
        let message = wrappedm.unwrap();

        assert_eq!(msg, &message);
    });
}
