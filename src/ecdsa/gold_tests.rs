use cryptonum::{SCN,UCN};
use dsa::rfc6979::*;
use ecdsa::curves::EllipticCurve;
use ecdsa::math::ECCPoint;
use ecdsa::private::ECDSAPrivate;
use ecdsa::public::ECDSAPublic;
use sha1::Sha1;
use sha2::{Sha224,Sha256,Sha384,Sha512};
use testing::run_test;

fn get_curve(cbytes: &[u8]) -> EllipticCurve {
    match usize::from(UCN::from_bytes(cbytes)) {
        0x192 => EllipticCurve::p192(),
        0x224 => EllipticCurve::p224(),
        0x256 => EllipticCurve::p256(),
        0x384 => EllipticCurve::p384(),
        0x521 => EllipticCurve::p521(),
        _     => panic!("Unacceptable curve identifier")
    }
}

#[test]
fn verification_tests()
{
    run_test("tests/ecdsa/signature.test", 8, |case| {
        let (neg0, cbytes) = case.get("c").unwrap();
        let (negx, xbytes) = case.get("x").unwrap();
        let (negy, ybytes) = case.get("y").unwrap();
        let (neg1, hbytes) = case.get("h").unwrap();
        let (neg2, msg)    = case.get("m").unwrap();
        let (neg3, rbytes) = case.get("r").unwrap();
        let (neg4, sbytes) = case.get("s").unwrap();

        assert!(!neg0 & !neg1 & !neg2 & !neg3 & !neg4);
        let curve = get_curve(cbytes);
        let ux = UCN::from_bytes(xbytes);
        let uy = UCN::from_bytes(ybytes);
        let x = SCN{ negative: *negx, value: ux };
        let y = SCN{ negative: *negy, value: uy };
        let point = ECCPoint::new(&curve, x, y);
        let public = ECDSAPublic::new(&curve, &point);
        let r = UCN::from_bytes(rbytes);
        let s = UCN::from_bytes(sbytes);
        println!("r: {:X}", r);
        let sig = DSASignature{ r: r, s: s };

        match usize::from(UCN::from_bytes(hbytes)) {
            0x1   => assert!(public.verify::<Sha1>(msg, &sig)),
            0x224 => assert!(public.verify::<Sha224>(msg, &sig)),
            0x256 => assert!(public.verify::<Sha256>(msg, &sig)),
            0x384 => assert!(public.verify::<Sha384>(msg, &sig)),
            0x512 => assert!(public.verify::<Sha512>(msg, &sig)),
            v     => panic!("Bad hash size {}!", v)
        }
    });
}

#[test]
fn signing_tests()
{
    run_test("tests/ecdsa/signature.test", 8, |case| {
        let (neg0, cbytes) = case.get("c").unwrap();
        let (neg1, dbytes) = case.get("d").unwrap();
        let (neg2, hbytes) = case.get("h").unwrap();
        let (neg3, msg)    = case.get("m").unwrap();
        let (neg4, rbytes) = case.get("r").unwrap();
        let (neg5, sbytes) = case.get("s").unwrap();

        assert!(!neg0 & !neg1 & !neg2 & !neg3 & !neg4 & !neg5);
        let curve = get_curve(cbytes);
        let d = UCN::from_bytes(dbytes);
        let private = ECDSAPrivate::new(&curve, &d);
        let r = UCN::from_bytes(rbytes);
        let s = UCN::from_bytes(sbytes);
        let sig = DSASignature{ r: r, s: s };

        match usize::from(UCN::from_bytes(hbytes)) {
            0x1   => assert_eq!(sig, private.sign::<Sha1>(msg)),
            0x224 => assert_eq!(sig, private.sign::<Sha224>(msg)),
            0x256 => assert_eq!(sig, private.sign::<Sha256>(msg)),
            0x384 => assert_eq!(sig, private.sign::<Sha384>(msg)),
            0x512 => assert_eq!(sig, private.sign::<Sha512>(msg)),
            v     => panic!("Bad hash size {}!", v)
        }
    });
}
