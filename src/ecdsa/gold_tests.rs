use cryptonum::{SCN,UCN};
//use dsa::rfc6979::*;
use ecdsa::curves::*;
use ecdsa::point::ECPoint;
//use ecdsa::private::ECDSAPrivate;
//use ecdsa::public::ECDSAPublic;
//use sha1::Sha1;
//use sha2::{Sha224,Sha256,Sha384,Sha512};
use testing::run_test;

fn get_curve(cbytes: &[u8]) -> &'static EllipticCurve {
    match usize::from(UCN::from_bytes(cbytes)) {
        0x192 => &NIST_P192,
        0x224 => &NIST_P224,
        0x256 => &NIST_P256,
        0x384 => &NIST_P384,
        0x521 => &NIST_P521,
        x     => panic!("Unacceptable curve identifier {}", x)
    }
}

#[test]
fn point_negate()
{
    run_test("tests/ecdsa/ec_negate.test", 5, |case| {
        let (neg0, abytes) = case.get("a").unwrap();
        let (neg1, bbytes) = case.get("b").unwrap();
        let (neg2, cbytes) = case.get("c").unwrap();
        let (neg3, xbytes) = case.get("x").unwrap();
        let (neg4, ybytes) = case.get("y").unwrap();

        assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4);
        let curve = get_curve(&cbytes);
        let x = SCN::from(UCN::from_bytes(xbytes));
        let y = SCN::from(UCN::from_bytes(ybytes));
        let orig = ECPoint::new(curve, x, y);
        let a = SCN::from(UCN::from_bytes(abytes));
        let b = SCN::from(UCN::from_bytes(bbytes));
        let inverted = ECPoint::new(curve, a, b);
        assert_eq!(inverted, orig.negate());
    });
}

#[test]
fn point_double()
{
    run_test("tests/ecdsa/ec_dble.test", 5, |case| {
        println!("START");
        let (neg0, abytes) = case.get("a").unwrap();
        let (neg1, bbytes) = case.get("b").unwrap();
        let (neg2, cbytes) = case.get("c").unwrap();
        let (neg3, xbytes) = case.get("x").unwrap();
        let (neg4, ybytes) = case.get("y").unwrap();

        assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4);
        println!("SEC1");
        let curve = get_curve(&cbytes);
        println!("SEC2");
        let x = SCN::from(UCN::from_bytes(xbytes));
        let y = SCN::from(UCN::from_bytes(ybytes));
        let orig = ECPoint::new(curve, x, y);
        println!("SEC3");
        let a = SCN::from(UCN::from_bytes(abytes));
        let b = SCN::from(UCN::from_bytes(bbytes));
        let doubled = ECPoint::new(curve, a, b);
        println!("SEC4");
        assert_eq!(doubled, orig.double());
    });
}

#[test]
fn point_add()
{
    run_test("tests/ecdsa/ec_add.test", 7, |case| {
        let (neg0, abytes) = case.get("a").unwrap();
        let (neg1, bbytes) = case.get("b").unwrap();
        let (neg2, qbytes) = case.get("q").unwrap();
        let (neg3, rbytes) = case.get("r").unwrap();
        let (neg4, cbytes) = case.get("c").unwrap();
        let (neg5, xbytes) = case.get("x").unwrap();
        let (neg6, ybytes) = case.get("y").unwrap();

        assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 && !neg5 && !neg6);
        let curve = get_curve(&cbytes);
        let x = SCN::from(UCN::from_bytes(xbytes));
        let y = SCN::from(UCN::from_bytes(ybytes));
        let p1 = ECPoint::new(curve, x, y);
        let q = SCN::from(UCN::from_bytes(qbytes));
        let r = SCN::from(UCN::from_bytes(rbytes));
        let p2 = ECPoint::new(curve, q, r);
        let a = SCN::from(UCN::from_bytes(abytes));
        let b = SCN::from(UCN::from_bytes(bbytes));
        let result = ECPoint::new(curve, a, b);
        assert_eq!(result, p1.add(&p2));
    });
}

#[test]
fn point_scale()
{
    run_test("tests/ecdsa/ec_mul.test", 6, |case| {
        let (neg0, abytes) = case.get("a").unwrap();
        let (neg1, bbytes) = case.get("b").unwrap();
        let (neg2, kbytes) = case.get("k").unwrap();
        let (neg3, cbytes) = case.get("c").unwrap();
        let (neg4, xbytes) = case.get("x").unwrap();
        let (neg5, ybytes) = case.get("y").unwrap();

        assert!(!neg0 && !neg1 && !neg2 && !neg3 && !neg4 && !neg5);
        let curve = get_curve(&cbytes);
        let x = SCN::from(UCN::from_bytes(xbytes));
        let y = SCN::from(UCN::from_bytes(ybytes));
        let base = ECPoint::new(curve, x, y);
        let k = UCN::from_bytes(kbytes);
        let a = SCN::from(UCN::from_bytes(abytes));
        let b = SCN::from(UCN::from_bytes(bbytes));
        let result = ECPoint::new(curve, a, b);
        assert_eq!(result, base.scale(&k));
    });
}


//#[test]
//fn verification_tests()
//{
//    run_test("tests/ecdsa/signature.test", 8, |case| {
//        let (neg0, cbytes) = case.get("c").unwrap();
//        let (negx, xbytes) = case.get("x").unwrap();
//        let (negy, ybytes) = case.get("y").unwrap();
//        let (neg1, hbytes) = case.get("h").unwrap();
//        let (neg2, msg)    = case.get("m").unwrap();
//        let (neg3, rbytes) = case.get("r").unwrap();
//        let (neg4, sbytes) = case.get("s").unwrap();
//
//        assert!(!neg0 & !neg1 & !neg2 & !neg3 & !neg4);
//        let curve = get_curve(cbytes);
//        let ux = UCN::from_bytes(xbytes);
//        let uy = UCN::from_bytes(ybytes);
//        let x = SCN{ negative: *negx, value: ux };
//        let y = SCN{ negative: *negy, value: uy };
//        let point = ECCPoint::new(&curve, x, y);
//        let public = ECDSAPublic::new(&curve, &point);
//        let r = UCN::from_bytes(rbytes);
//        let s = UCN::from_bytes(sbytes);
//        println!("r: {:X}", r);
//        let sig = DSASignature{ r: r, s: s };
//
//        match usize::from(UCN::from_bytes(hbytes)) {
//            0x1   => assert!(public.verify::<Sha1>(msg, &sig)),
//            0x224 => assert!(public.verify::<Sha224>(msg, &sig)),
//            0x256 => assert!(public.verify::<Sha256>(msg, &sig)),
//            0x384 => assert!(public.verify::<Sha384>(msg, &sig)),
//            0x512 => assert!(public.verify::<Sha512>(msg, &sig)),
//            v     => panic!("Bad hash size {}!", v)
//        }
//    });
//}
//
//#[test]
//fn signing_tests()
//{
//    run_test("tests/ecdsa/signature.test", 8, |case| {
//        let (neg0, cbytes) = case.get("c").unwrap();
//        let (neg1, dbytes) = case.get("d").unwrap();
//        let (neg2, hbytes) = case.get("h").unwrap();
//        let (neg3, msg)    = case.get("m").unwrap();
//        let (neg4, rbytes) = case.get("r").unwrap();
//        let (neg5, sbytes) = case.get("s").unwrap();
//
//        assert!(!neg0 & !neg1 & !neg2 & !neg3 & !neg4 & !neg5);
//        let curve = get_curve(cbytes);
//        let d = UCN::from_bytes(dbytes);
//        let private = ECDSAPrivate::new(&curve, &d);
//        let r = UCN::from_bytes(rbytes);
//        let s = UCN::from_bytes(sbytes);
//        let sig = DSASignature{ r: r, s: s };
//
//        match usize::from(UCN::from_bytes(hbytes)) {
//            0x1   => assert_eq!(sig, private.sign::<Sha1>(msg)),
//            0x224 => assert_eq!(sig, private.sign::<Sha224>(msg)),
//            0x256 => assert_eq!(sig, private.sign::<Sha256>(msg)),
//            0x384 => assert_eq!(sig, private.sign::<Sha384>(msg)),
//            0x512 => assert_eq!(sig, private.sign::<Sha512>(msg)),
//            v     => panic!("Bad hash size {}!", v)
//        }
//    });
//}
