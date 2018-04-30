use cryptonum::unsigned::BarrettUCN;
use testing::{make_signed,make_unsigned,run_test};

#[test]
fn unsigned_sum_test()
{
    run_test("tests/math/unsigned_add.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        let res   = x + y;
        assert_eq!(res, *z);
    });
}

#[test]
fn signed_sum_test()
{
    run_test("tests/math/signed_add.tests", 3, |bcase| {
        let case  = make_signed(bcase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x + y, *z);
    });
}

#[test]
fn unsigned_sub_test()
{
    run_test("tests/math/unsigned_sub.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x - y, *z);
    });
}

#[test]
fn signed_sub_test()
{
    run_test("tests/math/signed_sub.tests", 3, |bcase| {
        let case  = make_signed(bcase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x - y, *z);
    });
}

#[test]
fn unsigned_mul_test()
{
    run_test("tests/math/unsigned_mul.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x * y, *z);
    });
}

#[test]
fn signed_mul_test()
{
    run_test("tests/math/signed_mul.tests", 3, |bcase| {
        let case  = make_signed(bcase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x * y, *z);
    });
}

#[test]
fn unsigned_div_test()
{
    run_test("tests/math/unsigned_div.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x / y, *z);
    });
}

#[test]
fn signed_div_test()
{
    run_test("tests/math/signed_div.tests", 3, |bcase| {
        let case  = make_signed(bcase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x / y, *z);
    });
}

#[test]
fn unsigned_mod_test()
{
    run_test("tests/math/unsigned_mod.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x % y, *z);
    });
}

#[test]
fn signed_mod_test()
{
    run_test("tests/math/signed_mod.tests", 3, |bcase| {
        let case  = make_signed(bcase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x % y, *z);
    });
}

#[test]
fn modular_exponentiation_test()
{
    run_test("tests/math/modexp.tests", 4, |scase| {
        let case  = make_unsigned(scase);
        let a     = case.get("a").unwrap();
        let b     = case.get("b").unwrap();
        let m     = case.get("m").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(a.modexp(&b, &m), *z);
    });
}

#[test]
fn fast_modular_exponentiation_test()
{
    run_test("tests/math/fastmodexp.tests", 6, |scase| {
        let case  = make_unsigned(scase);
        let a     = case.get("a").unwrap();
        let b     = case.get("b").unwrap();
        let kbig  = case.get("k").unwrap();
        let k     = usize::from(kbig);
        let m     = case.get("m").unwrap();
        let u     = case.get("u").unwrap();
        let z     = case.get("z").unwrap();
        let mu    = BarrettUCN{ k: k, u: u.clone(), m: m.clone() };
        assert_eq!(a.fastmodexp(&b, &mu), *z);
    });
}

#[test]
fn barrett_reduction_test()
{
    run_test("tests/math/barrett.tests", 5, |scase| {
        let case     = make_unsigned(scase);
        let kbig     = case.get("k").unwrap();
        let m        = case.get("m").unwrap();
        let r        = case.get("r").unwrap();
        let u        = case.get("u").unwrap();
        let v        = case.get("v").unwrap();
        let k        = usize::from(kbig);
        let barrett  = m.barrett_u();
        let result   = v.reduce(&barrett);
        assert_eq!(barrett.k, k);
        assert_eq!(&barrett.u, u);
        assert_eq!(&barrett.m, m);
        assert_eq!(&result, r);
    });
}

#[test]
fn modular_inverse_test()
{
    run_test("tests/math/modinv.tests", 3, |scase| {
        let case     = make_unsigned(scase);
        let a        = case.get("x").unwrap();
        let m        = case.get("y").unwrap();
        let r        = case.get("z").unwrap();
        let result   = a.modinv(m);
        assert_eq!(r, &result);
    });
}
