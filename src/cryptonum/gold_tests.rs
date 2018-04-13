use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::str::Lines;

use cryptonum::unsigned::{UCN,BarrettUCN};
use cryptonum::signed::SCN;

fn next_value_set(line: &str) -> (String, SCN)
{
    assert!(line.is_ascii());
    assert_eq!(": ", &line[1..3]);
    let key = String::from(&line[0..1]);
    let val = SCN::from_str(&line[3..]);
    (key, val)
}

fn next_test_case(contents: &mut Lines, lines: usize) ->
    Option<HashMap<String,SCN>>
{
    let mut res = HashMap::new();
    let mut count = 0;

    while count < lines {
        let line = contents.next()?;
        let (key, val) = next_value_set(line);
        res.insert(key, val);
        count += 1;
    }

    Some(res)
}

fn make_unsigned(m: HashMap<String,SCN>) -> HashMap<String,UCN>
{
    let mut res: HashMap<String,UCN> = HashMap::new();

    for (key, sval) in m.iter() {
        assert!(!sval.is_negative());
        res.insert(key.clone(), sval.clone().into());
    }

    res
}

fn run_test<F>(fname: &'static str, i: usize, f: F)
 where F: Fn(HashMap<String,SCN>)
{
    let mut file = File::open(fname).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut iter = contents.lines();

    while let Some(scase) = next_test_case(&mut iter, i) {
        f(scase);
    }
}

#[test]
fn unsigned_sum_test()
{
    run_test("tests/math/unsigned_add.tests", 3, |scase| {
        let case  = make_unsigned(scase);
        let x     = case.get("x").unwrap();
        let y     = case.get("y").unwrap();
        let z     = case.get("z").unwrap();
        assert_eq!(x + y, *z);
    });
}

#[test]
fn signed_sum_test()
{
    run_test("tests/math/signed_add.tests", 3, |case| {
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
    run_test("tests/math/signed_sub.tests", 3, |case| {
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
    run_test("tests/math/signed_mul.tests", 3, |case| {
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
    run_test("tests/math/signed_div.tests", 3, |case| {
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
    run_test("tests/math/signed_mod.tests", 3, |case| {
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
