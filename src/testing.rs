use cryptonum::{SCN,UCN};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::str::Lines;

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

pub fn make_unsigned(m: HashMap<String,SCN>) -> HashMap<String,UCN>
{
    let mut res: HashMap<String,UCN> = HashMap::new();

    for (key, sval) in m.iter() {
        assert!(!sval.is_negative());
        res.insert(key.clone(), sval.clone().into());
    }

    res
}

pub fn run_test<F>(fname: &'static str, i: usize, f: F)
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


