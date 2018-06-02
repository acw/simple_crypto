use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::str::Lines;

fn next_value_set(line: &str) -> (String, bool, Vec<u8>)
{
    assert!(line.is_ascii());
    let mut items = line.split(": ");
    let key = items.next().unwrap();
    let valbits = items.next().unwrap();
    let neg = valbits.contains('-');
    let valbitsnoneg = valbits.trim_left_matches("-");

    let mut nibble_iter = valbitsnoneg.chars().rev();
    let mut val = Vec::new();

    while let Some(c1) = nibble_iter.next() {
        match nibble_iter.next() {
            None => {
                val.push( c1.to_digit(16).unwrap() as u8 );
            }
            Some(c2) => {
                let b1 = c1.to_digit(16).unwrap() as u8;
                let b2 = c2.to_digit(16).unwrap() as u8;
                val.push( (b2 << 4) | b1 );
            }
        }
    }
    val.reverse();

    (key.to_string(), neg, val)
}

fn next_test_case(contents: &mut Lines, lines: usize) ->
    Option<HashMap<String,(bool,Vec<u8>)>>
{
    let mut res = HashMap::new();
    let mut count = 0;

    while count < lines {
        let line = contents.next()?;
        let (key, neg, val) = next_value_set(line);
        res.insert(key, (neg,val));
        count += 1;
    }

    Some(res)
}

pub fn run_test<F>(fname: String, i: usize, f: F)
 where F: Fn(HashMap<String,(bool,Vec<u8>)>)
{
    let mut file = File::open(fname).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut iter = contents.lines();

    while let Some(scase) = next_test_case(&mut iter, i) {
        f(scase);
    }
}
