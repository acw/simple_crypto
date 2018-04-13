macro_rules! define_from
{
    ($type: ident, $base: ident) => {
        impl From<$base> for $type {
            fn from(x: $base) -> $type {
                if x == 0 {
                    UCN{ contents: Vec::new() }
                } else {
                    UCN{ contents: vec![x as u64] }
                }
            }
        }
    }
}

macro_rules! define_signed_from
{
    ($type: ident, $base: ident, $uns: ident) => {
        impl From<$uns> for $type {
            fn from(x: $uns) -> $type {
                SCN{ negative: false, value: UCN::from(x) }
            }
        }

        impl From<$base> for $type {
            fn from(x: $base) -> $type {
                let neg = x < 0;
                let absx = x.abs();
                SCN{ negative: neg, value: UCN::from(absx as $uns) }
            }
        }
    }
}

macro_rules! define_into
{
    ($type: ident, $base: ident) => {
        impl<'a> From<&'a $type> for $base {
            fn from(x: &$type) -> $base {
                if x.contents.is_empty() {
                    0
                } else {
                   x.contents[0] as $base
                }
            }
        }

        impl From<$type> for $base {
            fn from(x: $type) -> $base {
                $base::from(&x)
            }
        }
    }
}

macro_rules! define_signed_into
{
    ($type: ident, $base: ident, $uns: ident) => {
        impl<'a> From<&'a $type> for $uns {
            fn from(x: &$type) -> $uns {
                let res: $uns = $uns::from(&x.value);
                if x.negative { 0-res } else { res }
            }
        }

        impl<'a> From<&'a $type> for $base {
            fn from(x: &$type) -> $base {
                let res: $uns = $uns::from(&x.value);
                if x.negative { (0-res) as $base } else { res as $base }
            }
        }

        impl From<$type> for $uns {
            fn from(x: $type) -> $uns {
                $uns::from(&x)
            }
        }

        impl From<$type> for $base {
            fn from(x: $type) -> $base {
                $base::from(&x)
            }
        }
    }
}
