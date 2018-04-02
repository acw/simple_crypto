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
        impl Into<$base> for $type {
            fn into(self) -> $base {
                if self.contents.is_empty() {
                    0
                } else {
                    self.contents[0] as $base
                }
            }
        }
    }
}

macro_rules! define_signed_into
{
    ($type: ident, $base: ident, $uns: ident) => {
        impl Into<$uns> for $type {
            fn into(self) -> $uns {
                let res: $uns = self.value.into();
                if self.negative { 0-res } else { res }
            }
        }

        impl Into<$base> for $type {
            fn into(self) -> $base {
                let res: $uns = self.value.into();
                if self.negative { (0-res) as $base } else { res as $base }
            }
        }
    }
}
