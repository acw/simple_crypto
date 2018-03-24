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
