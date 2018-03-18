macro_rules! generate_unsigned_conversions
{
    ($type: ident, $count: expr) => {
        generate_unsigned_primtype_conversions!($type, u8,  $count);
        generate_unsigned_primtype_conversions!($type, u16, $count);
        generate_unsigned_primtype_conversions!($type, u32, $count);
        generate_unsigned_primtype_conversions!($type, u64, $count);
    }
}

macro_rules! generate_signed_conversions
{
    ($type: ident, $base: ident) => {
        generate_signed_primtype_conversions!($type, $base, i8,  u8);
        generate_signed_primtype_conversions!($type, $base, i16, u16);
        generate_signed_primtype_conversions!($type, $base, i32, u32);
        generate_signed_primtype_conversions!($type, $base, i64, u64);
    }
}

macro_rules! generate_unsigned_primtype_conversions
{
    ($type: ident, $base: ty, $count: expr) => {
        generate_from!($type, $base, x, {
            let mut res = $type{ contents: [0; $count] };
            res.contents[0] = x as u64;
            res
        });
        generate_into!($type, $base, self, {
            self.contents[0] as $base
        });
    }
}

macro_rules! generate_signed_primtype_conversions
{
    ($type: ident, $untype: ident, $base: ident, $unbase: ident) => {
        generate_from!($type, $unbase, x, {
            $type{ negative: false, value: $untype::from(x) }
        });
        generate_into!($type, $unbase, self, {
            self.value.contents[0] as $unbase
        });
        generate_from!($type, $base, x, {
            let neg = x < 0;
            $type{negative: neg, value: $untype::from(x.abs() as $unbase)}
        });
        generate_into!($type, $base, self, {
            if self.negative {
                let start = self.value.contents[0] as $unbase;
                let mask = ($unbase::max_value() - 1) >> 1;
                let res = (start & mask) as $base;
                -res
            } else {
                self.value.contents[0] as $base
            }
        });
    }
}

macro_rules! generate_from
{
    ($type: ident, $base: ty, $x: ident, $body: block) => {
        impl From<$base> for $type {
            fn from($x: $base) -> $type $body
        }
    }
}

macro_rules! generate_into
{
    ($type: ident, $base: ty, $self: ident, $body: block) => {
        impl Into<$base> for $type {
            fn into($self) -> $base $body
        }
    }
}
