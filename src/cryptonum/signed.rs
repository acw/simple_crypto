use cryptonum::core::*;
use cryptonum::traits::*;
use cryptonum::unsigned::*;
use std::cmp::Ordering;
use std::fmt::{Debug,Error,Formatter};
use std::ops::*;

construct_signed!(I512,   U512,   i512);
construct_signed!(I1024,  U1024,  i1024);
construct_signed!(I2048,  U2048,  i2048);
construct_signed!(I3072,  U3072,  i3072);
construct_signed!(I4096,  U4096,  i4096);
construct_signed!(I7680,  U7680,  i7680);
construct_signed!(I8192,  U8192,  i8192);
construct_signed!(I15360, U15360, i15360);
