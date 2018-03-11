//! # Simple-Crypto CryptoNum
//!
//! This module is designed to provide large, fixed-width number support for
//! the rest of the Simple-Crypto libraries. Feel free to use it other places,
//! of course, but that's its origin.
mod core;
#[macro_use]
mod builder;
mod traits;

use self::core::*;
use self::traits::*;
use std::cmp::Ordering;
use std::fmt::{Debug,Error,Formatter};
use std::ops::*;

construct_unsigned!(U512,   BarretMu512,   u512,     8);
construct_unsigned!(U1024,  BarretMu1024,  u1024,   16);
construct_unsigned!(U2048,  BarretMu2048,  u2048,   32);
construct_unsigned!(U3072,  BarretMu3072,  u3072,   48);
construct_unsigned!(U4096,  BarretMu4096,  u4096,   64);
construct_unsigned!(U7680,  BarretMu7680,  u7680,  120);
construct_unsigned!(U8192,  BarretMu8192,  u8192,  128);
construct_unsigned!(U15360, BarretMu15360, u15360, 240);
