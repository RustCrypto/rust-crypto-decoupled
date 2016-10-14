#![no_std]
extern crate crypto_ops;
extern crate generic_array;
extern crate byte_tools;
extern crate digest;

mod mac;
pub use mac::{Mac, MacResult};

mod hmac;
pub use hmac::{Hmac};
