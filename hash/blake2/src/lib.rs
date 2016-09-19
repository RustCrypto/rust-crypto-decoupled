#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_digest;
extern crate crypto_mac;
extern crate crypto_ops;
#[cfg(test)]
#[macro_use]
extern crate crypto_tests;

mod consts;

mod blake2b;
pub use blake2b::Blake2b;

mod blake2s;
pub use blake2s::Blake2s;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
