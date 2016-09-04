#![cfg_attr(not(feature="use-std"), no_std)]

extern crate crypto_digest;

#[cfg(feature = "use-std")]
extern crate rand;

#[cfg(feature = "use-std")]
pub mod digest;
