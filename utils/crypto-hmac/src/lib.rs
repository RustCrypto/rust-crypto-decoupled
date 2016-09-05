#![cfg_attr(not(feature="use-std"), no_std)]
extern crate crypto_bytes;
extern crate crypto_digest;
extern crate crypto_mac;

#[cfg(feature="use-std")]
use std::iter::repeat;
#[cfg(not(feature="use-std"))]
use core::iter::repeat;

use crypto_bytes::copy_memory;
use crypto_digest::Digest;
use crypto_mac::{Mac, MacResult};

/// The Hmac struct represents an Hmac function - a Message Authentication Code
/// using a Digest.
pub struct Hmac<D> {
    digest: D,
    i_key: Vec<u8>,
    o_key: Vec<u8>,
    finished: bool
}

fn derive_key(key: &mut [u8], mask: u8) {
    for elem in key.iter_mut() {
        *elem ^= mask;
    }
}

/// The key that Hmac processes must be the same as the block size of the
/// underlying Digest. If the provided key is smaller than that, we just pad it
/// with zeros. If its larger, we hash it and then pad it with zeros.
fn expand_key<D: Digest>(digest: &mut D, key: &[u8]) -> Vec<u8> {
    let bs = digest.block_size();
    let mut expanded_key: Vec<u8> = repeat(0).take(bs).collect();

    if key.len() <= bs {
        copy_memory(key, &mut expanded_key);
    } else {
        let output_size = digest.output_bytes();
        digest.input(key);
        digest.result(&mut expanded_key[..output_size]);
        digest.reset();
    }
    expanded_key
}

/// Hmac uses two keys derived from the provided key - one by xoring every byte
/// with 0x36 and another with 0x5c.
fn create_keys<D: Digest>(digest: &mut D, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i_key = expand_key(digest, key);
    let mut o_key = i_key.clone();
    derive_key(&mut i_key, 0x36);
    derive_key(&mut o_key, 0x5c);
    (i_key, o_key)
}

impl <D: Digest> Hmac<D> {
    /// Create a new Hmac instance.
    ///
    /// # Arguments
    /// * digest - The Digest to use.
    /// * key - The key to use.
    pub fn new(mut digest: D, key: &[u8]) -> Hmac<D> {
        let (i_key, o_key) = create_keys(&mut digest, key);
        digest.input(&i_key[..]);
        Hmac {
            digest: digest,
            i_key: i_key,
            o_key: o_key,
            finished: false
        }
    }
}

impl <D: Digest> Mac for Hmac<D> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.digest.input(data);
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(&self.i_key[..]);
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = self.digest.output_bytes();
        let mut code: Vec<u8> = repeat(0).take(output_size).collect();

        self.raw_result(&mut code);

        MacResult::new_from_owned(code)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        if !self.finished {
            self.digest.result(output);

            self.digest.reset();
            self.digest.input(&self.o_key[..]);
            self.digest.input(output);

            self.finished = true;
        }

        self.digest.result(output);
    }

    fn output_bytes(&self) -> usize { self.digest.output_bytes() }
}

#[cfg(test)]
mod tests;
