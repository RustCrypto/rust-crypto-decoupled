#![cfg_attr(not(feature="std"), no_std)]

#[cfg(feature = "std")]
extern crate rustc_serialize;
#[cfg(feature = "std")]
use rustc_serialize::hex::ToHex;

// Small crutch until type level integers are here
// Max hash size is equal to 512 bits, but to test sha3 extendable output function
// we need 512 bytes
pub const MAX_DIGEST_SIZE: usize = 512;

/// The Digest trait specifies an interface common to digest functions, such as
/// SHA-1 and the SHA-2 family of digest functions.
pub trait Digest {
    /// Provide message data.
    ///
    /// # Arguments
    ///
    /// * input - A vector of message data
    fn input(&mut self, input: &[u8]);

    /// Retrieve the digest result. This method may be called multiple times.
    ///
    /// # Arguments
    ///
    /// * out - the vector to hold the result. Must be large enough to contain
    /// `output_bits()`.
    fn result(&mut self, out: &mut [u8]);

    /// Reset the digest. This method must be called after `result()` and before
    /// supplying more data.
    fn reset(&mut self);

    /// Get the output size in bytes.
    fn output_bytes(&self) -> usize;

    /// Get the block size in bytes.
    fn block_size(&self) -> usize;

    /// Get the output size in bits.
    fn output_bits(&self) -> usize { self.output_bytes() * 8 }

    /// Convenience function that feeds a string into a digest.
    ///
    /// # Arguments
    ///
    /// * `input` The string to feed into the digest
    fn input_str(&mut self, input: &str) { self.input(input.as_bytes()); }

    /// Convenience function that retrieves the result of a digest as a
    /// String in hexadecimal format.
    #[cfg(feature = "std")]
    fn result_str(&mut self) -> String {
        let mut buf = [0u8; MAX_DIGEST_SIZE];
        self.result(&mut buf);
        buf[..self.output_bytes()].to_hex()
    }
}
