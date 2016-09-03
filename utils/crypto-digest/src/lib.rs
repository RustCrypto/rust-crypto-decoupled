#![cfg_attr(not(feature="use-std"), no_std)]

#[cfg(feature = "use-std")]
extern crate rustc_serialize;
#[cfg(feature = "use-std")]
extern crate rand;
#[cfg(feature = "use-std")]
use std::iter::repeat;
#[cfg(feature = "use-std")]
use rustc_serialize::hex::ToHex;

#[cfg(feature = "use-std")]
pub mod test_digest;

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

    /// Get the output size in bits.
    fn output_bits(&self) -> usize;

    /// Get the output size in bytes.
    fn output_bytes(&self) -> usize { (self.output_bits() + 7) / 8 }

    /// Get the block size in bytes.
    fn block_size(&self) -> usize;



    /// Convenience function that feeds a string into a digest.
    ///
    /// # Arguments
    ///
    /// * `input` The string to feed into the digest
    fn input_str(&mut self, input: &str) { self.input(input.as_bytes()); }

    // Convenience function that retrieves the result of a digest as a
    // String in hexadecimal format.
    #[cfg(feature = "use-std")]
    fn result_str(&mut self) -> String {
        let mut buf: Vec<u8> =
            repeat(0).take((self.output_bits() + 7) / 8).collect();
        self.result(&mut buf);
        buf[..].to_hex()
    }
}
