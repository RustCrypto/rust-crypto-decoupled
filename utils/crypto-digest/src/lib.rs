#![no_std]

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
}
