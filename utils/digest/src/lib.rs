#![no_std]
extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

/// The Digest trait specifies an interface common to digest functions
pub trait Digest : Default {
    type N: ArrayLength<u8>;

    /// Create new digest instance
    fn new() -> Self {
        Default::default()
    }

    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn input(&mut self, input: &[u8]);

    /// Retrieve the digest result. This method consumes digest instance
    fn result(self) -> GenericArray<u8, Self::N>;

    /// Get the block size in bytes.
    fn block_size(&self) -> usize;

    /// Get the output size in bytes.
    fn output_bytes(&self) -> usize { Self::N::to_usize() }

    /// Get the output size in bits.
    fn output_bits(&self) -> usize { Self::N::to_usize() * 8 }
}
