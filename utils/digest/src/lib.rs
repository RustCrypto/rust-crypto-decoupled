#![no_std]
extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

/// The Digest trait specifies an interface common to digest functions
pub trait Digest : Default {
    type R: ArrayLength<u8>;
    type B: ArrayLength<u8>;

    /// Create new digest instance.
    fn new() -> Self;

    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn input(&mut self, input: &[u8]);

    /// Retrieve the digest result. This method consumes digest instance.
    fn result(self) -> GenericArray<u8, Self::R>;

    /// Get the block size in bytes.
    fn block_bytes(&self) -> usize { Self::B::to_usize() }

    /// Get the block size in bits.
    fn block_bits(&self) -> usize { 8 * Self::B::to_usize() }

    /// Get the output size in bytes.
    fn output_bytes(&self) -> usize { Self::R::to_usize() }

    /// Get the output size in bits.
    fn output_bits(&self) -> usize { 8 * Self::R::to_usize() }
}
