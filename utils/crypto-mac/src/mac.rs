use crypto_ops::fixed_time_eq;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

/// The Mac trait defines methods for a Message Authentication function.
pub trait Mac {
    type R: ArrayLength<u8>;

    /// Process input data.
    ///
    /// # Arguments
    /// * data - The input data to process.
    fn input(&mut self, data: &[u8]);

    /// Obtain the result of a Mac computation as a MacResult.
    fn result(self) -> MacResult<Self::R>;

    /// Get the size of the Mac code, in bytes.
    fn output_bytes(&self) -> usize { Self::R::to_usize() }
}

/// A MacResult wraps a Mac code and provides a safe Eq implementation that runs
/// in fixed time.
pub struct MacResult<N: ArrayLength<u8>> {
    code: GenericArray<u8, N>
}

impl<N> MacResult<N> where N: ArrayLength<u8> {
    /// Create a new MacResult.
    pub fn new(code: GenericArray<u8, N>) -> MacResult<N> {
        MacResult{code: code}
    }
}

impl<N> PartialEq for MacResult<N> where N: ArrayLength<u8> {
    fn eq(&self, x: &MacResult<N>) -> bool {
        fixed_time_eq(&self.code[..], &x.code[..])
    }
}

impl<N> Eq for MacResult<N> where N: ArrayLength<u8> { }
