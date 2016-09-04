#![cfg_attr(not(feature="use-std"), no_std)]
extern crate constant_op;
use constant_op::fixed_time_eq;

/// The Mac trait defines methods for a Message Authentication function.
pub trait Mac<MacResult> {
    /// Process input data.
    ///
    /// # Arguments
    /// * data - The input data to process.
    fn input(&mut self, data: &[u8]);

    /// Reset the Mac state to begin processing another input stream.
    fn reset(&mut self);

    /// Obtain the result of a Mac computation as a MacResult.
    fn result(&mut self) -> MacResult;

    /// Obtain the result of a Mac computation as [u8]. This method should be
    /// used very carefully since incorrect use of the Mac code could result in
    /// permitting a timing attack which defeats the security provided by a Mac
    /// function.
    fn raw_result(&mut self, output: &mut [u8]);

    /// Get the size of the Mac code, in bytes.
    fn output_bytes(&self) -> usize;
}

/// A MacResult wraps a Mac code and provides a safe Eq implementation that runs
/// in fixed time.
pub struct MacResult128 {
    code: [u8; 16]
}

impl MacResult128 {
    /// Create a new MacResult.
    pub fn new(code: [u8; 16]) -> MacResult128 {
        MacResult128{code: code}
    }

    /// Create a new MacResult from slice
    pub fn new_from_slice(code: &[u8]) -> MacResult128 {
        assert_eq!(code.len(), 16);
        let mut mac = MacResult128{code: Default::default()};
        mac.code.clone_from_slice(code);
        mac
    }

    /// Get the code value. Be very careful using this method, since incorrect
    /// use of the code value may permit timing attacks which defeat the
    /// security provided by the Mac function.
    pub fn code<'s>(&'s self) -> &'s [u8] {
        &self.code[..]
    }
}

impl PartialEq for MacResult128 {
    fn eq(&self, x: &MacResult128) -> bool {
        fixed_time_eq(&self.code[..], &x.code[..])
    }
}

impl Eq for MacResult128 { }
