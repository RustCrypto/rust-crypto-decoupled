#![cfg_attr(not(feature="use-std"), no_std)]
extern crate crypto_bytes;
use crypto_bytes::{copy_memory, zero};

/// A `FixedBuffer`, likes its name implies, is a fixed size buffer. When the
/// buffer becomes full, it must be processed. The input() method takes care of
/// processing and then clearing the buffer automatically. However, other
/// methods do not and require the caller to process the buffer. Any method that
/// modifies the buffer directory or provides the caller with bytes that can be
/// modifies results in those bytes being marked as used by the buffer.
pub trait FixedBuffer {
    /// Input a vector of bytes. If the buffer becomes full, process it with the
    /// provided function and then clear the buffer.
    fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], func: F);

    /// Reset the buffer.
    fn reset(&mut self);

    /// Zero the buffer up until the specified index. The buffer position
    /// currently must not be greater than that index.
    fn zero_until(&mut self, idx: usize);

    /// Get a slice of the buffer of the specified size. There must be at least
    /// that many bytes remaining in the buffer.
    fn next(&mut self, len: usize) -> &mut [u8];

    /// Get the current buffer. The buffer must already be full. This clears the
    /// buffer as well.
    fn full_buffer(&mut self) -> &[u8];

    /// Get the current buffer.
    fn current_buffer(&mut self) -> &[u8];

    /// Get the current position of the buffer.
    fn position(&self) -> usize;

    /// Get the number of bytes remaining in the buffer until it is full.
    fn remaining(&self) -> usize;

    /// Get the size of the buffer
    fn size(&self) -> usize;
}

macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
    impl FixedBuffer for $name {
        fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
            let mut i = 0;
            // FIXME: #6304 - This local variable shouldn't be necessary.
            let size = $size;
            // If there is already data in the buffer, copy as much as we can
            // into it and process the data if the buffer becomes full.
            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if input.len() >= buffer_remaining {
                        copy_memory(
                            &input[..buffer_remaining],
                            &mut self.buffer[self.buffer_idx..size]);
                    self.buffer_idx = 0;
                    func(&self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_memory(
                        input,
                        &mut self.buffer[self.buffer_idx..][..input.len()]);
                    self.buffer_idx += input.len();
                    return;
                }
            }

            // While we have at least a full buffer size chunks's worth of data,
            // process that data without copying it into the buffer
            while input.len() - i >= size {
                func(&input[i..i + size]);
                i += size;
            }

            // Copy any input data into the buffer. At this point in the method,
            // the ammount of data left in the input vector will be less than
            // the buffer size and the buffer will be empty.
            let input_remaining = input.len() - i;
            copy_memory(
                &input[i..],
                &mut self.buffer[0..input_remaining]);
            self.buffer_idx += input_remaining;
        }

        fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        fn zero_until(&mut self, idx: usize) {
            assert!(idx >= self.buffer_idx);
            zero(&mut self.buffer[self.buffer_idx..idx]);
            self.buffer_idx = idx;
        }

        fn next(&mut self, len: usize) -> &mut [u8] {
            self.buffer_idx += len;
            &mut self.buffer[self.buffer_idx - len..self.buffer_idx]
        }

        fn full_buffer(& mut self) -> &[u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            &self.buffer[..$size]
        }

        fn current_buffer(&mut self) -> &[u8] {
            let tmp = self.buffer_idx;
            self.buffer_idx = 0;
            &self.buffer[..tmp]
        }

        fn position(&self) -> usize { self.buffer_idx }

        fn remaining(&self) -> usize { $size - self.buffer_idx }

        fn size(&self) -> usize { $size }
    }
));

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
#[derive(Copy)]
pub struct FixedBuffer64 {
    buffer: [u8; 64],
    buffer_idx: usize,
}

impl Clone for FixedBuffer64 {
    fn clone(&self) -> FixedBuffer64 { *self }
}

impl FixedBuffer64 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer64 {
        FixedBuffer64 {
            buffer: [0u8; 64],
            buffer_idx: 0,
        }
    }
}

impl Default for FixedBuffer64 {
    fn default() -> Self { Self::new() }
}


impl_fixed_buffer!(FixedBuffer64, 64);

/// A fixed size buffer of 128 bytes useful for cryptographic operations.
#[derive(Copy)]
pub struct FixedBuffer128 {
    buffer: [u8; 128],
    buffer_idx: usize,
}

impl Clone for FixedBuffer128 {
    fn clone(&self) -> FixedBuffer128 { *self }
}

impl FixedBuffer128 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer128 {
        FixedBuffer128 {
            buffer: [0u8; 128],
            buffer_idx: 0,
        }
    }
}

impl Default for FixedBuffer128 {
    fn default() -> Self { Self::new() }
}

impl_fixed_buffer!(FixedBuffer128, 128);


/// The `StandardPadding` trait adds a method useful for various hash algorithms
/// to a `FixedBuffer` struct.
pub trait StandardPadding {
    /// Add standard padding to the buffer. The buffer must not be full when
    /// this method is called and is guaranteed to have exactly rem remaining
    /// bytes when it returns. If there are not at least rem bytes available,
    /// the buffer will be zero padded, processed, cleared, and then filled with
    /// zeros again until only rem bytes are remaining.
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, func: F);
}

impl<T: FixedBuffer> StandardPadding for T {
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}
