#![no_std]
extern crate crypto_buffers;
extern crate generic_array;

use crypto_buffers::{BufferResult, RefReadBuffer, RefWriteBuffer, ReadBuffer,
                     WriteBuffer};
use core::cmp;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::{U8, U16};

pub type Block<N> = GenericArray<u8, N>;
pub type Block64 = Block<U8>;
pub type Block128 = Block<U16>;

pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    fn encrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);

    fn decrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);
}


pub trait BlockEncryptorX8 {
    fn block_size(&self) -> usize;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> usize;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
pub enum SymmetricCipherError {
    InvalidLength,
    InvalidPadding,
}

pub trait Encryptor {
    fn encrypt(&mut self, input: &mut RefReadBuffer,
               output: &mut RefWriteBuffer, eof: bool)
               -> Result<BufferResult, SymmetricCipherError>;
}

pub trait Decryptor {
    fn decrypt(&mut self, input: &mut RefReadBuffer,
               output: &mut RefWriteBuffer, eof: bool)
               -> Result<BufferResult, SymmetricCipherError>;
}

pub trait SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}

/*

// TODO - Its a bit unclear to me why this is necessary
impl SynchronousStreamCipher for Box<SynchronousStreamCipher + 'static> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        let me = &mut **self;
        me.process(input, output);
    }
}

impl Encryptor for Box<SynchronousStreamCipher + 'static> {
    fn encrypt(&mut self, input: &mut RefReadBuffer,
               output: &mut RefWriteBuffer, _: bool)
               -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Box<SynchronousStreamCipher + 'static> {
    fn decrypt(&mut self, input: &mut RefReadBuffer,
               output: &mut RefWriteBuffer, _: bool)
               -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}*/

/// `symm_enc_or_dec()` implements the necessary functionality to turn a
/// `SynchronousStreamCipher` into an Encryptor or Decryptor
pub fn symm_enc_or_dec<S: SynchronousStreamCipher,
                       R: ReadBuffer,
                       W: WriteBuffer>
    (c: &mut S, input: &mut R, output: &mut W)
     -> Result<BufferResult, SymmetricCipherError> {
    let count = cmp::min(input.remaining(), output.remaining());
    c.process(input.take_next(count), output.take_next(count));
    if input.is_empty() {
        Ok(BufferResult::BufferUnderflow)
    } else {
        Ok(BufferResult::BufferOverflow)
    }
}
