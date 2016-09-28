#![no_std]

pub trait AeadEncryptor {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]);
}

pub trait AeadDecryptor {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool;
}
