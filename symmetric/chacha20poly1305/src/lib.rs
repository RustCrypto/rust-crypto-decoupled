#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_aead;
extern crate crypto_symmetric;
extern crate crypto_bytes;
extern crate crypto_mac;
extern crate crypto_ops;
extern crate chacha20;
extern crate poly1305;

use crypto_aead::{AeadEncryptor, AeadDecryptor};
use crypto_symmetric::SynchronousStreamCipher;
use crypto_mac::Mac;
use crypto_bytes::write_u64_le;
use crypto_ops::fixed_time_eq;
use chacha20::ChaCha20;
use poly1305::Poly1305;


#[derive(Clone, Copy)]
pub struct ChaCha20Poly1305 {
    cipher  : ChaCha20,
    mac: Poly1305,
    finished: bool,
    data_len: usize
}

impl ChaCha20Poly1305 {
  pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> ChaCha20Poly1305 {
      assert!(key.len() == 16 || key.len() == 32);
      assert!(nonce.len() == 8);

      let mut cipher = ChaCha20::new(key, nonce);
      let mut mac_key = [0u8; 64];
      let zero_key = [0u8; 64];
      cipher.process(&zero_key, &mut mac_key);

      let mut mac = Poly1305::new(&mac_key[..32]);
      mac.input(aad);
      let mut aad_len = [0u8; 8];
      let aad_len_uint: u64 = aad.len() as u64;
      write_u64_le(&mut aad_len, aad_len_uint);
      mac.input(&aad_len);
      ChaCha20Poly1305 {
        cipher: cipher,
        mac: mac,
        finished: false,
        data_len: 0
      }
  }
}

impl AeadEncryptor for ChaCha20Poly1305 {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
        assert!(input.len() == output.len());
        assert!(self.finished == false);
        self.cipher.process(input, output);
        self.data_len += input.len();
        self.mac.input(output);
        self.finished = true;
        let mut data_len_buf = [0u8; 8];
        write_u64_le(&mut data_len_buf, self.data_len as u64);
        self.mac.input(&data_len_buf);
        self.mac.raw_result(out_tag);
    }
}

impl AeadDecryptor for ChaCha20Poly1305 {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
        assert!(input.len() == output.len());
        assert!(self.finished == false);

        self.finished = true;

        self.mac.input(input);

        self.data_len += input.len();
        let mut data_len_buf = [0u8; 8];

        write_u64_le(&mut data_len_buf, self.data_len as u64);
        self.mac.input(&data_len_buf);

        let mut calc_tag =  [0u8; 16];
        self.mac.raw_result(&mut calc_tag);
        if fixed_time_eq(&calc_tag[..tag.len()], tag) {
            self.cipher.process(input, output);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
