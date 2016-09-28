#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_buffers;
extern crate crypto_symmetric;
extern crate simd;

use core::cmp;
use crypto_buffers::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto_symmetric::{Encryptor, Decryptor, SynchronousStreamCipher,
                       SymmetricCipherError, symm_enc_or_dec};
use crypto_bytes::{read_u32_le, write_u32_le, xor_keystream};
use simd::u32x4;

#[derive(Clone,Copy)]
struct ChaChaState {
  a: u32x4,
  b: u32x4,
  c: u32x4,
  d: u32x4
}

#[derive(Copy)]
pub struct ChaCha20 {
    state  : ChaChaState,
    output : [u8; 64],
    offset : usize,
}

impl Clone for ChaCha20 { fn clone(&self) -> ChaCha20 { *self } }

macro_rules! swizzle{
    ($b: expr, $c: expr, $d: expr) => {{
        let u32x4(b10, b11, b12, b13) = $b;
        $b = u32x4(b11, b12, b13, b10);
        let u32x4(c10, c11, c12, c13) = $c;
        $c = u32x4(c12, c13,c10, c11);
        let u32x4(d10, d11, d12, d13) = $d;
        $d = u32x4(d13, d10, d11, d12);
    }}
}

macro_rules! state_to_buffer {
    ($state: expr, $output: expr) => {{
        let u32x4(a1, a2, a3, a4) = $state.a;
        let u32x4(b1, b2, b3, b4) = $state.b;
        let u32x4(c1, c2, c3, c4) = $state.c;
        let u32x4(d1, d2, d3, d4) = $state.d;
        let lens = [
            a1,a2,a3,a4,
            b1,b2,b3,b4,
            c1,c2,c3,c4,
            d1,d2,d3,d4
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut $output[i*4..(i+1)*4], lens[i]);
        }
    }}
}

macro_rules! round{
    ($state: expr) => {{
      $state.a = $state.a + $state.b;
      rotate!($state.d, $state.a, S16);
      $state.c = $state.c + $state.d;
      rotate!($state.b, $state.c, S12);
      $state.a = $state.a + $state.b;
      rotate!($state.d, $state.a, S8);
      $state.c = $state.c + $state.d;
      rotate!($state.b, $state.c, S7);
    }}
}

macro_rules! rotate {
    ($a: expr, $b: expr, $c:expr) => {{
      let v = $a ^ $b;
      let r = S32 - $c;
      let right = v >> r;
      $a = (v << $c) ^ right
    }}
}

static S32:u32x4 = u32x4(32, 32, 32, 32);
static S16:u32x4 = u32x4(16, 16, 16, 16);
static S12:u32x4 = u32x4(12, 12, 12, 12);
static S8:u32x4 = u32x4(8, 8, 8, 8);
static S7:u32x4 = u32x4(7, 7, 7, 7);

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8 || nonce.len() == 12);

        ChaCha20{ state: ChaCha20::expand(key, nonce), output: [0u8; 64], offset: 64 }
    }

    pub fn new_xchacha20(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert!(key.len() == 32);
        assert!(nonce.len() == 24);

        // HChaCha20 produces a 256-bit output block starting from a 512 bit
        // input block where (x0,x1,...,x15) where
        //
        //  * (x0, x1, x2, x3) is the ChaCha20 constant.
        //  * (x4, x5, ... x11) is a 256 bit key.
        //  * (x12, x13, x14, x15) is a 128 bit nonce.
        let mut xchacha20 = ChaCha20{
            state: ChaCha20::expand(key, &nonce[0..16]),
            output: [0u8; 64],
            offset: 64 };

        // Use HChaCha to derive the subkey, and initialize a ChaCha20 instance
        // with the subkey and the remaining 8 bytes of the nonce.
        let mut new_key = [0; 32];
        xchacha20.hchacha20(&mut new_key);
        xchacha20.state = ChaCha20::expand(&new_key, &nonce[16..24]);

        xchacha20
    }

    fn expand(key: &[u8], nonce: &[u8]) -> ChaChaState {

        let constant = match key.len() {
            16 => b"expand 16-byte k",
            32 => b"expand 32-byte k",
            _  => unreachable!(),
        };
        ChaChaState {
            a: u32x4(
                read_u32_le(&constant[0..4]),
                read_u32_le(&constant[4..8]),
                read_u32_le(&constant[8..12]),
                read_u32_le(&constant[12..16])
            ),
            b: u32x4(
                read_u32_le(&key[0..4]),
                read_u32_le(&key[4..8]),
                read_u32_le(&key[8..12]),
                read_u32_le(&key[12..16])
            ),
            c: if key.len() == 16 {
                    u32x4(
                        read_u32_le(&key[0..4]),
                        read_u32_le(&key[4..8]),
                        read_u32_le(&key[8..12]),
                        read_u32_le(&key[12..16])
                    )
                } else {
                    u32x4(
                        read_u32_le(&key[16..20]),
                        read_u32_le(&key[20..24]),
                        read_u32_le(&key[24..28]),
                        read_u32_le(&key[28..32])
                    )
                },
            d: if nonce.len() == 16 {
                   u32x4(
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8]),
                        read_u32_le(&nonce[8..12]),
                        read_u32_le(&nonce[12..16])
                    )
               } else if nonce.len() == 12 {
                   u32x4(
                        0,
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8]),
                        read_u32_le(&nonce[8..12])
                    )
               } else {
                   u32x4(
                        0,
                        0,
                        read_u32_le(&nonce[0..4]),
                        read_u32_le(&nonce[4..8])
                    )
               }
        }
    }

    fn hchacha20(&mut self, out: &mut [u8]) -> () {
        let mut state = self.state;

        // Apply r/2 iterations of the same "double-round" function,
        // obtaining (z0, z1, ... z15) = doubleround r/2 (x0, x1, ... x15).
        for _ in 0..10 {
            round!(state);
            let u32x4(b10, b11, b12, b13) = state.b;
            state.b = u32x4(b11, b12, b13, b10);
            let u32x4(c10, c11, c12, c13) = state.c;
            state.c = u32x4(c12, c13,c10, c11);
            let u32x4(d10, d11, d12, d13) = state.d;
            state.d = u32x4(d13, d10, d11, d12);
            round!(state);
            let u32x4(b20, b21, b22, b23) = state.b;
            state.b = u32x4(b23, b20, b21, b22);
            let u32x4(c20, c21, c22, c23) = state.c;
            state.c = u32x4(c22, c23, c20, c21);
            let u32x4(d20, d21, d22, d23) = state.d;
            state.d = u32x4(d21, d22, d23, d20);
        }

        // HChaCha20 then outputs the 256-bit block (z0, z1, z2, z3, z12, z13,
        // z14, z15).  These correspond to the constant and input positions in
        // the ChaCha matrix.
        let u32x4(a1, a2, a3, a4) = state.a;
        let u32x4(d1, d2, d3, d4) = state.d;
        let lens = [
            a1,a2,a3,a4,
            d1,d2,d3,d4
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut out[i*4..(i+1)*4], lens[i]);
        }
    }

    // put the the next 64 keystream bytes into self.output
    fn update(&mut self) {
        let mut state = self.state;

        for _ in 0..10 {
            round!(state);
            swizzle!(state.b, state.c, state.d);
            round!(state);
            swizzle!(state.d, state.c, state.b);
        }
        state.a = state.a + self.state.a;
        state.b = state.b + self.state.b;
        state.c = state.c + self.state.c;
        state.d = state.d + self.state.d;

        state_to_buffer!(state, self.output);

        self.state.d = self.state.d + u32x4(1, 0, 0, 0);
        let u32x4(c12, _, _, _) = self.state.d;
        if c12 == 0 {
            // we could increment the other counter word with an 8 byte nonce
            // but other implementations like boringssl have this same
            // limitation
            panic!("counter is exhausted");
        }

        self.offset = 0;
    }
}

impl SynchronousStreamCipher for ChaCha20 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0;
        while i < len {
            // If there is no keystream available in the output buffer,
            // generate the next block.
            if self.offset == 64 {
                self.update();
            }

            // Process the min(available keystream, remaining input length).
            let count = cmp::min(64 - self.offset, len - i);
            xor_keystream(&mut output[i..i+count], &input[i..i+count],
                &self.output[self.offset..]);
            i += count;
            self.offset += count;
        }
    }
}

impl Encryptor for ChaCha20 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for ChaCha20 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
