#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_buffers;
extern crate crypto_bytes;
extern crate crypto_symmetric;
extern crate simd;

#[cfg(test)]
extern crate sha2;
#[cfg(test)]
extern crate crypto_digest;

use crypto_buffers::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto_symmetric::{Encryptor, Decryptor, SynchronousStreamCipher,
                       SymmetricCipherError, symm_enc_or_dec};
use crypto_bytes::{read_u32_le, write_u32_le, xor_keystream};
use simd::u32x4;

use core::cmp;

#[derive(Clone, Copy)]
struct SalsaState {
  a: u32x4,
  b: u32x4,
  c: u32x4,
  d: u32x4
}

#[derive(Copy)]
pub struct Salsa20 {
    state: SalsaState,
    output: [u8; 64],
    offset: usize,
}

impl Clone for Salsa20 { fn clone(&self) -> Salsa20 { *self } }

const S7:u32x4 = u32x4(7, 7, 7, 7);
const S9:u32x4 = u32x4(9, 9, 9, 9);
const S13:u32x4 = u32x4(13, 13, 13, 13);
const S18:u32x4 = u32x4(18, 18, 18, 18);
const S32:u32x4 = u32x4(32, 32, 32, 32);

macro_rules! prepare_rowround {
    ($a: expr, $b: expr, $c: expr) => {{
        let u32x4(a10, a11, a12, a13) = $a;
        $a = u32x4(a13, a10, a11, a12);
        let u32x4(b10, b11, b12, b13) = $b;
        $b = u32x4(b12, b13, b10, b11);
        let u32x4(c10, c11, c12, c13) = $c;
        $c = u32x4(c11, c12, c13, c10);
    }}
}

macro_rules! prepare_columnround {
    ($a: expr, $b: expr, $c: expr) => {{
        let u32x4(a13, a10, a11, a12) = $a;
        $a = u32x4(a10, a11, a12, a13);
        let u32x4(b12, b13, b10, b11) = $b;
        $b = u32x4(b10, b11, b12, b13);
        let u32x4(c11, c12, c13, c10) = $c;
        $c = u32x4(c10, c11, c12, c13);
    }}
}

macro_rules! add_rotate_xor {
    ($dst: expr, $a: expr, $b: expr, $shift: expr) => {{
        let v = $a + $b;
        let r = S32 - $shift;
        let right = v >> r;
        $dst = $dst ^ (v << $shift) ^ right
    }}
}

fn columnround(state: &mut SalsaState) -> () {
    add_rotate_xor!(state.a, state.d, state.c, S7);
    add_rotate_xor!(state.b, state.a, state.d, S9);
    add_rotate_xor!(state.c, state.b, state.a, S13);
    add_rotate_xor!(state.d, state.c, state.b, S18);
}

fn rowround(state: &mut SalsaState) -> () {
    add_rotate_xor!(state.c, state.d, state.a, S7);
    add_rotate_xor!(state.b, state.c, state.d, S9);
    add_rotate_xor!(state.a, state.c, state.b, S13);
    add_rotate_xor!(state.d, state.a, state.b, S18);
}

impl Salsa20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Salsa20 {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8);
        Salsa20 { state: Salsa20::expand(key, nonce), output: [0; 64], offset: 64 }
    }

    pub fn new_xsalsa20(key: &[u8], nonce: &[u8]) -> Salsa20 {
        assert!(key.len() == 32);
        assert!(nonce.len() == 24);
        let mut xsalsa20 = Salsa20 { state: Salsa20::expand(key, &nonce[0..16]), output: [0; 64], offset: 64 };

        let mut new_key = [0; 32];
        xsalsa20.hsalsa20_hash(&mut new_key);
        xsalsa20.state = Salsa20::expand(&new_key, &nonce[16..24]);

        xsalsa20
    }

    fn expand(key: &[u8], nonce: &[u8]) -> SalsaState {
        let constant = match key.len() {
            16 => b"expand 16-byte k",
            32 => b"expand 32-byte k",
            _  => unreachable!(),
        };

        // The state vectors are laid out to facilitate SIMD operation,
        // instead of the natural matrix ordering.
        //
        //  * Constant (x0, x5, x10, x15)
        //  * Key (x1, x2, x3, x4, x11, x12, x13, x14)
        //  * Input (x6, x7, x8, x9)

        let key_tail; // (x11, x12, x13, x14)
        if key.len() == 16 {
            key_tail = key;
        } else {
            key_tail = &key[16..32];
        }

        let x8; let x9; // (x8, x9)
        if nonce.len() == 16 {
            // HSalsa uses the full 16 byte nonce.
            x8 = read_u32_le(&nonce[8..12]);
            x9 = read_u32_le(&nonce[12..16]);
        } else {
            x8 = 0;
            x9 = 0;
        }

        SalsaState {
            a: u32x4(
                read_u32_le(&key[12..16]),      // x4
                x9,                             // x9
                read_u32_le(&key_tail[12..16]), // x14
                read_u32_le(&key[8..12]),       // x3
            ),
            b: u32x4(
                x8,                             // x8
                read_u32_le(&key_tail[8..12]),  // x13
                read_u32_le(&key[4..8]),        // x2
                read_u32_le(&nonce[4..8])       // x7
            ),
            c: u32x4(
                read_u32_le(&key_tail[4..8]),   // x12
                read_u32_le(&key[0..4]),        // x1
                read_u32_le(&nonce[0..4]),      // x6
                read_u32_le(&key_tail[0..4])    // x11
            ),
            d: u32x4(
                read_u32_le(&constant[0..4]),   // x0
                read_u32_le(&constant[4..8]),   // x5
                read_u32_le(&constant[8..12]),  // x10
                read_u32_le(&constant[12..16]), // x15
            )
        }
    }

    fn hash(&mut self) {
        let mut state = self.state;
        for _ in 0..10 {
            columnround(&mut state);
            prepare_rowround!(state.a, state.b, state.c);
            rowround(&mut state);
            prepare_columnround!(state.a, state.b, state.c);
        }
        let u32x4(x4, x9, x14, x3) = self.state.a + state.a;
        let u32x4(x8, x13, x2, x7) = self.state.b + state.b;
        let u32x4(x12, x1, x6, x11) = self.state.c + state.c;
        let u32x4(x0, x5, x10, x15) = self.state.d + state.d;
        let lens = [
             x0,  x1,  x2,  x3,
             x4,  x5,  x6,  x7,
             x8,  x9, x10, x11,
            x12, x13, x14, x15
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut self.output[i*4..(i+1)*4], lens[i]);
        }

        self.state.b = self.state.b + u32x4(1, 0, 0, 0);
        let u32x4(_, _, _, ctr_lo) = self.state.b;
        if ctr_lo == 0 {
            self.state.a = self.state.a + u32x4(0, 1, 0, 0);
        }

        self.offset = 0;
    }

    fn hsalsa20_hash(&mut self, out: &mut [u8]) {
        let mut state = self.state;
        for _ in 0..10 {
            columnround(&mut state);
            prepare_rowround!(state.a, state.b, state.c);
            rowround(&mut state);
            prepare_columnround!(state.a, state.b, state.c);
        }
        let u32x4(_, x9, _, _) = state.a;
        let u32x4(x8, _, _, x7) = state.b;
        let u32x4(_, _, x6, _) = state.c;
        let u32x4(x0, x5, x10, x15) = state.d;
        let lens = [
            x0, x5, x10, x15,
            x6, x7, x8, x9
        ];
        for i in 0..lens.len() {
            write_u32_le(&mut out[i*4..(i+1)*4], lens[i]);
        }
    }
}

impl SynchronousStreamCipher for Salsa20 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0;
        while i < len {
            // If there is no keystream available in the output buffer,
            // generate the next block.
            if self.offset == 64 {
                self.hash();
            }

            // Process the min(available keystream, remaining input length).
            let count = cmp::min(64 - self.offset, len - i);
            xor_keystream(&mut output[i..i+count], &input[i..i+count], &self.output[self.offset..]);
            i += count;
            self.offset += count;
        }
    }
}

impl Encryptor for Salsa20 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Salsa20 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

pub fn hsalsa20(key: &[u8], nonce: &[u8], out: &mut [u8]) {
    assert!(key.len() == 32);
    assert!(nonce.len() == 16);
    let mut h = Salsa20 { state: Salsa20::expand(key, nonce), output: [0; 64], offset: 64 };
    h.hsalsa20_hash(out);
}


#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
