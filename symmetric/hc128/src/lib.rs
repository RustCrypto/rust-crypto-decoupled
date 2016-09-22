#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_buffers;
extern crate crypto_symmetric;

use crypto_buffers::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto_symmetric::{Encryptor, Decryptor, SynchronousStreamCipher,
                       SymmetricCipherError, symm_enc_or_dec};
use crypto_bytes::{read_u32_le, write_u32_le};

use core::ptr;

#[derive(Copy)]
pub struct Hc128 {
    p: [u32; 512],
    q: [u32; 512],
    cnt: usize,
    output: [u8; 4],
    output_index: usize
}

impl Clone for Hc128 { fn clone(&self) -> Hc128 { *self } }

impl Hc128 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Hc128 {
        assert!(key.len() == 16);
        assert!(nonce.len() == 16);
        let mut hc128 = Hc128 { p: [0; 512], q: [0; 512], cnt: 0, output: [0; 4], output_index: 0 };
        hc128.init(&key, &nonce);

        hc128
    }

    fn init(&mut self, key : &[u8], nonce : &[u8]) {
        self.cnt = 0;

        let mut w : [u32; 1280] = [0; 1280];

        for i in 0..16 {
            w[i >> 2] |= (key[i] as u32) << (8 * (i & 0x3));
        }
        unsafe {
            ptr::copy_nonoverlapping(w.as_ptr(), w.as_mut_ptr().offset(4), 4);
        }

        for i in 0..nonce.len() & 16 {
            w[(i >> 2) + 8] |= (nonce[i] as u32) << (8 * (i & 0x3));
        }
        unsafe {
            ptr::copy_nonoverlapping(w.as_ptr().offset(8), w.as_mut_ptr().offset(12), 4);
        }

        for i in 16..1280 {
            w[i] = f2(w[i - 2]).wrapping_add(w[i - 7]).wrapping_add(f1(w[i - 15])).wrapping_add(w[i - 16]).wrapping_add(i as u32);
        }

        // Copy contents of w into p and q
        unsafe {
            ptr::copy_nonoverlapping(w.as_ptr().offset(256), self.p.as_mut_ptr(),  512);
            ptr::copy_nonoverlapping(w.as_ptr().offset(768), self.q.as_mut_ptr(), 512);
        }

        for i in 0..512 {
            self.p[i] = self.step();
        }
        for i in 0..512 {
            self.q[i] = self.step();
        }

        self.cnt = 0;
    }

    fn step(&mut self) -> u32 {
        let j : usize = self.cnt & 0x1FF;

        // Precompute resources
        let dim_j3 : usize = (j.wrapping_sub(3)) & 0x1FF;
        let dim_j10 : usize = (j.wrapping_sub(10)) & 0x1FF;
        let dim_j511 : usize = (j.wrapping_sub(511)) & 0x1FF;
        let dim_j12 : usize = (j.wrapping_sub(12)) & 0x1FF;

        let ret : u32;

        if self.cnt < 512 {
            self.p[j] = self.p[j].wrapping_add(self.p[dim_j3].rotate_right(10) ^ self.p[dim_j511].rotate_right(23)).wrapping_add(self.p[dim_j10].rotate_right(8));
            ret = (self.q[(self.p[dim_j12] & 0xFF) as usize].wrapping_add(self.q[(((self.p[dim_j12] >> 16) & 0xFF) + 256) as usize])) ^ self.p[j];
        } else {
            self.q[j] = self.q[j].wrapping_add(self.q[dim_j3].rotate_left(10) ^ self.q[dim_j511].rotate_left(23)).wrapping_add(self.q[dim_j10].rotate_left(8));
            ret = (self.p[(self.q[dim_j12] & 0xFF) as usize].wrapping_add(self.p[(((self.q[dim_j12] >> 16) & 0xFF) + 256) as usize])) ^ self.q[j];
        }

        self.cnt = (self.cnt + 1) & 0x3FF;
        ret
    }

    fn next(&mut self) -> u8 {
        if self.output_index == 0 {
            let step = self.step();
            write_u32_le(&mut self.output, step);
        }
        let ret = self.output[self.output_index];
        self.output_index = (self.output_index + 1) & 0x3;

        ret
    }
}

fn f1(x: u32) -> u32 {
    let ret : u32 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
    ret
}

fn f2(x: u32) -> u32 {
    let ret : u32 = x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
    ret
}

impl SynchronousStreamCipher for Hc128 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());

        if input.len() <= 4 {
            // Process data bytewise
            for (inb, outb) in input.iter().zip(output.iter_mut()) {
                *outb = *inb ^ self.next();
            }
        } else {
            let mut data_index = 0;
            let data_index_end = data_index + input.len();

            // Process any unused keystream (self.buffer)
            // remaining from previous operations
            while self.output_index > 0 && data_index < data_index_end {
                output[data_index] = input[data_index] ^ self.next();
                data_index += 1;
            }

            // Process input data blockwise until depleted,
            // or remaining length less than block size
            // (size of the keystream buffer, self.buffer : 4 bytes)
            while data_index + 4 <= data_index_end {
                let data_index_inc = data_index + 4;

                // Read input as le-u32
                let input_u32 = read_u32_le(&input[data_index..data_index_inc]);
                // XOR with keystream u32
                let xored = input_u32 ^ self.step();
                // Write output as le-u32
                write_u32_le(&mut output[data_index..data_index_inc], xored);

                data_index = data_index_inc;
            }

            // Process remaining data, if any
            // (e.g. input length not divisible by 4)
            while data_index < data_index_end {
                output[data_index] = input[data_index] ^ self.next();
                data_index += 1;
            }
        }
    }
}

impl Encryptor for Hc128 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Hc128 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
