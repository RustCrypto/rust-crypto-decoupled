#![no_std]
#![feature(step_by)]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_digest;
extern crate crypto_fixed_buffer;
#[cfg(test)]
#[macro_use]
extern crate crypto_tests;

use crypto_bytes::{write_u32_le, read_u32v_le};
use crypto_digest::Digest;
use crypto_fixed_buffer::{FixedBuffer, FixedBuffer64, StandardPadding};

mod consts;
use consts::{C1, C2, C3, C4};

/// A structure that represents that state of a digest computation for the MD5
/// digest function
#[derive(Clone, Copy)]
struct Md5State {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
}


impl Md5State {
    fn new() -> Md5State {
        Md5State {
            s0: consts::S0,
            s1: consts::S1,
            s2: consts::S2,
            s3: consts::S3,
        }
    }

    fn reset(&mut self) {
        self.s0 = consts::S0;
        self.s1 = consts::S1;
        self.s2 = consts::S2;
        self.s3 = consts::S3;
    }

    fn process_block(&mut self, input: &[u8]) {
        fn f(u: u32, v: u32, w: u32) -> u32 { (u & v) | (!u & w) }

        fn g(u: u32, v: u32, w: u32) -> u32 { (u & w) | (v & !w) }

        fn h(u: u32, v: u32, w: u32) -> u32 { u ^ v ^ w }

        fn i(u: u32, v: u32, w: u32) -> u32 { v ^ (u | !w) }

        fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(f(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(g(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(h(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(i(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        let mut a = self.s0;
        let mut b = self.s1;
        let mut c = self.s2;
        let mut d = self.s3;

        let mut data = [0u32; 16];

        read_u32v_le(&mut data, input);

        // round 1
        for i in (0..16).step_by(4) {
            a = op_f(a, b, c, d, data[i].wrapping_add(C1[i]), 7);
            d = op_f(d, a, b, c, data[i + 1].wrapping_add(C1[i + 1]), 12);
            c = op_f(c, d, a, b, data[i + 2].wrapping_add(C1[i + 2]), 17);
            b = op_f(b, c, d, a, data[i + 3].wrapping_add(C1[i + 3]), 22);
        }

        // round 2
        let mut t = 1;
        for i in (0..16).step_by(4) {
            let q = data[t & 0x0f].wrapping_add(C2[i]);
            a = op_g(a, b, c, d, q, 5);
            let q = data[(t + 5) & 0x0f].wrapping_add(C2[i + 1]);
            d = op_g(d, a, b, c, q, 9);
            let q = data[(t + 10) & 0x0f].wrapping_add(C2[i + 2]);
            c = op_g(c, d, a, b, q, 14);
            let q = data[(t + 15) & 0x0f].wrapping_add(C2[i + 3]);
            b = op_g(b, c, d, a, q, 20);
            t += 20;
        }

        // round 3
        t = 5;
        for i in (0..16).step_by(4) {
            let q = data[t & 0x0f].wrapping_add(C3[i]);
            a = op_h(a, b, c, d, q, 4);
            let q = data[(t + 3) & 0x0f].wrapping_add(C3[i + 1]);
            d = op_h(d, a, b, c, q, 11);
            let q = data[(t + 6) & 0x0f].wrapping_add(C3[i + 2]);
            c = op_h(c, d, a, b, q, 16);
            let q = data[(t + 9) & 0x0f].wrapping_add(C3[i + 3]);
            b = op_h(b, c, d, a, q, 23);
            t += 12;
        }

        // round 4
        t = 0;
        for i in (0..16).step_by(4) {
            let q = data[t & 0x0f].wrapping_add(C4[i]);
            a = op_i(a, b, c, d, q, 6);
            let q = data[(t + 7) & 0x0f].wrapping_add(C4[i + 1]);
            d = op_i(d, a, b, c, q, 10);
            let q = data[(t + 14) & 0x0f].wrapping_add(C4[i + 2]);
            c = op_i(c, d, a, b, q, 15);
            let q = data[(t + 21) & 0x0f].wrapping_add(C4[i + 3]);
            b = op_i(b, c, d, a, q, 21);
            t += 28;
        }

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

/// The MD5 Digest algorithm
#[derive(Clone, Copy)]
pub struct Md5 {
    length_bytes: u64,
    buffer: FixedBuffer64,
    state: Md5State,
    finished: bool,
}

impl Md5 {
    /// Construct a new instance of the MD5 Digest.
    pub fn new() -> Md5 {
        Md5 {
            length_bytes: 0,
            buffer: FixedBuffer64::new(),
            state: Md5State::new(),
            finished: false,
        }
    }
}

impl Default for Md5 {
    fn default() -> Self { Self::new() }
}

impl Digest for Md5 {
    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| {
            self_state.process_block(d);
        });
    }

    fn reset(&mut self) {
        self.length_bytes = 0;
        self.buffer.reset();
        self.state.reset();
        self.finished = false;
    }

    fn result(&mut self, out: &mut [u8]) {
        if !self.finished {
            let self_state = &mut self.state;
            self.buffer.standard_padding(8, |d: &[u8]| {
                self_state.process_block(d);
            });
            write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
            write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
            self_state.process_block(self.buffer.full_buffer());
            self.finished = true;
        }

        write_u32_le(&mut out[0..4], self.state.s0);
        write_u32_le(&mut out[4..8], self.state.s1);
        write_u32_le(&mut out[8..12], self.state.s2);
        write_u32_le(&mut out[12..16], self.state.s3);
    }

    fn output_bytes(&self) -> usize { 16 }

    fn block_size(&self) -> usize { 64 }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
