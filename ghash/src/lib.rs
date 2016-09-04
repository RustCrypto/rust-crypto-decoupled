//! This is an implementaiton of GHASH as used in GCM [1].
//! It is defined as GHASH(H, A, C), where H is a MAC key, A is authenticated
//! data, and C is the ciphertext. GHASH can be used as a keyed MAC, if C is
//! left empty.
//!
//! In order to ensure constant time computation it uses the approach described
//! in [2] section 5.2.
//!
//! [1] - "The Galois/Counter Mode of Operation (GCM)" - David A. McGrew and John Viega
//!       <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
//! [2] - "Faster and Timing-Attack Resistant AES-GCM" - Emilia Käsper and Peter Schwabe
//!       <http://cryptojedi.org/papers/aesbs-20090616.pdf>

#![cfg_attr(not(feature="use-std"), no_std)]
#![cfg_attr(test, feature(test))]
#[cfg(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_mac;
extern crate simd;

#[cfg(feature="use-std")]
use std::ops::BitXor;
#[cfg(feature="use-std")]
use std::mem;

#[cfg(not(feature="use-std"))]
use core::ops::BitXor;
#[cfg(not(feature="use-std"))]
use core::mem;

use crypto_bytes::{read_u32_be, write_u32_be, copy_memory};
use crypto_mac::{Mac, MacResult128};

/// A struct representing an element in GF(2^128)
/// x^0 is the msb, while x^127 is the lsb
#[derive(Clone, Copy)]
struct Gf128 { d: simd::u32x4 }

impl Gf128 {
    fn new(a: u32, b: u32, c: u32, d: u32) -> Gf128 {
        Gf128 { d: simd::u32x4(a, b, c, d) }
    }

    fn from_bytes(bytes: &[u8]) -> Gf128 {
        assert!(bytes.len() == 16);
        let d = read_u32_be(&bytes[0..4]);
        let c = read_u32_be(&bytes[4..8]);
        let b = read_u32_be(&bytes[8..12]);
        let a = read_u32_be(&bytes[12..16]);
        Gf128::new(a, b, c, d)
    }

    fn to_bytes(&self) -> [u8; 16] {
        let simd::u32x4(a, b, c, d) = self.d;
        let mut result: [u8; 16] = unsafe { mem::uninitialized() };

        write_u32_be(&mut result[0..4], d);
        write_u32_be(&mut result[4..8], c);
        write_u32_be(&mut result[8..12], b);
        write_u32_be(&mut result[12..16], a);

        result
    }

    /// Multiply the element by x modulo x^128
    /// This is equivalent to a rightshift in the bit representation
    fn times_x(self) -> Gf128 {
        let simd::u32x4(a, b, c, d) = self.d;
        Gf128::new(a >> 1 | b << 31, b >> 1 | c << 31, c >> 1 |  d << 31, d >> 1)
    }

    /// Multiply the element by x modulo x^128 + x^7 + x^2 + x + 1
    /// This is equivalent to a rightshift, followed by an XOR iff the lsb was
    /// set, in the bit representation
    fn times_x_reduce(self) -> Gf128 {
        let r = Gf128::new(0, 0, 0, 0b1110_0001 << 24);
        self.cond_xor(r, self.times_x())
    }

    /// Adds y, and multiplies with h using a precomputed array of the values
    /// h * x^0 to h * x^127
    fn add_and_mul(&mut self, y: Gf128, hs: &[Gf128; 128]) {
        *self = *self ^ y;
        let mut x = mem::replace(self, Gf128::new(0, 0, 0, 0));

        for &y in hs.iter().rev() {
            *self = x.cond_xor(y, *self);
            x = x.times_x();
        }
    }

    /// This XORs the value of y with x if the LSB of self is set, otherwise
    /// y is returned
    fn cond_xor(self, x: Gf128, y: Gf128) -> Gf128 {
        let lsb = simd::u32x4(1, 0, 0, 0);
        let m = if (self.d & lsb) == lsb {0xffffffff} else {0};
        let mask = simd::u32x4(m, m, m, m);
        Gf128 { d: (x.d & mask) ^ y.d }
    }
}

impl BitXor for Gf128 {
    type Output = Gf128;

    fn bitxor(self, rhs: Gf128) -> Gf128 {
        Gf128 { d: self.d ^ rhs.d }
    }
}

/// A structure representing the state of a GHASH computation
#[derive(Copy)]
pub struct Ghash {
    hs: [Gf128; 128],
    state: Gf128,
    a_len: usize,
    rest: Option<[u8; 16]>,
    finished: bool
}

impl Clone for Ghash { fn clone(&self) -> Ghash { *self } }

/// A structure representing the state of a GHASH computation, after input for
/// C was provided
#[derive(Copy)]
pub struct GhashWithC {
    hs: [Gf128; 128],
    state: Gf128,
    a_len: usize,
    c_len: usize,
    rest: Option<[u8; 16]>
}

impl Clone for GhashWithC { fn clone(&self) -> GhashWithC { *self } }

fn update(state: &mut Gf128, len: &mut usize, data: &[u8], srest: &mut Option<[u8; 16]>,
          hs: &[Gf128; 128]) {
    let rest_len = *len % 16;
    let data_len = data.len();
    *len += data_len;

    let data = match srest.take() {
        None => data,
        Some(mut rest) => {
            if 16 - rest_len > data_len {
                copy_memory(data, &mut rest[rest_len..]);
                *srest = Some(rest);
                return;
            }

            let (fill, data) = data.split_at(16 - rest_len);
            copy_memory(fill, &mut rest[rest_len..]);
            state.add_and_mul(Gf128::from_bytes(&rest), hs);
            data
        }
    };

    let (data, rest) = data.split_at(data_len - data_len % 16);

    for chunk in data.chunks(16) {
        let x = Gf128::from_bytes(chunk);
        state.add_and_mul(x, hs);
    }

    if rest.len() != 0 {
        let mut tmp = [0; 16];
        copy_memory(rest, &mut tmp);
        *srest = Some(tmp);
    }
}

impl Ghash {
    /// Creates a new GHASH state, with `h` as the key
    #[inline]
    pub fn new(h: &[u8]) -> Ghash {
        assert!(h.len() == 16);
        let mut table: [Gf128; 128] = unsafe { mem::uninitialized() };

        // Precompute values for h * x^0 to h * x^127
        let mut h = Gf128::from_bytes(h);
        for poly in table.iter_mut() {
            *poly = h;
            h = h.times_x_reduce();
        }

        Ghash {
            hs: table,
            state: Gf128::new(0, 0, 0, 0),
            a_len: 0,
            rest: None,
            finished: false
        }
    }

    fn flush(&mut self) {
        for rest in self.rest.take().iter() {
            self.state.add_and_mul(Gf128::from_bytes(rest), &self.hs);
        }
    }

    /// Feeds data for GHASH's A input
    #[inline]
    pub fn input_a(mut self, a: &[u8]) -> Ghash {
        assert!(!self.finished);
        update(&mut self.state, &mut self.a_len, a, &mut self.rest, &self.hs);
        self
    }

    /// Feeds data for GHASH's C input
    #[inline]
    pub fn input_c(mut self, c: &[u8]) -> GhashWithC {
        assert!(!self.finished);
        self.flush();

        let mut c_len = 0;
        update(&mut self.state, &mut c_len, c, &mut self.rest, &self.hs);

        let Ghash { hs, state, a_len, rest, .. } = self;
        GhashWithC {
            hs: hs,
            state: state,
            a_len: a_len,
            c_len: c_len,
            rest: rest
        }
    }

    /// Retrieve the digest result
    #[inline]
    pub fn result(mut self) -> [u8; 16] {
        if !self.finished {
            self.flush();

            let a_len = self.a_len as u64 * 8;
            let lens = Gf128::new(0, 0, a_len as u32, (a_len >> 32) as u32);
            self.state.add_and_mul(lens, &self.hs);

            self.finished = true;
        }

        self.state.to_bytes()
    }
}

impl GhashWithC {
    /// Feeds data for GHASH's C input
    #[inline]
    pub fn input_c(mut self, c: &[u8]) -> GhashWithC {
        update(&mut self.state, &mut self.c_len, c, &mut self.rest, &self.hs);
        self
    }

    /// Retrieve the digest result
    #[inline]
    pub fn result(mut self) -> [u8; 16] {
        for rest in self.rest.take().iter() {
            self.state.add_and_mul(Gf128::from_bytes(rest), &self.hs);
        }

        let a_len = self.a_len as u64 * 8;
        let c_len = self.c_len as u64 * 8;
        let lens = Gf128::new(c_len as u32, (c_len >> 32) as u32,
                              a_len as u32, (a_len >> 32) as u32);
        self.state.add_and_mul(lens, &self.hs);

        self.state.to_bytes()
    }
}

impl Mac<MacResult128> for Ghash {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        update(&mut self.state, &mut self.a_len, data, &mut self.rest, &self.hs);
    }

    fn reset(&mut self) {
        self.state = Gf128::new(0, 0, 0, 0);
        self.a_len = 0;
        self.rest = None;
        self.finished = false;
    }

    fn result(&mut self) -> MacResult128 {
        let mut mac = [0u8; 16];
        self.raw_result(&mut mac[..]);
        MacResult128::new(mac)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        assert!(output.len() >= 16);
        if !self.finished {
            self.flush();

            let a_len = self.a_len as u64 * 8;
            let lens = Gf128::new(0, 0, a_len as u32, (a_len >> 32) as u32);
            self.state.add_and_mul(lens, &self.hs);

            self.finished = true;
        }

        copy_memory(&self.state.to_bytes(), output);
    }

    fn output_bytes(&self) -> usize { 16 }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
