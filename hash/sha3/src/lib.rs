//! An implementation of the SHA-3 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//! * `SHA3-224`
//! * `SHA3-256`
//! * `SHA3-384`
//! * `SHA3-512`
//! * `SHAKE128`, an extendable output function (XOF)
//! * `SHAKE256`, an extendable output function (XOF)
//! * `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission
//!    without padding changes)
//!
//! Based on an [implementation by Sébastien Martini](https://github.com/seb-m/crypto.rs/blob/master/src/sha3.rs)
//!
//! # Usage
//!
//! An example of using `SHA3-256` is:
//!
//! ```rust,ignore
//! use self::crypto::digest::Digest;
//! use self::crypto::sha3::Sha3;
//!
//! // create a SHA3-256 object
//! let mut hasher = Sha3::sha3_256();
//!
//! // write input message
//! hasher.input_str("abc");
//!
//! // read hash digest
//! let hex = hasher.result_str();
//!
//! let out = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
//! assert_eq!(hex, out);
//! ```

#![no_std]
#![feature(test)]
#![feature(stmt_expr_attributes)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_digest;
#[cfg(test)]
#[macro_use]
extern crate crypto_tests;

use core::cmp;
use crypto_digest::Digest;
use crypto_bytes::zero;

mod keccak;

/// SHA-3 Modes.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum Sha3Mode {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
}

impl Sha3Mode {
    /// Return the expected hash size in bytes specified for `mode`, or 0
    /// for modes with variable output as for shake functions.
    pub fn digest_length(&self) -> usize {
        match *self {
            Sha3Mode::Sha3_224 |
            Sha3Mode::Keccak224 => 28,
            Sha3Mode::Sha3_256 |
            Sha3Mode::Keccak256 => 32,
            Sha3Mode::Sha3_384 |
            Sha3Mode::Keccak384 => 48,
            Sha3Mode::Sha3_512 |
            Sha3Mode::Keccak512 => 64,
            Sha3Mode::Shake128 |
            Sha3Mode::Shake256 => 0,
        }
    }

    /// Return `true` if `mode` is a SHAKE mode.
    pub fn is_shake(&self) -> bool {
        match *self {
            Sha3Mode::Shake128 |
            Sha3Mode::Shake256 => true,
            _ => false,
        }
    }

    /// Return `true` if `mode` is a Keccak mode.
    pub fn is_keccak(&self) -> bool {
        match *self {
            Sha3Mode::Keccak224 |
            Sha3Mode::Keccak256 |
            Sha3Mode::Keccak384 |
            Sha3Mode::Keccak512 => true,
            _ => false,
        }
    }

    /// Return the capacity in bytes.
    fn capacity(&self) -> usize {
        match *self {
            Sha3Mode::Shake128 => 32,
            Sha3Mode::Sha3_224 |
            Sha3Mode::Keccak224 => 56,
            Sha3Mode::Sha3_256 |
            Sha3Mode::Keccak256 |
            Sha3Mode::Shake256 => 64,
            Sha3Mode::Sha3_384 |
            Sha3Mode::Keccak384 => 96,
            Sha3Mode::Sha3_512 |
            Sha3Mode::Keccak512 => 128,
        }
    }
}

pub struct Sha3 {
    state: [u8; keccak::B], // B bytes
    mode: Sha3Mode,
    can_absorb: bool, // Can absorb
    can_squeeze: bool, // Can squeeze
    offset: usize, /* Enqueued bytes in state for absorb phase
                    * Squeeze offset for squeeze phase */
}

impl Sha3 {
    /// New SHA-3 instanciated from specified SHA-3 `mode`.
    pub fn new(mode: Sha3Mode) -> Sha3 {
        Sha3 {
            state: [0; keccak::B],
            mode: mode,
            can_absorb: true,
            can_squeeze: true,
            offset: 0,
        }
    }

    /// New SHA3-224 instance.
    pub fn sha3_224() -> Sha3 { Sha3::new(Sha3Mode::Sha3_224) }

    /// New SHA3-256 instance.
    pub fn sha3_256() -> Sha3 { Sha3::new(Sha3Mode::Sha3_256) }

    /// New SHA3-384 instance.
    pub fn sha3_384() -> Sha3 { Sha3::new(Sha3Mode::Sha3_384) }

    /// New SHA3-512 instance.
    pub fn sha3_512() -> Sha3 { Sha3::new(Sha3Mode::Sha3_512) }

    /// New SHAKE-128 instance.
    pub fn shake_128() -> Sha3 { Sha3::new(Sha3Mode::Shake128) }

    /// New SHAKE-256 instance.
    pub fn shake_256() -> Sha3 { Sha3::new(Sha3Mode::Shake256) }

    /// New Keccak224 instance.
    pub fn keccak224() -> Sha3 { Sha3::new(Sha3Mode::Keccak224) }

    /// New Keccak256 instance.
    pub fn keccak256() -> Sha3 { Sha3::new(Sha3Mode::Keccak256) }

    /// New Keccak384 instance.
    pub fn keccak384() -> Sha3 { Sha3::new(Sha3Mode::Keccak384) }

    /// New Keccak512 instance.
    pub fn keccak512() -> Sha3 { Sha3::new(Sha3Mode::Keccak512) }

    fn finalize(&mut self) {
        assert!(self.can_absorb);

        let output_bits = self.output_bits();

        let ds_len = if self.mode.is_keccak() {
            0
        } else if output_bits != 0 {
            2
        } else {
            4
        };

        fn set_domain_sep(out_len: usize, buf: &mut [u8]) {
            assert!(buf.len() > 0);
            if out_len != 0 {
                // 01...
                buf[0] &= 0xfe;
                buf[0] |= 0x2;
            } else {
                // 1111...
                buf[0] |= 0xf;
            }
        }

        // All parameters are expected to be in bits.
        fn pad_len(ds_len: usize, offset: usize, rate: usize) -> usize {
            assert!(rate % 8 == 0 && offset % 8 == 0);
            let r: i64 = rate as i64;
            let m: i64 = (offset + ds_len) as i64;
            let zeros = (((-m - 2) + 2 * r) % r) as usize;
            assert!((m as usize + zeros + 2) % 8 == 0);
            (ds_len as usize + zeros + 2) / 8
        }

        fn set_pad(offset: usize, buf: &mut [u8]) {
            assert!(buf.len() as f32 >= ((offset + 2) as f32 / 8.0).ceil());
            let s = offset / 8;
            let buflen = buf.len();
            buf[s] |= 1 << (offset % 8);
            for i in (offset % 8) + 1..8 {
                buf[s] &= !(1 << i);
            }
            for v in buf.iter_mut().skip(s + 1) {
                *v = 0;
            }
            buf[buflen - 1] |= 0x80;
        }

        let p_len = pad_len(ds_len, self.offset * 8, self.rate() * 8);

        // FIXME: check correctness
        const BUF_LEN: usize = 1 << 8;
        assert!(p_len < BUF_LEN);
        let mut buf = [0; BUF_LEN];
        let mut p = &mut buf[..p_len];

        if ds_len != 0 {
            set_domain_sep(self.output_bits(), &mut p);
        }

        set_pad(ds_len, &mut p);

        self.input(&p);
        self.can_absorb = false;
    }

    fn rate(&self) -> usize { keccak::B - self.mode.capacity() }
}

impl Digest for Sha3 {
    fn input(&mut self, data: &[u8]) {
        if !self.can_absorb {
            panic!("Invalid state, absorb phase already finalized.");
        }

        let r = self.rate();
        assert!(self.offset < r);

        let in_len = data.len();
        let mut in_pos: usize = 0;

        // Absorb
        while in_pos < in_len {
            let offset = self.offset;
            let nread = cmp::min(r - offset, in_len - in_pos);
            for i in 0..nread {
                self.state[offset + i] ^= data[in_pos + i];
            }
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            self.offset = 0;
            keccak::f(&mut self.state);
        }
    }

    fn result(&mut self, out: &mut [u8]) {
        if !self.can_squeeze {
            panic!("Nothing left to squeeze.");
        }

        if self.can_absorb {
            self.finalize();
        }

        let r = self.rate();
        let out_len = self.mode.digest_length();
        if out_len != 0 {
            assert!(self.offset < out_len);
        } else {
            assert!(self.offset < r);
        }

        let in_len = out.len();
        let mut in_pos: usize = 0;

        // Squeeze
        while in_pos < in_len {
            let offset = self.offset % r;
            let mut nread = cmp::min(r - offset, in_len - in_pos);
            if out_len != 0 {
                nread = cmp::min(nread, out_len - self.offset);
            }

            for i in 0..nread {
                out[in_pos + i] = self.state[offset + i];
            }
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            if out_len == 0 {
                self.offset = 0;
            } else {
                self.offset += nread;
            }

            keccak::f(&mut self.state);
        }

        if out_len != 0 && out_len == self.offset {
            self.can_squeeze = false;
        }
    }

    fn reset(&mut self) {
        self.can_absorb = true;
        self.can_squeeze = true;
        self.offset = 0;

        zero(&mut self.state);
    }

    fn output_bytes(&self) -> usize { self.mode.digest_length() }

    fn block_size(&self) -> usize { keccak::B - self.mode.capacity() }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
