//! An implementation of the SHA-2 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-2 standard:
//!
//! `Sha224`, which is the 32-bit `Sha256` algorithm with the result truncated
//! to 224 bits.
//! `Sha256`, which is the 32-bit `Sha256` algorithm.
//! `Sha384`, which is the 64-bit `Sha512` algorithm with the result truncated
//! to 384 bits.
//! `Sha512`, which is the 64-bit `Sha512` algorithm.
//! `Sha512Trunc224`, which is the 64-bit `Sha512` algorithm with the result
//! truncated to 224 bits.
//! `Sha512Trunc256`, which is the 64-bit `Sha512` algorithm with the result
//! truncated to 256 bits.
//!
//! Algorithmically, there are only 2 core algorithms: `Sha256` and `Sha512`.
//! All other algorithms are just applications of these with different initial
//! hash values, and truncated to different digest bit lengths.
//!
//! # Usage
//!
//! An example of using `Sha256` is:
//!
//! ```rust,ignore
//! extern crate digest;
//!
//! use digest::Digest;
//! use self::sha2::Sha256;
//!
//! create a Sha256 object
//! let mut hasher = Sha256::new();
//!
//! write input message
//! hasher.input_str("hello world");
//!
//! read hash digest
//! let hex = hasher.result_str();
//!
//! assert_eq!(hex,
//! concat!("b94d27b9934d3e08a52e52d7da7dabfa",
//! "c484efe37a5380ee9088f7ace2efcde9"));
//! ```
//!
//! An example of using `Sha512` is:
//!
//! ```rust,ignore
//! extern crate digest;
//!
//! use digest::Digest;
//! use self::sha2::Sha512;
//!
//! create a Sha512 object
//! let mut hasher = Sha512::new();
//!
//! write input message
//! hasher.input_str("hello world");
//!
//! read hash digest
//! let hex = hasher.result_str();
//!
//! assert_eq!(hex,
//! concat!("309ecc489c12d6eb4cc40f50c902f2b4",
//! "d0ed77ee511a7c7a9bcd3ca86d4cd86f",
//! "989dd35bc5ff499670da34255b45b0cf",
//! "d830e81f605dcf7dc5542e93ae9cd76f"));
//! ```


#![cfg_attr(not(feature="use-std"), no_std)]
#![feature(test)]

extern crate test;
extern crate crypto_bytes;
extern crate crypto_digest;
extern crate crypto_fixed_buffer;
extern crate simd;
#[cfg(test)]
extern crate crypto_tests;

use crypto_digest::Digest;
use crypto_bytes::{write_u32_be, read_u32v_be, write_u64_be, read_u64v_be,
                  add_bytes_to_bits, add_bytes_to_bits_tuple};
use crypto_fixed_buffer::{FixedBuffer, FixedBuffer128, FixedBuffer64,
                                 StandardPadding};

use simd::u32x4;
use simd::sixty_four::u64x2;

const STATE_LEN: usize = 8;
const BLOCK_LEN: usize = 16;

/// Not an intrinsic, but works like an unaligned load.
#[inline]
fn sha256load(v2: u32x4, v3: u32x4) -> u32x4 {
    u32x4(v3.extract(3), v2.extract(0), v2.extract(1), v2.extract(2))
}

/// Not an intrinsic, but useful for swapping vectors.
#[inline]
fn sha256swap(v0: u32x4) -> u32x4 {
    u32x4(v0.extract(2), v0.extract(3), v0.extract(0), v0.extract(1))
}

/// Emulates `llvm.x86.sha256msg1` intrinsic.
// #[inline]
fn sha256msg1(v0: u32x4, v1: u32x4) -> u32x4 {

    // sigma 0 on vectors
    #[inline]
    fn sigma0x4(x: u32x4) -> u32x4 {
        ((x >> u32x4::new(7, 7, 7, 7)) | (x << u32x4::new(25, 25, 25, 25))) ^
        ((x >> u32x4::new(18, 18, 18, 18)) |
         (x << u32x4::new(14, 14, 14, 14))) ^
        (x >> u32x4::new(3, 3, 3, 3))
    }

    v0 + sigma0x4(sha256load(v0, v1))
}

/// Emulates `llvm.x86.sha256msg2` intrinsic.
// #[inline]
fn sha256msg2(v4: u32x4, v3: u32x4) -> u32x4 {

    macro_rules! sigma1 {
        ($a:expr) => (($a.rotate_right(17) ^ $a.rotate_right(19) ^ ($a >> 10)))
    }

    let u32x4(x3, x2, x1, x0) = v4;
    let u32x4(w15, w14, _, _) = v3;

    let w16 = x0.wrapping_add(sigma1!(w14));
    let w17 = x1.wrapping_add(sigma1!(w15));
    let w18 = x2.wrapping_add(sigma1!(w16));
    let w19 = x3.wrapping_add(sigma1!(w17));

    u32x4(w19, w18, w17, w16)
}

/// Performs 4 rounds of the SHA-256 message schedule update.
pub fn sha256_schedule_x4(v0: u32x4, v1: u32x4, v2: u32x4, v3: u32x4) -> u32x4 {
    sha256msg2(sha256msg1(v0, v1) + sha256load(v2, v3), v3)
}

/// Emulates `llvm.x86.sha256rnds2` intrinsic.
// #[inline]
pub fn sha256_digest_round_x2(cdgh: u32x4, abef: u32x4, wk: u32x4) -> u32x4 {

    macro_rules! big_sigma0 {
        ($a:expr) => (($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22)))
    }
    macro_rules! big_sigma1 {
        ($a:expr) => (($a.rotate_right(6) ^ $a.rotate_right(11) ^ $a.rotate_right(25)))
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => (($c ^ ($a & ($b ^ $c))))
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => (($a & $b) ^ ($a & $c) ^ ($b & $c))
    } // Majority, SHA1M

    let u32x4(_, _, wk1, wk0) = wk;
    let u32x4(a0, b0, e0, f0) = abef;
    let u32x4(c0, d0, g0, h0) = cdgh;

    // a round
    let x0 = big_sigma1!(e0)
        .wrapping_add(bool3ary_202!(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_sigma0!(a0).wrapping_add(bool3ary_232!(a0, b0, c0));
    let (a1, b1, c1, d1, e1, f1, g1, h1) =
        (x0.wrapping_add(y0), a0, b0, c0, x0.wrapping_add(d0), e0, f0, g0);

    // a round
    let x1 = big_sigma1!(e1)
        .wrapping_add(bool3ary_202!(e1, f1, g1))
        .wrapping_add(wk1)
        .wrapping_add(h1);
    let y1 = big_sigma0!(a1).wrapping_add(bool3ary_232!(a1, b1, c1));
    let (a2, b2, _, _, e2, f2, _, _) =
        (x1.wrapping_add(y1), a1, b1, c1, x1.wrapping_add(d1), e1, f1, g1);

    u32x4(a2, b2, e2, f2)
}

/// Process a block with the SHA-256 algorithm.
pub fn sha256_digest_block_u32(state: &mut [u32; 8], block: &[u32; 16]) {
    let k = &K32X4;

    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => (
            sha256msg2(sha256msg1($v0, $v1) + sha256load($v2, $v3), $v3)
        )
    }

    macro_rules! rounds4 {
        ($abef:ident, $cdgh:ident, $rest:expr) => {
            {
                $cdgh = sha256_digest_round_x2($cdgh, $abef, $rest);
                $abef = sha256_digest_round_x2($abef, $cdgh, sha256swap($rest));
            }
        }
    }

    let mut abef = u32x4(state[0], state[1], state[4], state[5]);
    let mut cdgh = u32x4(state[2], state[3], state[6], state[7]);

    // Rounds 0..64
    let mut w0 = u32x4(block[3], block[2], block[1], block[0]);
    rounds4!(abef, cdgh, k[0] + w0);
    let mut w1 = u32x4(block[7], block[6], block[5], block[4]);
    rounds4!(abef, cdgh, k[1] + w1);
    let mut w2 = u32x4(block[11], block[10], block[9], block[8]);
    rounds4!(abef, cdgh, k[2] + w2);
    let mut w3 = u32x4(block[15], block[14], block[13], block[12]);
    rounds4!(abef, cdgh, k[3] + w3);
    let mut w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[4] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[5] + w0);
    w1 = schedule!(w2, w3, w4, w0);
    rounds4!(abef, cdgh, k[6] + w1);
    w2 = schedule!(w3, w4, w0, w1);
    rounds4!(abef, cdgh, k[7] + w2);
    w3 = schedule!(w4, w0, w1, w2);
    rounds4!(abef, cdgh, k[8] + w3);
    w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[9] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[10] + w0);
    w1 = schedule!(w2, w3, w4, w0);
    rounds4!(abef, cdgh, k[11] + w1);
    w2 = schedule!(w3, w4, w0, w1);
    rounds4!(abef, cdgh, k[12] + w2);
    w3 = schedule!(w4, w0, w1, w2);
    rounds4!(abef, cdgh, k[13] + w3);
    w4 = schedule!(w0, w1, w2, w3);
    rounds4!(abef, cdgh, k[14] + w4);
    w0 = schedule!(w1, w2, w3, w4);
    rounds4!(abef, cdgh, k[15] + w0);

    let u32x4(a, b, e, f) = abef;
    let u32x4(c, d, g, h) = cdgh;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Process a block with the SHA-256 algorithm. (See more...)
///
/// Internally, this uses functions which resemble the new Intel SHA instruction
/// sets, and so it's data locality properties may improve performance. However,
/// to benefit the most from this implementation, replace these functions with
/// x86 intrinsics to get a possible speed boost.
///
/// # Implementation
///
/// The `Sha256` algorithm is implemented with functions that resemble the new
/// Intel SHA instruction set extensions. These intructions fall into two
/// categories: message schedule calculation, and the message block 64-round
/// digest calculation. The schedule-related instructions allow 4 rounds to be
/// calculated as:
///
/// ```ignore
/// use std::simd::u32x4;
/// use self::crypto::sha2::{
///     sha256msg1,
///     sha256msg2,
///     sha256load
/// };
///
/// fn schedule4_data(work: &mut [u32x4], w: &[u32]) {
///
///     // this is to illustrate the data order
///     work[0] = u32x4(w[3], w[2], w[1], w[0]);
///     work[1] = u32x4(w[7], w[6], w[5], w[4]);
///     work[2] = u32x4(w[11], w[10], w[9], w[8]);
///     work[3] = u32x4(w[15], w[14], w[13], w[12]);
/// }
///
/// fn schedule4_work(work: &mut [u32x4], t: usize) {
///
///     // this is the core expression
///     work[t] = sha256msg2(sha256msg1(work[t - 4], work[t - 3]) +
///                          sha256load(work[t - 2], work[t - 1]),
///                          work[t - 1])
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn schedule_work(w: &mut [u32], t: usize) {
///     w[t] = sigma1!(w[t - 2]) + w[t - 7] + sigma0!(w[t - 15]) + w[t - 16];
/// }
/// ```
///
/// and the digest-related instructions allow 4 rounds to be calculated as:
///
/// ```ignore
/// use std::simd::u32x4;
/// use self::crypto::sha2::{K32X4,
///     sha256rnds2,
///     sha256swap
/// };
///
/// fn rounds4(state: &mut [u32; 8], work: &mut [u32x4], t: usize) {
///     let [a, b, c, d, e, f, g, h]: [u32; 8] = *state;
///
///     // this is to illustrate the data order
///     let mut abef = u32x4(a, b, e, f);
///     let mut cdgh = u32x4(c, d, g, h);
///     let temp = K32X4[t] + work[t];
///
///     // this is the core expression
///     cdgh = sha256rnds2(cdgh, abef, temp);
///     abef = sha256rnds2(abef, cdgh, sha256swap(temp));
///
///     *state = [abef.0, abef.1, cdgh.0, cdgh.1,
///               abef.2, abef.3, cdgh.2, cdgh.3];
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn round(state: &mut [u32; 8], w: &mut [u32], t: usize) {
///     let [a, b, c, mut d, e, f, g, mut h]: [u32; 8] = *state;
///
///     h += big_sigma1!(e) +   choose!(e, f, g) + K32[t] + w[t]; d += h;
///     h += big_sigma0!(a) + majority!(a, b, c);
///
///     *state = [h, a, b, c, d, e, f, g];
/// }
/// ```
///
/// **NOTE**: It is important to note, however, that these instructions are not
/// implemented by any CPU (at the time of this writing), and so they are
/// emulated in this library until the instructions become more common, and gain
///  support in LLVM (and GCC, etc.).
pub fn sha256_digest_block(state: &mut [u32; 8], block: &[u8]) {
    assert_eq!(block.len(), BLOCK_LEN * 4);
    let mut block2 = [0u32; BLOCK_LEN];
    read_u32v_be(&mut block2[..], block);
    sha256_digest_block_u32(state, &block2);
}

/// Not an intrinsic, but works like an unaligned load.
#[inline]
fn sha512load(v0: u64x2, v1: u64x2) -> u64x2 {
    u64x2::new(v1.extract(1), v0.extract(0))
}

/// Performs 2 rounds of the SHA-512 message schedule update.
pub fn sha512_schedule_x2(v0: u64x2, v1: u64x2, v4to5: u64x2, v7: u64x2)
                          -> u64x2 {

    // sigma 0
    fn sigma0(x: u64) -> u64 {
        ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7)
    }

    // sigma 1
    fn sigma1(x: u64) -> u64 {
        ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6)
    }

    let u64x2(w1, w0) = v0;
    let u64x2(_, w2) = v1;
    let u64x2(w10, w9) = v4to5;
    let u64x2(w15, w14) = v7;

    let w16 =
        sigma1(w14).wrapping_add(w9).wrapping_add(sigma0(w1)).wrapping_add(w0);
    let w17 =
        sigma1(w15).wrapping_add(w10).wrapping_add(sigma0(w2)).wrapping_add(w1);

    u64x2(w17, w16)
}

/// Performs one round of the SHA-512 message block digest.
pub fn sha512_digest_round(ae: u64x2, bf: u64x2, cg: u64x2, dh: u64x2,
                           wk0: u64)
                           -> u64x2 {

    macro_rules! big_sigma0 {
        ($a:expr) => (($a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39)))
    }
    macro_rules! big_sigma1 {
        ($a:expr) => (($a.rotate_right(14) ^ $a.rotate_right(18) ^ $a.rotate_right(41)))
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => (($c ^ ($a & ($b ^ $c))))
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => (($a & $b) ^ ($a & $c) ^ ($b & $c))
    } // Majority, SHA1M

    let u64x2(a0, e0) = ae;
    let u64x2(b0, f0) = bf;
    let u64x2(c0, g0) = cg;
    let u64x2(d0, h0) = dh;

    // a round
    let x0 = big_sigma1!(e0)
        .wrapping_add(bool3ary_202!(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_sigma0!(a0).wrapping_add(bool3ary_232!(a0, b0, c0));
    let (a1, _, _, _, e1, _, _, _) =
        (x0.wrapping_add(y0), a0, b0, c0, x0.wrapping_add(d0), e0, f0, g0);

    u64x2(a1, e1)
}

/// Process a block with the SHA-512 algorithm.
pub fn sha512_digest_block_u64(state: &mut [u64; 8], block: &[u64; 16]) {
    let k = &K64X2;

    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v4:expr, $v5:expr, $v7:expr) => (
             sha512_schedule_x2($v0, $v1, sha512load($v4, $v5), $v7)
        )
    }

    macro_rules! rounds4 {
        ($ae:ident, $bf:ident, $cg:ident, $dh:ident, $wk0:expr, $wk1:expr) => {
            {
                let u64x2(u, t) = $wk0;
                let u64x2(w, v) = $wk1;

                $dh = sha512_digest_round($ae, $bf, $cg, $dh, t);
                $cg = sha512_digest_round($dh, $ae, $bf, $cg, u);
                $bf = sha512_digest_round($cg, $dh, $ae, $bf, v);
                $ae = sha512_digest_round($bf, $cg, $dh, $ae, w);
            }
        }
    }

    let mut ae = u64x2(state[0], state[4]);
    let mut bf = u64x2(state[1], state[5]);
    let mut cg = u64x2(state[2], state[6]);
    let mut dh = u64x2(state[3], state[7]);

    // Rounds 0..20
    let (mut w1, mut w0) = (u64x2(block[3], block[2]),
                            u64x2(block[1], block[0]));
    rounds4!(ae, bf, cg, dh, k[0] + w0, k[1] + w1);
    let (mut w3, mut w2) = (u64x2(block[7], block[6]),
                            u64x2(block[5], block[4]));
    rounds4!(ae, bf, cg, dh, k[2] + w2, k[3] + w3);
    let (mut w5, mut w4) = (u64x2(block[11], block[10]),
                            u64x2(block[9], block[8]));
    rounds4!(ae, bf, cg, dh, k[4] + w4, k[5] + w5);
    let (mut w7, mut w6) = (u64x2(block[15], block[14]),
                            u64x2(block[13], block[12]));
    rounds4!(ae, bf, cg, dh, k[6] + w6, k[7] + w7);
    let mut w8 = schedule!(w0, w1, w4, w5, w7);
    let mut w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, k[8] + w8, k[9] + w9);

    // Rounds 20..40
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, k[10] + w0, k[11] + w1);
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, k[12] + w2, k[13] + w3);
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, k[14] + w4, k[15] + w5);
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, k[16] + w6, k[17] + w7);
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, k[18] + w8, k[19] + w9);

    // Rounds 40..60
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, k[20] + w0, k[21] + w1);
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, k[22] + w2, k[23] + w3);
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, k[24] + w4, k[25] + w5);
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, k[26] + w6, k[27] + w7);
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, k[28] + w8, k[29] + w9);

    // Rounds 60..80
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, k[30] + w0, k[31] + w1);
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, k[32] + w2, k[33] + w3);
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, k[34] + w4, k[35] + w5);
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, k[36] + w6, k[37] + w7);
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, k[38] + w8, k[39] + w9);

    let u64x2(a, e) = ae;
    let u64x2(b, f) = bf;
    let u64x2(c, g) = cg;
    let u64x2(d, h) = dh;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Process a block with the SHA-512 algorithm. (See more...)
///
/// Internally, this uses functions that resemble the new Intel SHA
/// instruction set extensions, but since no architecture seems to
/// have any designs, these may not be the final designs if and/or when
/// there are instruction set extensions with SHA-512. So to summarize:
/// SHA-1 and SHA-256 are being implemented in hardware soon (at the time
/// of this writing), but it doesn't look like SHA-512 will be hardware
/// accelerated any time soon.
///
/// # Implementation
///
/// These functions fall into two categories: message schedule calculation, and
/// the message block 64-round digest calculation. The schedule-related
/// functions allow 4 rounds to be calculated as:
///
/// ```ignore
/// use std::simd::u64x2;
/// use self::crypto::sha2::{
///     sha512msg,
///     sha512load
/// };
///
/// fn schedule4_data(work: &mut [u64x2], w: &[u64]) {
///
///     // this is to illustrate the data order
///     work[0] = u64x2(w[1], w[0]);
///     work[1] = u64x2(w[3], w[2]);
///     work[2] = u64x2(w[5], w[4]);
///     work[3] = u64x2(w[7], w[6]);
///     work[4] = u64x2(w[9], w[8]);
///     work[5] = u64x2(w[11], w[10]);
///     work[6] = u64x2(w[13], w[12]);
///     work[7] = u64x2(w[15], w[14]);
/// }
///
/// fn schedule4_work(work: &mut [u64x2], t: usize) {
///
///     // this is the core expression
///     work[t] = sha512msg(work[t - 8],
///                         work[t - 7],
///                         sha512load(work[t - 4], work[t - 3]),
///                         work[t - 1]);
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn schedule_work(w: &mut [u64], t: usize) {
///     w[t] = sigma1!(w[t - 2]) + w[t - 7] + sigma0!(w[t - 15]) + w[t - 16];
/// }
/// ```
///
/// and the digest-related functions allow 4 rounds to be calculated as:
///
/// ```ignore
/// use std::simd::u64x2;
/// use self::crypto::sha2::{K64X2, sha512rnd};
///
/// fn rounds4(state: &mut [u64; 8], work: &mut [u64x2], t: usize) {
///     let [a, b, c, d, e, f, g, h]: [u64; 8] = *state;
///
///     // this is to illustrate the data order
///     let mut ae = u64x2(a, e);
///     let mut bf = u64x2(b, f);
///     let mut cg = u64x2(c, g);
///     let mut dh = u64x2(d, h);
///     let u64x2(w1, w0) = K64X2[2*t]     + work[2*t];
///     let u64x2(w3, w2) = K64X2[2*t + 1] + work[2*t + 1];
///
///     // this is the core expression
///     dh = sha512rnd(ae, bf, cg, dh, w0);
///     cg = sha512rnd(dh, ae, bf, cg, w1);
///     bf = sha512rnd(cg, dh, ae, bf, w2);
///     ae = sha512rnd(bf, cg, dh, ae, w3);
///
///     *state = [ae.0, bf.0, cg.0, dh.0,
///               ae.1, bf.1, cg.1, dh.1];
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn round(state: &mut [u64; 8], w: &mut [u64], t: usize) {
///     let [a, b, c, mut d, e, f, g, mut h]: [u64; 8] = *state;
///
///     h += big_sigma1!(e) +   choose!(e, f, g) + K64[t] + w[t]; d += h;
///     h += big_sigma0!(a) + majority!(a, b, c);
///
///     *state = [h, a, b, c, d, e, f, g];
/// }
/// ```
///
pub fn sha512_digest_block(state: &mut [u64; 8], block: &[u8]) {
    assert_eq!(block.len(), BLOCK_LEN * 8);
    let mut block2 = [0u64; BLOCK_LEN];
    read_u64v_be(&mut block2[..], block);
    sha512_digest_block_u64(state, &block2);
}

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Copy, Clone)]
struct Engine512State {
    h: [u64; 8],
}

impl Engine512State {
    fn new(h: &[u64; 8]) -> Engine512State { Engine512State { h: *h } }

    fn reset(&mut self, h: &[u64; STATE_LEN]) { self.h = *h; }

    pub fn process_block(&mut self, data: &[u8]) {
        sha512_digest_block(&mut self.h, data);
    }
}

/// Constants necessary for SHA-512 family of digests.
pub const K64: [u64; 80] = [0x428a2f98d728ae22,
                            0x7137449123ef65cd,
                            0xb5c0fbcfec4d3b2f,
                            0xe9b5dba58189dbbc,
                            0x3956c25bf348b538,
                            0x59f111f1b605d019,
                            0x923f82a4af194f9b,
                            0xab1c5ed5da6d8118,
                            0xd807aa98a3030242,
                            0x12835b0145706fbe,
                            0x243185be4ee4b28c,
                            0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f,
                            0x80deb1fe3b1696b1,
                            0x9bdc06a725c71235,
                            0xc19bf174cf692694,
                            0xe49b69c19ef14ad2,
                            0xefbe4786384f25e3,
                            0x0fc19dc68b8cd5b5,
                            0x240ca1cc77ac9c65,
                            0x2de92c6f592b0275,
                            0x4a7484aa6ea6e483,
                            0x5cb0a9dcbd41fbd4,
                            0x76f988da831153b5,
                            0x983e5152ee66dfab,
                            0xa831c66d2db43210,
                            0xb00327c898fb213f,
                            0xbf597fc7beef0ee4,
                            0xc6e00bf33da88fc2,
                            0xd5a79147930aa725,
                            0x06ca6351e003826f,
                            0x142929670a0e6e70,
                            0x27b70a8546d22ffc,
                            0x2e1b21385c26c926,
                            0x4d2c6dfc5ac42aed,
                            0x53380d139d95b3df,
                            0x650a73548baf63de,
                            0x766a0abb3c77b2a8,
                            0x81c2c92e47edaee6,
                            0x92722c851482353b,
                            0xa2bfe8a14cf10364,
                            0xa81a664bbc423001,
                            0xc24b8b70d0f89791,
                            0xc76c51a30654be30,
                            0xd192e819d6ef5218,
                            0xd69906245565a910,
                            0xf40e35855771202a,
                            0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8,
                            0x1e376c085141ab53,
                            0x2748774cdf8eeb99,
                            0x34b0bcb5e19b48a8,
                            0x391c0cb3c5c95a63,
                            0x4ed8aa4ae3418acb,
                            0x5b9cca4f7763e373,
                            0x682e6ff3d6b2b8a3,
                            0x748f82ee5defb2fc,
                            0x78a5636f43172f60,
                            0x84c87814a1f0ab72,
                            0x8cc702081a6439ec,
                            0x90befffa23631e28,
                            0xa4506cebde82bde9,
                            0xbef9a3f7b2c67915,
                            0xc67178f2e372532b,
                            0xca273eceea26619c,
                            0xd186b8c721c0c207,
                            0xeada7dd6cde0eb1e,
                            0xf57d4f7fee6ed178,
                            0x06f067aa72176fba,
                            0x0a637dc5a2c898a6,
                            0x113f9804bef90dae,
                            0x1b710b35131c471b,
                            0x28db77f523047d84,
                            0x32caab7b40c72493,
                            0x3c9ebe0a15c9bebc,
                            0x431d67c49c100d4c,
                            0x4cc5d4becb3e42b6,
                            0x597f299cfc657e2a,
                            0x5fcb6fab3ad6faec,
                            0x6c44198c4a475817];

/// Constants necessary for SHA-512 family of digests.
pub const K64X2: [u64x2; 40] = [u64x2(K64[1], K64[0]),
                                u64x2(K64[3], K64[2]),
                                u64x2(K64[5], K64[4]),
                                u64x2(K64[7], K64[6]),
                                u64x2(K64[9], K64[8]),
                                u64x2(K64[11], K64[10]),
                                u64x2(K64[13], K64[12]),
                                u64x2(K64[15], K64[14]),
                                u64x2(K64[17], K64[16]),
                                u64x2(K64[19], K64[18]),
                                u64x2(K64[21], K64[20]),
                                u64x2(K64[23], K64[22]),
                                u64x2(K64[25], K64[24]),
                                u64x2(K64[27], K64[26]),
                                u64x2(K64[29], K64[28]),
                                u64x2(K64[31], K64[30]),
                                u64x2(K64[33], K64[32]),
                                u64x2(K64[35], K64[34]),
                                u64x2(K64[37], K64[36]),
                                u64x2(K64[39], K64[38]),
                                u64x2(K64[41], K64[40]),
                                u64x2(K64[43], K64[42]),
                                u64x2(K64[45], K64[44]),
                                u64x2(K64[47], K64[46]),
                                u64x2(K64[49], K64[48]),
                                u64x2(K64[51], K64[50]),
                                u64x2(K64[53], K64[52]),
                                u64x2(K64[55], K64[54]),
                                u64x2(K64[57], K64[56]),
                                u64x2(K64[59], K64[58]),
                                u64x2(K64[61], K64[60]),
                                u64x2(K64[63], K64[62]),
                                u64x2(K64[65], K64[64]),
                                u64x2(K64[67], K64[66]),
                                u64x2(K64[69], K64[68]),
                                u64x2(K64[71], K64[70]),
                                u64x2(K64[73], K64[72]),
                                u64x2(K64[75], K64[74]),
                                u64x2(K64[77], K64[76]),
                                u64x2(K64[79], K64[78])];

/// A structure that keeps track of the state of the Sha-512 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Copy, Clone)]
struct Engine512 {
    length_bits: (u64, u64),
    buffer: FixedBuffer128,
    state: Engine512State,
    finished: bool,
}

impl Engine512 {
    fn new(h: &[u64; STATE_LEN]) -> Engine512 {
        Engine512 {
            length_bits: (0, 0),
            buffer: FixedBuffer128::new(),
            state: Engine512State::new(h),
            finished: false,
        }
    }

    fn reset(&mut self, h: &[u64; STATE_LEN]) {
        self.length_bits = (0, 0);
        self.buffer.reset();
        self.state.reset(h);
        self.finished = false;
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits_tuple(self.length_bits,
                                                   input.len() as u64);
        let self_state = &mut self.state;
        self.buffer
            .input(input, |input: &[u8]| self_state.process_block(input));
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        let self_state = &mut self.state;
        self.buffer.standard_padding(16, |input: &[u8]| {
            self_state.process_block(input)
        });
        match self.length_bits {
            (hi, low) => {
                write_u64_be(self.buffer.next(8), hi);
                write_u64_be(self.buffer.next(8), low);
            },
        }
        self_state.process_block(self.buffer.full_buffer());

        self.finished = true;
    }
}


/// The SHA-512 hash algorithm with the SHA-512 initial hash value.
#[derive(Copy, Clone)]
pub struct Sha512 {
    engine: Engine512,
}

impl Sha512 {
    /// Construct an new instance of a SHA-512 digest.
    pub fn new() -> Sha512 { Sha512 { engine: Engine512::new(&H512) } }
}

impl Default for Sha512 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha512 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u64_be(&mut out[0..8], self.engine.state.h[0]);
        write_u64_be(&mut out[8..16], self.engine.state.h[1]);
        write_u64_be(&mut out[16..24], self.engine.state.h[2]);
        write_u64_be(&mut out[24..32], self.engine.state.h[3]);
        write_u64_be(&mut out[32..40], self.engine.state.h[4]);
        write_u64_be(&mut out[40..48], self.engine.state.h[5]);
        write_u64_be(&mut out[48..56], self.engine.state.h[6]);
        write_u64_be(&mut out[56..64], self.engine.state.h[7]);
    }

    fn reset(&mut self) { self.engine.reset(&H512); }

    fn output_bits(&self) -> usize { 512 }

    fn block_size(&self) -> usize { 128 }
}

static H512: [u64; STATE_LEN] = [0x6a09e667f3bcc908,
                                 0xbb67ae8584caa73b,
                                 0x3c6ef372fe94f82b,
                                 0xa54ff53a5f1d36f1,
                                 0x510e527fade682d1,
                                 0x9b05688c2b3e6c1f,
                                 0x1f83d9abfb41bd6b,
                                 0x5be0cd19137e2179];


/// The SHA-512 hash algorithm with the SHA-384 initial hash value. The result
/// is truncated to 384 bits.
#[derive(Copy, Clone)]
pub struct Sha384 {
    engine: Engine512,
}

impl Sha384 {
    /// Construct an new instance of a SHA-384 digest.
    pub fn new() -> Sha384 { Sha384 { engine: Engine512::new(&H384) } }
}

impl Default for Sha384 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha384 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u64_be(&mut out[0..8], self.engine.state.h[0]);
        write_u64_be(&mut out[8..16], self.engine.state.h[1]);
        write_u64_be(&mut out[16..24], self.engine.state.h[2]);
        write_u64_be(&mut out[24..32], self.engine.state.h[3]);
        write_u64_be(&mut out[32..40], self.engine.state.h[4]);
        write_u64_be(&mut out[40..48], self.engine.state.h[5]);
    }

    fn reset(&mut self) { self.engine.reset(&H384); }

    fn output_bits(&self) -> usize { 384 }

    fn block_size(&self) -> usize { 128 }
}

static H384: [u64; STATE_LEN] = [0xcbbb9d5dc1059ed8,
                                 0x629a292a367cd507,
                                 0x9159015a3070dd17,
                                 0x152fecd8f70e5939,
                                 0x67332667ffc00b31,
                                 0x8eb44a8768581511,
                                 0xdb0c2e0d64f98fa7,
                                 0x47b5481dbefa4fa4];


/// The SHA-512 hash algorithm with the SHA-512/256 initial hash value. The
/// result is truncated to 256 bits.
#[derive(Clone, Copy)]
pub struct Sha512Trunc256 {
    engine: Engine512,
}

impl Sha512Trunc256 {
    /// Construct an new instance of a SHA-512/256 digest.
    pub fn new() -> Sha512Trunc256 {
        Sha512Trunc256 { engine: Engine512::new(&H512_TRUNC_256) }
    }
}

impl Default for Sha512Trunc256 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha512Trunc256 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u64_be(&mut out[0..8], self.engine.state.h[0]);
        write_u64_be(&mut out[8..16], self.engine.state.h[1]);
        write_u64_be(&mut out[16..24], self.engine.state.h[2]);
        write_u64_be(&mut out[24..32], self.engine.state.h[3]);
    }

    fn reset(&mut self) { self.engine.reset(&H512_TRUNC_256); }

    fn output_bits(&self) -> usize { 256 }

    fn block_size(&self) -> usize { 128 }
}

static H512_TRUNC_256: [u64; STATE_LEN] = [0x22312194fc2bf72c,
                                           0x9f555fa3c84c64c2,
                                           0x2393b86b6f53b151,
                                           0x963877195940eabd,
                                           0x96283ee2a88effe3,
                                           0xbe5e1e2553863992,
                                           0x2b0199fc2c85b8aa,
                                           0x0eb72ddc81c52ca2];


/// The SHA-512 hash algorithm with the SHA-512/224 initial hash value.
/// The result is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha512Trunc224 {
    engine: Engine512,
}

impl Sha512Trunc224 {
    /// Construct an new instance of a SHA-512/224 digest.
    pub fn new() -> Sha512Trunc224 {
        Sha512Trunc224 { engine: Engine512::new(&H512_TRUNC_224) }
    }
}

impl Default for Sha512Trunc224 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha512Trunc224 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u64_be(&mut out[0..8], self.engine.state.h[0]);
        write_u64_be(&mut out[8..16], self.engine.state.h[1]);
        write_u64_be(&mut out[16..24], self.engine.state.h[2]);
        write_u32_be(&mut out[24..28], (self.engine.state.h[3] >> 32) as u32);
    }

    fn reset(&mut self) { self.engine.reset(&H512_TRUNC_224); }

    fn output_bits(&self) -> usize { 224 }

    fn block_size(&self) -> usize { 128 }
}

static H512_TRUNC_224: [u64; STATE_LEN] = [0x8c3d37c819544da2,
                                           0x73e1996689dcd4d6,
                                           0x1dfab7ae32ff9c82,
                                           0x679dd514582f9fcf,
                                           0x0f6d2b697bd44da8,
                                           0x77e36f7304c48942,
                                           0x3f9d85a86a1d36c8,
                                           0x1112e6ad91d692a1];


/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone, Copy)]
struct Engine256State {
    h: [u32; 8],
}

impl Engine256State {
    fn new(h: &[u32; STATE_LEN]) -> Engine256State { Engine256State { h: *h } }

    fn reset(&mut self, h: &[u32; STATE_LEN]) { self.h = *h; }

    pub fn process_block(&mut self, data: &[u8]) {
        sha256_digest_block(&mut self.h, data);
    }
}

/// Constants necessary for SHA-256 family of digests.
pub const K32: [u32; 64] =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

/// Constants necessary for SHA-256 family of digests.
pub const K32X4: [u32x4; 16] = [u32x4(K32[3], K32[2], K32[1], K32[0]),
                                u32x4(K32[7], K32[6], K32[5], K32[4]),
                                u32x4(K32[11], K32[10], K32[9], K32[8]),
                                u32x4(K32[15], K32[14], K32[13], K32[12]),
                                u32x4(K32[19], K32[18], K32[17], K32[16]),
                                u32x4(K32[23], K32[22], K32[21], K32[20]),
                                u32x4(K32[27], K32[26], K32[25], K32[24]),
                                u32x4(K32[31], K32[30], K32[29], K32[28]),
                                u32x4(K32[35], K32[34], K32[33], K32[32]),
                                u32x4(K32[39], K32[38], K32[37], K32[36]),
                                u32x4(K32[43], K32[42], K32[41], K32[40]),
                                u32x4(K32[47], K32[46], K32[45], K32[44]),
                                u32x4(K32[51], K32[50], K32[49], K32[48]),
                                u32x4(K32[55], K32[54], K32[53], K32[52]),
                                u32x4(K32[59], K32[58], K32[57], K32[56]),
                                u32x4(K32[63], K32[62], K32[61], K32[60])];

/// A structure that keeps track of the state of the Sha-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone, Copy)]
struct Engine256 {
    length_bits: u64,
    buffer: FixedBuffer64,
    state: Engine256State,
    finished: bool,
}

impl Engine256 {
    fn new(h: &[u32; STATE_LEN]) -> Engine256 {
        Engine256 {
            length_bits: 0,
            buffer: FixedBuffer64::new(),
            state: Engine256State::new(h),
            finished: false,
        }
    }

    fn reset(&mut self, h: &[u32; STATE_LEN]) {
        self.length_bits = 0;
        self.buffer.reset();
        self.state.reset(h);
        self.finished = false;
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits,
                                             input.len() as u64);
        let self_state = &mut self.state;
        self.buffer
            .input(input, |input: &[u8]| self_state.process_block(input));
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }

        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |input: &[u8]| {
            self_state.process_block(input)
        });
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        self_state.process_block(self.buffer.full_buffer());

        self.finished = true;
    }
}


/// The SHA-256 hash algorithm with the SHA-256 initial hash value.
#[derive(Clone, Copy)]
pub struct Sha256 {
    engine: Engine256,
}

impl Sha256 {
    /// Construct an new instance of a SHA-256 digest.
    pub fn new() -> Sha256 { Sha256 { engine: Engine256::new(&H256) } }
}

impl Default for Sha256 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha256 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();

        write_u32_be(&mut out[0..4], self.engine.state.h[0]);
        write_u32_be(&mut out[4..8], self.engine.state.h[1]);
        write_u32_be(&mut out[8..12], self.engine.state.h[2]);
        write_u32_be(&mut out[12..16], self.engine.state.h[3]);
        write_u32_be(&mut out[16..20], self.engine.state.h[4]);
        write_u32_be(&mut out[20..24], self.engine.state.h[5]);
        write_u32_be(&mut out[24..28], self.engine.state.h[6]);
        write_u32_be(&mut out[28..32], self.engine.state.h[7]);
    }

    fn reset(&mut self) { self.engine.reset(&H256); }

    fn output_bits(&self) -> usize { 256 }

    fn block_size(&self) -> usize { 64 }
}

static H256: [u32; STATE_LEN] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                 0xa54ff53a, 0x510e527f, 0x9b05688c,
                                 0x1f83d9ab, 0x5be0cd19];


/// The SHA-256 hash algorithm with the SHA-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha224 {
    engine: Engine256,
}

impl Sha224 {
    /// Construct an new instance of a SHA-224 digest.
    pub fn new() -> Sha224 { Sha224 { engine: Engine256::new(&H224) } }
}

impl Default for Sha224 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha224 {
    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(&mut self, out: &mut [u8]) {
        self.engine.finish();
        write_u32_be(&mut out[0..4], self.engine.state.h[0]);
        write_u32_be(&mut out[4..8], self.engine.state.h[1]);
        write_u32_be(&mut out[8..12], self.engine.state.h[2]);
        write_u32_be(&mut out[12..16], self.engine.state.h[3]);
        write_u32_be(&mut out[16..20], self.engine.state.h[4]);
        write_u32_be(&mut out[20..24], self.engine.state.h[5]);
        write_u32_be(&mut out[24..28], self.engine.state.h[6]);
    }

    fn reset(&mut self) { self.engine.reset(&H224); }

    fn output_bits(&self) -> usize { 224 }

    fn block_size(&self) -> usize { 64 }
}

static H224: [u32; STATE_LEN] = [0xc1059ed8, 0x367cd507, 0x3070dd17,
                                 0xf70e5939, 0xffc00b31, 0x68581511,
                                 0x64f98fa7, 0xbefa4fa4];

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
