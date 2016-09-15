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


#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_digest;
extern crate crypto_fixed_buffer;
extern crate simd;
#[cfg(test)]
#[macro_use]
extern crate crypto_tests;

use crypto_digest::Digest;
use crypto_bytes::{write_u32_be, read_u32v_be, write_u64_be, read_u64v_be,
                  add_bytes_to_bits, add_bytes_to_bits_tuple};
use crypto_fixed_buffer::{FixedBuffer, FixedBuffer128, FixedBuffer64,
                                 StandardPadding};

use simd::u32x4;
use simd::sixty_four::u64x2;

mod consts;
use consts::{STATE_LEN, BLOCK_LEN, K32X4, K64X2,
    H224, H256, H384, H512, H512_TRUNC_224, H512_TRUNC_256};

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

    fn output_bytes(&self) -> usize { 512/8 }

    fn block_size(&self) -> usize { 128 }
}


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

    fn output_bytes(&self) -> usize { 384/8 }

    fn block_size(&self) -> usize { 128 }
}


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

    fn output_bytes(&self) -> usize { 256/8 }

    fn block_size(&self) -> usize { 128 }
}


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

    fn output_bytes(&self) -> usize { 224/8 }

    fn block_size(&self) -> usize { 128 }
}


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

    fn output_bytes(&self) -> usize { 256/8 }

    fn block_size(&self) -> usize { 64 }
}

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

    fn output_bytes(&self) -> usize { 224/8 }

    fn block_size(&self) -> usize { 64 }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
