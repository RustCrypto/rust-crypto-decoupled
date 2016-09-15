use test::Bencher;
use crypto_digest::Digest;
use consts::{STATE_LEN, BLOCK_LEN};
use super::{Sha256, Sha512, sha256_digest_block_u32, sha512_digest_block_u64};

#[bench]
pub fn sha256_block(bh: &mut Bencher) {
    let mut state = [0u32; STATE_LEN];
    let words = [1u32; BLOCK_LEN];
    bh.iter(|| {
        sha256_digest_block_u32(&mut state, &words);
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn sha512_block(bh: &mut Bencher) {
    let mut state = [0u64; STATE_LEN];
    let words = [1u64; BLOCK_LEN];
    bh.iter(|| {
        sha512_digest_block_u64(&mut state, &words);
    });
    bh.bytes = 128u64;
}

#[bench]
pub fn sha256_10(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_1k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_64k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_10(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_1k(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_64k(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
