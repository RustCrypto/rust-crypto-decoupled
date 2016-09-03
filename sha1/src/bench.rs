use test::Bencher;
use crypto_digest::Digest;
use super::{STATE_LEN, BLOCK_LEN};
use super::{Sha1, sha1_digest_block_u32};

#[bench]
pub fn sha1_block(bh: &mut Bencher) {
    let mut state = [0u32; STATE_LEN];
    let words = [1u32; BLOCK_LEN];
    bh.iter(|| {
        sha1_digest_block_u32(&mut state, &words);
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn sha1_10(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_1k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_64k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
