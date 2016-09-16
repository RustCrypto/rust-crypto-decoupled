use test::Bencher;
use crypto_digest::Digest;
use super::{Blake2b, Blake2s};


#[bench]
pub fn blake2b_10(bh: & mut Bencher) {
    let mut sh = Blake2b::new(64);
    let bytes = [1u8; 10];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2b_1k(bh: & mut Bencher) {
    let mut sh = Blake2b::new(64);
    let bytes = [1u8; 1024];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2b_64k(bh: & mut Bencher) {
    let mut sh = Blake2b::new(64);
    let bytes = [1u8; 65536];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}


#[bench]
pub fn blake2s_10(bh: & mut Bencher) {
    let mut sh = Blake2s::new(32);
    let bytes = [1u8; 10];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2s_1k(bh: & mut Bencher) {
    let mut sh = Blake2s::new(32);
    let bytes = [1u8; 1024];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2s_64k(bh: & mut Bencher) {
    let mut sh = Blake2s::new(32);
    let bytes = [1u8; 65536];
    bh.iter( || {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}