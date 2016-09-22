use test::Bencher;
use super::ChaCha20;
use crypto_symmetric::SynchronousStreamCipher;

#[bench]
pub fn chacha20_10(bh: & mut Bencher) {
    let mut chacha20 = ChaCha20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 10];
    let mut output = [0u8; 10];
    bh.iter( || {
        chacha20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn chacha20_1k(bh: & mut Bencher) {
    let mut chacha20 = ChaCha20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 1024];
    let mut output = [0u8; 1024];
    bh.iter( || {
        chacha20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn chacha20_64k(bh: & mut Bencher) {
    let mut chacha20 = ChaCha20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 65536];
    let mut output = [0u8; 65536];
    bh.iter( || {
        chacha20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}