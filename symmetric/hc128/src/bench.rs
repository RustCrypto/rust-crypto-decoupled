use test::Bencher;
use super::Hc128;
use crypto_symmetric::SynchronousStreamCipher;

#[bench]
pub fn hc128_10(bh: & mut Bencher) {
    let mut hc128 = Hc128::new(&[0; 16], &[0; 16]);
    let input = [1u8; 10];
    let mut output = [0u8; 10];
    bh.iter( || {
        hc128.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn hc128_1k(bh: & mut Bencher) {
    let mut hc128 = Hc128::new(&[0; 16], &[0; 16]);
    let input = [1u8; 1024];
    let mut output = [0u8; 1024];
    bh.iter( || {
        hc128.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn hc128_64k(bh: & mut Bencher) {
    let mut hc128 = Hc128::new(&[0; 16], &[0; 16]);
    let input = [1u8; 65536];
    let mut output = [0u8; 65536];
    bh.iter( || {
        hc128.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}