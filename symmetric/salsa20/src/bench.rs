use test::Bencher;
use crypto_symmetric::SynchronousStreamCipher;
use super::Salsa20;

#[bench]
pub fn salsa20_10(bh: & mut Bencher) {
    let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 10];
    let mut output = [0u8; 10];
    bh.iter( || {
        salsa20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn salsa20_1k(bh: & mut Bencher) {
    let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 1024];
    let mut output = [0u8; 1024];
    bh.iter( || {
        salsa20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn salsa20_64k(bh: & mut Bencher) {
    let mut salsa20 = Salsa20::new(&[0; 32], &[0; 8]);
    let input = [1u8; 65536];
    let mut output = [0u8; 65536];
    bh.iter( || {
        salsa20.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}