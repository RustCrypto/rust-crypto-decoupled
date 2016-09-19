use test::Bencher;
use crypto_symmetric::SynchronousStreamCipher;
use super::Sosemanuk;

#[bench]
pub fn sosemanuk_10(bh: & mut Bencher) {
    let mut sosemanuk = Sosemanuk::new(&[0; 32], &[0; 16]);
    let input = [1u8; 10];
    let mut output = [0u8; 10];
    bh.iter( || {
        sosemanuk.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn sosemanuk_1k(bh: & mut Bencher) {
    let mut sosemanuk = Sosemanuk::new(&[0; 32], &[0; 16]);
    let input = [1u8; 1024];
    let mut output = [0u8; 1024];
    bh.iter( || {
        sosemanuk.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn sosemanuk_64k(bh: & mut Bencher) {
    let mut sosemanuk = Sosemanuk::new(&[0; 32], &[0; 16]);
    let input = [1u8; 65536];
    let mut output = [0u8; 65536];
    bh.iter( || {
        sosemanuk.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}