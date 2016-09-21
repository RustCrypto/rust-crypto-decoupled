use test::Bencher;
use crypto_symmetric::SynchronousStreamCipher;
use super::Rc4;

#[bench]
pub fn rc4_10(bh: & mut Bencher) {
    let mut rc4 = Rc4::new("key".as_bytes());
    let input = [1u8; 10];
    let mut output = [0u8; 10];
    bh.iter( || {
        rc4.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn rc4_1k(bh: & mut Bencher) {
    let mut rc4 = Rc4::new("key".as_bytes());
    let input = [1u8; 1024];
    let mut output = [0u8; 1024];
    bh.iter( || {
        rc4.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn rc4_64k(bh: & mut Bencher) {
    let mut rc4 = Rc4::new("key".as_bytes());
    let input = [1u8; 65536];
    let mut output = [0u8; 65536];
    bh.iter( || {
        rc4.process(&input, &mut output);
    });
    bh.bytes = input.len() as u64;
}