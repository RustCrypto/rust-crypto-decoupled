use test::Bencher;
use crypto_mac::Mac;
use super::Poly1305;

#[bench]
pub fn poly1305_10(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 32];
    let bytes   = [1u8; 10];
    bh.iter( || {
        let mut poly = Poly1305::new(&key);
        poly.input(&bytes);
        poly.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn poly1305_1k(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 32];
    let bytes   = [1u8; 1024];
    bh.iter( || {
        let mut poly = Poly1305::new(&key);
        poly.input(&bytes);
        poly.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn poly1305_64k(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 32];
    let bytes   = [1u8; 65536];
    bh.iter( || {
        let mut poly = Poly1305::new(&key);
        poly.input(&bytes);
        poly.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}