use test::Bencher;
use crypto_mac::Mac;
use super::Ghash;

#[bench]
pub fn ghash_10(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 16];
    let bytes   = [1u8; 10];
    bh.iter( || {
        let mut ghash = Ghash::new(&key);
        ghash.input(&bytes);
        ghash.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn ghash_1k(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 16];
    let bytes   = [1u8; 1024];
    bh.iter( || {
        let mut ghash = Ghash::new(&key);
        ghash.input(&bytes);
        ghash.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn ghash_64k(bh: & mut Bencher) {
    let mut mac = [0u8; 16];
    let key     = [0u8; 16];
    let bytes   = [1u8; 65536];
    bh.iter( || {
        let mut ghash = Ghash::new(&key);
        ghash.input(&bytes);
        ghash.raw_result(&mut mac);
    });
    bh.bytes = bytes.len() as u64;
}
