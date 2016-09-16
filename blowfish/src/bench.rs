use test::Bencher;
use super::Blowfish;
use crypto_symmetric::BlockEncryptor;

#[bench]
fn blowfish(bh: &mut Bencher) {
    let key = [0u8; 16];
    let plaintext = [1u8; 8];
    let state = Blowfish::new(&key);
    let mut ciphertext = [0u8; 8];

    bh.iter(|| {
        state.encrypt_block(&plaintext, &mut ciphertext);
    });
    bh.bytes = 8u64;
}