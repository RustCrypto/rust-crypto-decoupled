use test::Bencher;
use super::ChaCha20Poly1305;
use crypto_aead::{AeadEncryptor, AeadDecryptor};

#[bench]
pub fn chacha20poly1305_10(bh: & mut Bencher) {
  let input = [1u8; 10];
  let aad = [3u8; 10];
  bh.iter( || {
      let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
      let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

      let mut output = [0u8; 10];
      let mut tag = [0u8; 16];
      let mut output2 = [0u8; 10];
      cipher.encrypt(&input, &mut output, &mut tag);
      decipher.decrypt(&output, &mut output2, &tag);

    });
    bh.bytes = 10u64;
}

#[bench]
pub fn chacha20poly1305_1k(bh: & mut Bencher) {
  let input = [1u8; 1024];
  let aad = [3u8; 1024];
  bh.iter( || {
    let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
    let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

    let mut output = [0u8; 1024];
    let mut tag = [0u8; 16];
    let mut output2 = [0u8; 1024];

    cipher.encrypt(&input, &mut output, &mut tag);
    decipher.decrypt(&output, &mut output2, &tag);
    });
  bh.bytes = 1024u64;

}

#[bench]
pub fn chacha20poly1305_64k(bh: & mut Bencher) {
  let input = [1u8; 65536];
  let aad = [3u8; 65536];
    bh.iter( || {
      let mut cipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);
      let mut decipher = ChaCha20Poly1305::new(&[0; 32], &[0; 8], &aad);

      let mut output = [0u8; 65536];
      let mut tag = [0u8; 16];
      let mut output2 = [0u8; 65536];

      cipher.encrypt(&input, &mut output, &mut tag);
      decipher.decrypt(&output, &mut output2, &tag);

    });
     bh.bytes = 65536u64;
}