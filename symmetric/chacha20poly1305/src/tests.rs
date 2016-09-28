use super::ChaCha20Poly1305;
use crypto_aead::{AeadEncryptor, AeadDecryptor};

struct TestVector {
    pub name: &'static str,
    pub key: &'static [u8],
    pub nonce: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
    pub aad: &'static [u8],
    pub tag: &'static [u8],
}

macro_rules! get_vectors {
    ( $( $name:expr ),*  ) => {
        [$(
            TestVector {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                nonce: include_bytes!(concat!("data/", $name, ".nonce.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
                aad: include_bytes!(concat!("data/", $name, ".aad.bin")),
                tag: include_bytes!(concat!("data/", $name, ".tag.bin")),
            },
        )*]
    };
}

const MAX_MSG_LEN: usize = 295;
const MAX_TAG_LEN: usize = 139;

const TEST_VECTORS: [TestVector; 75] = get_vectors!("1", "2", "3", "4", "5", "6",
    "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32",
    "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45",
    "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58",
    "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71",
    "72", "73", "74", "75");

#[test]
fn chacha20poly1305_boringssl_vectors_encrypt() {
    for tv in TEST_VECTORS.iter() {
        let msg_len = tv.input.len();
        let tag_len = tv.tag.len();
        let ext_tag_len = if tag_len < 16 {16} else {tv.tag.len()};
        let mut c = ChaCha20Poly1305::new(tv.key, tv.nonce, tv.aad);
        let mut output = [0u8; MAX_MSG_LEN];
        let mut tag = [0u8; MAX_TAG_LEN];
        c.encrypt(tv.input, &mut output[..msg_len], &mut tag[..ext_tag_len]);
        assert_eq!(&output[..msg_len], tv.output);
        assert_eq!(&tag[..tag_len], tv.tag);
    }
}
#[test]
fn test_chacha20_256_poly1305_boringssl_vectors_decrypt() {
    for tv in TEST_VECTORS.iter() {
        let msg_len = tv.input.len();
        let mut c = ChaCha20Poly1305::new(tv.key, tv.nonce, tv.aad);
        let mut output = [0u8; MAX_MSG_LEN];
        let result = c.decrypt(tv.output, &mut output[..msg_len], tv.tag);
        assert!(result);
        assert_eq!(&output[..msg_len], tv.input);
    }
}
