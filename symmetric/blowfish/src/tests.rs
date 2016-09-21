use super::Blowfish;
use crypto_symmetric::{BlockEncryptor, BlockDecryptor};

struct SymmetricTest {
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

macro_rules! symmetric_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            SymmetricTest {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

const EAY_TESTS: [SymmetricTest; 34] = symmetric_tests!(
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
    "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26",
    "27", "28", "29", "30", "31", "32", "33", "34");

#[test]
fn blowfish_encrypt() {
    let mut buf = [0u8; 8];
    for test in EAY_TESTS.iter() {
        let state = Blowfish::new(test.key);
        state.encrypt_block(test.input, &mut buf[..]);
        assert_eq!(test.output, &buf[..]);
    }
}

#[test]
fn blowfish_decrypt() {
    let mut buf = [0u8; 8];
    for test in EAY_TESTS.iter() {
        let state = Blowfish::new(test.key);
        state.decrypt_block(test.output, &mut buf[..]);
        assert_eq!(test.input, &buf[..]);
    }
}
