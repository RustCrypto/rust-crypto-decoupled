use super::Blowfish;
use crypto_symmetric::BlockCipher;
use generic_array::GenericArray;

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

use generic_array::{ArrayLength};

#[inline]
fn from_slice<T, N: ArrayLength<T>>(slice: &[T]) -> &GenericArray<T, N> {
    assert_eq!(slice.len(), N::to_usize());
    unsafe {
        &*(slice.as_ptr() as *const GenericArray<T, N>)
    }
}

#[test]
fn blowfish_encrypt() {
    let mut output = GenericArray::new();
    for test in EAY_TESTS.iter() {
        let state = Blowfish::new(test.key);
        let input = from_slice(test.input);
        state.encrypt_block(input, &mut output);
        assert_eq!(test.output, &output[..]);
    }
}

#[test]
fn blowfish_decrypt() {
    let mut input = GenericArray::new();
    for test in EAY_TESTS.iter() {
        let state = Blowfish::new(test.key);
        let output = from_slice(test.output);
        state.decrypt_block(output, &mut input);
        assert_eq!(test.input, &input[..]);
    }
}
