use super::ChaCha20;
use crypto_symmetric::SynchronousStreamCipher;

struct Test {
    pub name: &'static str,
    pub key: &'static [u8],
    pub nonce: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

macro_rules! get_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                nonce: include_bytes!(concat!("data/", $name, ".nonce.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

const MAX_LEN : usize = 256;

#[test]
fn chacha20() {
    // http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
    let tests = get_tests!("1", "2", "3", "4", "5", "6", "7", "8", "9", "10");
    let mut buf = [0u8; MAX_LEN];
    for test in tests.iter() {
        let n = test.input.len();
        let mut state = ChaCha20::new(test.key, test.nonce);
        state.process(test.input, &mut buf[..n]);
        assert_eq!(test.output, &buf[..n]);
    }
}

#[test]
fn xchacha20() {
    // There aren't any convenient test vectors for XChaCha/20,
    // so, a simple test case was generated using Andrew Moon's
    // chacha-opt library, with the key/nonce from test_salsa20_cryptopp().
    let tests = get_tests!("x1");
    let mut buf = [0u8; MAX_LEN];
    for test in tests.iter() {
        let n = test.input.len();
        let mut state = ChaCha20::new_xchacha20(test.key, test.nonce);
        state.process(test.input, &mut buf[..n]);
        assert_eq!(test.output, &buf[..n]);
    }
}

