use super::Hc128;
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

#[test]
fn hc128() {
    // Vectors from http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/hc-256/hc-128/verified.test-vectors?rev=210&view=markup
    let tests = get_tests!("ecrypt_set_2_vector_0", "ecrypt_set_6_vector_1",
                           "ecrypt_set_6_vector_2", "ecrypt_set_6_vector_3");
    let mut buf = [0u8; 64];
    for test in tests.iter() {
        let mut state = Hc128::new(test.key, test.nonce);
        state.process(test.input, &mut buf[..]);
        assert_eq!(test.output, &buf[..]);
    }
}
