use super::Sosemanuk;
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
fn sosemanuk_encrypt() {
    // Vectors from http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/sosemanuk/unverified.test-vectors?rev=108&view=markup
    // Vector_128 tests are from TEST_VECTOR_128.txt from reference C implementation
    let tests = get_tests!("set_1_vector_0", "set_2_vector_63", "set_2_vector_90",
        "set_3_vector_135", "set_3_vector_207", "set_6_vector_3",
        "vector128_test1", "vector128_test2");
    let mut buf = [0u8; 160];
    for test in tests.iter() {
        let mut state = Sosemanuk::new(test.key, test.nonce);
        state.process(test.input, &mut buf[..test.output.len()]);
        assert_eq!(test.output, &buf[..test.output.len()]);
    }
}