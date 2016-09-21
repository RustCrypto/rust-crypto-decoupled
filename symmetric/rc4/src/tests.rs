use super::Rc4;
use crypto_symmetric::SynchronousStreamCipher;

struct Test {
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

macro_rules! get_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

#[test]
fn rc4() {
    // Wikipedia tests
    let tests = get_tests!("1", "2", "3");
    let mut buf = [0u8; 16];
    for test in tests.iter() {
        let mut state = Rc4::new(test.key);
        state.process(test.input, &mut buf[..test.output.len()]);
        assert_eq!(test.output, &buf[..test.output.len()]);
    }
}