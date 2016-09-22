use super::Salsa20;
use crypto_symmetric::SynchronousStreamCipher;
use sha2::Sha256;
use crypto_digest::Digest;

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
fn salsa20() {
    let tests = get_tests!("salsa20_128bit_ecrypt_set_1_vector_0",
                           "salsa20_256bit_ecrypt_set_1_vector_0");
    let mut buf = [0u8; 64];
    for test in tests.iter() {
        let mut state = Salsa20::new(test.key, test.nonce);
        state.process(test.input, &mut buf[..]);
        assert_eq!(test.output, &buf[..]);
    }
}

#[test]
fn xsalsa20() {
    let tests = get_tests!("xsalsa20_cryptopp");
    let mut buf = [0u8; 139];
    for test in tests.iter() {
        let mut state = Salsa20::new_xsalsa20(test.key, test.nonce);
        state.process(test.input, &mut buf[..]);
        assert_eq!(test.output, &buf[..]);
    }
}

#[test]
fn salsa20_256bit_nacl_vector_2() {
    let key = include_bytes!("data/salsa20_256bit_nacl_vector_2.key.bin");
    let nonce = include_bytes!("data/salsa20_256bit_nacl_vector_2.nonce.bin");
    let hash = include_bytes!("data/salsa20_256bit_nacl_vector_2.hash.bin");

    let mut salsa20 = Salsa20::new(&key[..], &nonce[..]);
    let mut sh = Sha256::new();

    let mut buf = [0u8; 256];
    for _ in 0..4194304/256 {
        let input = [0u8; 256];
        salsa20.process(&input[..], &mut buf[..]);
        sh.input(&buf[..]);
    }

    let mut buf = [0u8; 32];
    sh.result(&mut buf[..]);

    assert_eq!(hash, &buf[..]);
}
