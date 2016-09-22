use crypto_digest::Digest;

// Max hash size is equal to 512 bits, but to test sha3 extendable output function
// we need 512 bytes
pub const MAX_DIGEST_SIZE: usize = 512;

pub struct Test {
    pub name: &'static str,
    pub input: &'static [u8],
    pub output: &'static [u8],
}

#[macro_export]
macro_rules! new_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test {
                name: $name,
                input: include_bytes!(concat!("data/", $name, ".input")),
                output: include_bytes!(concat!("data/", $name, ".output")),
            },
        )*]
    };
}

pub fn main_test<D: Digest>(sh: &mut D, tests: &[Test]) {
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        sh.input(t.input);

        assert!(MAX_DIGEST_SIZE >= sh.output_bytes());
        let mut buf = [0u8; MAX_DIGEST_SIZE];
        let len = if sh.output_bytes() != 0 { sh.output_bytes() } else { t.output.len() };
        let mut buf = &mut buf[..len];
        sh.result(&mut buf);

        assert_eq!(buf[..], t.output[..]);
        sh.reset();
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.input(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let mut buf = [0u8; MAX_DIGEST_SIZE];
        let len = if sh.output_bytes() != 0 { sh.output_bytes() } else { t.output.len() };
        let mut buf = &mut buf[..len];
        sh.result(&mut buf);

        assert_eq!(buf[..], t.output[..]);

        sh.reset();
    }
}

pub fn one_million_a<D: Digest>(sh: &mut D, expected: &[u8]) {
    for _ in 0..50000 {
        sh.input(&[b'a'; 10]);
    }
    sh.input(&[b'a'; 500000]);

    let mut buf = [0u8; MAX_DIGEST_SIZE];
    let mut buf = &mut buf[..sh.output_bytes()];
    sh.result(&mut buf);

    assert_eq!(buf[..], expected[..]);
}
