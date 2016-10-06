use crypto_digest::Digest;

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

pub fn main_test<D: Digest>(tests: &[Test]) {
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        let mut sh = D::new();
        sh.input(t.input);

        let out = sh.result();

        assert_eq!(out[..], t.output[..]);
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let mut sh = D::new();
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.input(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let out = sh.result();

        assert_eq!(out[..], t.output[..]);
    }
}

pub fn one_million_a<D: Digest>(expected: &[u8]) {
    let mut sh = D::new();
    for _ in 0..50000 {
        sh.input(&[b'a'; 10]);
    }
    sh.input(&[b'a'; 500000]);
    let out = sh.result();
    assert_eq!(out[..], expected[..]);
}
