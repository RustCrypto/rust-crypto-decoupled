use crypto_digest::{Digest, MAX_DIGEST_SIZE};

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


/*
/// Feed 1,000,000 'a's into the digest with varying input sizes and check that
/// the result is correct.
pub fn one_million_random<D: Digest>(digest: &mut D,
                                              blocksize: usize,
                                              expected: &str) {
    let total_size = 1000000;
    let buffer: Vec<u8> = repeat(b'a').take(blocksize * 2).collect();
    let mut rng = IsaacRng::new_unseeded();
    let range = Range::new(0, 2 * blocksize + 1);
    let mut count = 0;

    digest.reset();

    while count < total_size {
        let next = range.ind_sample(&mut rng);
        let remaining = total_size - count;
        let size = if next > remaining { remaining } else { next };
        digest.input(&buffer[..size]);
        count += size;
    }

    let result_str = digest.result_str();

    assert!(expected == &result_str[..]);
}*/
