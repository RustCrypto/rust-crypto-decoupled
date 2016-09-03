#[cfg(feature = "use-std")]
use std::iter::repeat;
use super::Digest;
use rand::IsaacRng;
use rand::distributions::{IndependentSample, Range};

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
}
