#![cfg(feature="use-std")]
use crypto_digest::{Digest, test_digest};
use super::Md5;

struct Test {
    input: &'static str,
    output_str: &'static str,
}

fn test_hash<D: Digest>(sh: &mut D, tests: &[Test]) {
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        sh.input_str(t.input);

        let out_str = sh.result_str();
        assert_eq!(out_str, t.output_str);

        sh.reset();
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.input_str(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let out_str = sh.result_str();
        assert_eq!(out_str, t.output_str);

        sh.reset();
    }
}

#[test]
fn test_md5() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "d41d8cd98f00b204e9800998ecf8427e",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "9e107d9d372bb6826bd81d3542a419d6",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "e4d909c290d0fb1ca068ffaddf22cbd0",
         }];

    let mut sh = Md5::new();

    test_hash(&mut sh, &wikipedia_tests[..]);
}

#[test]
fn test_1million_random_md5() {
    let mut sh = Md5::new();
    test_digest::one_million_random(&mut sh,
                                64,
                                "7707d6ae4e027c70eea2a935c2296f21");
}
