#![cfg(feature = "use-std")]
use crypto_digest::Digest;
use crypto_tests;
use super::Sha1;

#[derive(Clone)]
struct Test {
    input: &'static str,
    output: [u8; 20],
    output_str: &'static str,
}

#[test]
fn test_fips_180_1() {
    // Test messages from FIPS 180-1
    let tests = [Test {
                     input: "abc",
                     output: [0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
                              0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
                              0x9C, 0xD0, 0xD8, 0x9D],
                     output_str: "a9993e364706816aba3e25717850c26c9cd0d89d",
                 },
                 Test {
                     input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                     output: [0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
                              0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
                              0xE5, 0x46, 0x70, 0xF1],
                     output_str: "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                 },
                 // Examples from wikipedia
                 Test {
                     input: "The quick brown fox jumps over the lazy dog",
                     output: [0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc,
                              0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39,
                              0x1b, 0x93, 0xeb, 0x12],
                     output_str: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                 },
                 Test {
                     input: "The quick brown fox jumps over the lazy cog",
                     output: [0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a,
                              0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b,
                              0x10, 0x0d, 0xb4, 0xb3],
                     output_str: "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
                 }];

    // Test that it works when accepting the message all at once

    let mut out = [0u8; 20];

    let mut sh = Sha1::new();
    for t in tests.iter() {
        sh.input_str(t.input);
        sh.result(&mut out);
        assert!(t.output[..] == out[..]);

        let out_str = sh.result_str();
        assert_eq!(out_str.len(), 40);
        assert!(&out_str[..] == t.output_str);

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
        sh.result(&mut out);
        assert!(t.output[..] == out[..]);

        let out_str = sh.result_str();
        assert_eq!(out_str.len(), 40);
        assert!(&out_str[..] == t.output_str);

        sh.reset();
    }
}

#[test]
fn test_1million_random_sha1() {
    let mut sh = Sha1::new();
    let output = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
    crypto_tests::digest::one_million_random(&mut sh, 64, output);
}
