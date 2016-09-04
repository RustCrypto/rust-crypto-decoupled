#![cfg(feature="use-std")]
use crypto_digest::{Digest, test_digest};
use super::Ripemd160;

#[derive(Clone)]
struct Test {
    input: &'static str,
    output: Vec<u8>,
    output_str: &'static str,
}

#[test]
fn test() {
    let tests = vec![// Test messages from FIPS 180-1
                     Test {
                         input: "abc",
                         output: vec![
                            0x8eu8, 0xb2u8, 0x08u8, 0xf7u8,
                            0xe0u8, 0x5du8, 0x98u8, 0x7au8,
                            0x9bu8, 0x04u8, 0x4au8, 0x8eu8,
                            0x98u8, 0xc6u8, 0xb0u8, 0x87u8,
                            0xf1u8, 0x5au8, 0x0bu8, 0xfcu8,
                        ],
                         output_str: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
                     },
                     Test {
                         input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                         output: vec![
                            0x12u8, 0xa0u8, 0x53u8, 0x38u8,
                            0x4au8, 0x9cu8, 0x0cu8, 0x88u8,
                            0xe4u8, 0x05u8, 0xa0u8, 0x6cu8,
                            0x27u8, 0xdcu8, 0xf4u8, 0x9au8,
                            0xdau8, 0x62u8, 0xebu8, 0x2bu8,
                        ],
                         output_str: "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
                     },
                     // Examples from wikipedia
                     Test {
                         input: "The quick brown fox jumps over the lazy dog",
                         output: vec![
                            0x37u8, 0xf3u8, 0x32u8, 0xf6u8,
                            0x8du8, 0xb7u8, 0x7bu8, 0xd9u8,
                            0xd7u8, 0xedu8, 0xd4u8, 0x96u8,
                            0x95u8, 0x71u8, 0xadu8, 0x67u8,
                            0x1cu8, 0xf9u8, 0xddu8, 0x3bu8,
                        ],
                         output_str: "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
                     },
                     Test {
                         input: "The quick brown fox jumps over the lazy cog",
                         output: vec![
                            0x13u8, 0x20u8, 0x72u8, 0xdfu8,
                            0x69u8, 0x09u8, 0x33u8, 0x83u8,
                            0x5eu8, 0xb8u8, 0xb6u8, 0xadu8,
                            0x0bu8, 0x77u8, 0xe7u8, 0xb6u8,
                            0xf1u8, 0x4au8, 0xcau8, 0xd7u8,
                        ],
                         output_str: "132072df690933835eb8b6ad0b77e7b6f14acad7",
                     }];

    // Test that it works when accepting the message all at once

    let mut out = [0u8; 20];

    let mut sh = Box::new(Ripemd160::new());
    for t in tests.iter() {
        (*sh).input_str(t.input);
        sh.result(&mut out);
        assert_eq!(&t.output[..], &out[..]);

        let out_str = (*sh).result_str();
        assert_eq!(out_str.len(), 40);
        assert_eq!(&out_str[..], t.output_str);

        sh.reset();
    }


    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            (*sh).input_str(&t.input[len - left..take + len - left]);
            left = left - take;
        }
        sh.result(&mut out);
        assert_eq!(&t.output[..], &out[..]);

        let out_str = (*sh).result_str();
        assert_eq!(out_str.len(), 40);
        assert!(&out_str[..] == t.output_str);

        sh.reset();
    }
}

#[test]
fn test_1million_random_ripemd160() {
    let mut sh = Ripemd160::new();
    test_digest::one_million_random(&mut sh,
                                    64,
                                    "52783243c1697bdbe16d37f97f68f08325dc1528");
}
