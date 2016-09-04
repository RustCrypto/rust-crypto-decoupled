#![cfg(feature="use-std")]
use crypto_digest::Digest;
use crypto_tests;
use super::{Sha512, Sha384, Sha512Trunc256, Sha512Trunc224, Sha256, Sha224};

struct Test {
    input: &'static str,
    output_str: &'static str,
}

fn test_hash<D: Digest>(sh: &mut D, tests: &[Test]) {
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        sh.input_str(t.input);

        let out_str = sh.result_str();
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

        let out_str = sh.result_str();
        assert!(&out_str[..] == t.output_str);

        sh.reset();
    }
}

#[test]
fn test_sha512() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha512::new();

    test_hash(&mut sh, &tests[..]);
}

#[test]
fn test_sha384() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha384::new();

    test_hash(&mut sh, &tests[..]);
}

#[test]
fn test_sha512_256() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "1546741840f8a492b959d9b8b2344b9b0eb51b004bba35c0aebaac86d45264c3",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha512Trunc256::new();

    test_hash(&mut sh, &tests[..]);
}

#[test]
fn test_sha512_224() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "6d6a9279495ec4061769752e7ff9c68b6b0b3c5a281b7917ce0572de",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha512Trunc224::new();

    test_hash(&mut sh, &tests[..]);
}

#[test]
fn test_sha256() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha256::new();

    test_hash(&mut sh, &tests[..]);
}

#[test]
fn test_sha224() {
    // Examples from wikipedia
    let wikipedia_tests =
        [Test {
             input: "",
             output_str: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog",
             output_str: "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
         },
         Test {
             input: "The quick brown fox jumps over the lazy dog.",
             output_str: "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
         }];

    let tests = wikipedia_tests;

    let mut sh = Sha224::new();

    test_hash(&mut sh, &tests[..]);
}


#[test]
fn test_1million_random_sha512() {
    let mut sh = Sha512::new();
    let output = concat!("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632",
                         "a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c",
                         "2c49aa2e4eadb217ad8cc09b");
    crypto_tests::digest::one_million_random(&mut sh, 128, output);
}


#[test]
fn test_1million_random_sha256() {
    let mut sh = Sha256::new();
    let output = concat!("cdc76e5c9914fb9281a1c7e284d73e67",
                         "f1809a48a497200e046d39ccc7112cd0");
    crypto_tests::digest::one_million_random(&mut sh, 64, output);
}
