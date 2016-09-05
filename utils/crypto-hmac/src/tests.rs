use std::iter::repeat;

use mac::{Mac, MacResult};
use hmac::Hmac;
use digest::Digest;
use md5::Md5;

struct Test {
    key: Vec<u8>,
    data: Vec<u8>,
    expected: Vec<u8>
}

// Test vectors from: http://tools.ietf.org/html/rfc2104

fn tests() -> Vec<Test> {
    vec![
        Test {
            key: repeat(0x0bu8).take(16).collect(),
            data: b"Hi There".to_vec(),
            expected: vec![
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
                0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d ]
        },
        Test {
            key: b"Jefe".to_vec(),
            data: b"what do ya want for nothing?".to_vec(),
            expected: vec![
                0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
                0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 ]
        },
        Test {
            key: repeat(0xaau8).take(16).collect(),
            data: repeat(0xddu8).take(50).collect(),
            expected: vec![
                0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
                0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 ]
        }
    ]
}

#[test]
fn test_hmac_md5() {
    let tests = tests();
    for t in tests.iter() {
        let mut hmac = Hmac::new(Md5::new(), &t.key[..]);

        hmac.input(&t.data[..]);
        let result = hmac.result();
        let expected = MacResult::new(&t.expected[..]);
        assert!(result == expected);

        hmac.reset();

        hmac.input(&t.data[..]);
        let result2 = hmac.result();
        let expected2 = MacResult::new(&t.expected[..]);
        assert!(result2 == expected2);
    }
}

#[test]
fn test_hmac_md5_incremental() {
    let tests = tests();
    for t in tests.iter() {
        let mut hmac = Hmac::new(Md5::new(), &t.key[..]);
        for i in 0..t.data.len() {
            hmac.input(&t.data[i..i + 1]);
        }
        let result = hmac.result();
        let expected = MacResult::new(&t.expected[..]);
        assert!(result == expected);
    }
}
